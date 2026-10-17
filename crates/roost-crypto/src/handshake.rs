//! Implements the X3DH handshake that starts Double Ratchet Sessions, and the proof that a first
//! Message's sender holds their Identity Key.

use crate::discovery_key::{DiscoveryKey, PublicDiscoveryKey, verify_public_discovery_key};
use crate::double_ratchet::{RatchetError, RatchetState};
use crate::keys::{
    KeyPair, PublicIdentityKey, PublicKey, PublicKeyError, SharedSecret, generate_key_pair,
    verify_public_identity_key,
};
use crate::one_time_prekey::{OneTimePreKey, PublicOneTimePreKey};
use crate::ratchet::RootKey;
use crate::sealed_frame::SealedFramePreKeyReference;
use crate::signed_prekey::{PublicSignedPreKey, SignedPreKey, verify_public_signed_prekey};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use roost_protocol::SessionId;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// Fixed prefix on the HKDF input. Future incompatible handshake derivations should change these
// bytes so peers fail during the first decrypt.
const F_PREFIX: [u8; 32] = [0xFF; 32];
const HKDF_INFO_WITHOUT_ONE_TIME_PREKEY: &[u8] = b"RoostX3DH-v1:without-opk";
const HKDF_INFO_WITH_ONE_TIME_PREKEY: &[u8] = b"RoostX3DH-v1:with-opk";
const SESSION_ID_INFO: &[u8] = b"RoostSessionId-v1:";
const SENDER_PROOF_CONTEXT: &[u8] = b"RoostX3DH-v1:sender-proof:";
/// Current public pre-key bundle format version.
pub const PREKEY_BUNDLE_VERSION: u8 = 1;
/// Length of the proof a first Message carries.
pub const SENDER_PROOF_LEN: usize = 32;

/// Public pre-key material used by the initiator to start an X3DH session.
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// Version of the public pre-key bundle format.
    pub version: u8,
    /// Responder discovery key verified by the responder's identity key.
    pub discovery_key: PublicDiscoveryKey,
    /// Responder signed pre-key verified by the discovery key.
    pub signed_prekey: PublicSignedPreKey,
    /// Optional one-time pre-key bound to the same discovery-key epoch.
    pub one_time_prekey: Option<PublicOneTimePreKey>,
}

/// The public half of a handshake, which the initiator sends until the responder replies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handshake {
    /// The initiator's ephemeral X25519 public key.
    pub base_key: PublicKey,
    /// The responder Discovery Key the handshake targets.
    pub responder_discovery_key: PublicKey,
    /// The responder prekeys the handshake used.
    pub prekey_reference: SealedFramePreKeyReference,
}

/// What a first Message's sender proof covers besides the handshake.
pub struct SenderProofTranscript<'a> {
    /// The handshake the proof belongs to.
    pub handshake: &'a Handshake,
    /// The sender's Identity Key, whose agreement half makes the proof.
    pub sender_identity_key: &'a PublicIdentityKey,
    /// The sender's Discovery Key, sealed with the proof so the recipient can reply.
    pub sender_discovery_key: &'a PublicDiscoveryKey,
    /// The sender certificate sealed with the proof.
    pub sender_certificate: &'a [u8],
    /// The domain signature over the sender certificate.
    pub sender_certificate_signature: &'a [u8],
}

/// Starts a Session with the responder whose bundle the initiator fetched.
///
/// The initiator's base key and first ratchet key are drawn from `rng`. The bundle's Discovery Key
/// must be signed by `responder_identity_key` and its signed prekey by that Discovery Key. Both
/// peers derive the returned [`SessionId`], and nobody else can.
pub fn initiate_handshake<R: RngCore + CryptoRng>(
    rng: &mut R,
    responder_identity_key: &PublicIdentityKey,
    responder_prekey_bundle: &PreKeyBundle,
) -> Result<(RatchetState, SessionId, Handshake), HandshakeError> {
    verify_public_identity_key(responder_identity_key)?;
    if responder_prekey_bundle.version != PREKEY_BUNDLE_VERSION {
        return Err(HandshakeError::UnsupportedPreKeyBundleVersion(
            responder_prekey_bundle.version,
        ));
    }
    verify_public_discovery_key(
        &responder_prekey_bundle.discovery_key,
        &responder_identity_key.verifying_key,
    )?;
    verify_public_signed_prekey(
        &responder_prekey_bundle.signed_prekey,
        &responder_prekey_bundle.discovery_key.verifying_key,
    )?;
    validate_bundle_epochs(responder_prekey_bundle)?;

    let base_key = generate_key_pair(rng);
    let signed_prekey_public_key = responder_prekey_bundle.signed_prekey.public_key;
    let one_time_prekey = responder_prekey_bundle.one_time_prekey.as_ref();
    let discovery_key_shared_secret = checked_shared_secret(
        base_key.diffie_hellman(&responder_prekey_bundle.discovery_key.public_key),
    )?;
    let signed_prekey_shared_secret =
        checked_shared_secret(base_key.diffie_hellman(&signed_prekey_public_key))?;
    let one_time_prekey_shared_secret = one_time_prekey
        .map(|prekey| checked_shared_secret(base_key.diffie_hellman(&prekey.public_key)))
        .transpose()?;
    let (root_key, session_id) = derive_root_key_and_session_id(
        &discovery_key_shared_secret,
        &signed_prekey_shared_secret,
        one_time_prekey_shared_secret.as_ref(),
    )?;
    let state = RatchetState::init_initiator(rng, root_key, &signed_prekey_public_key)?;
    let handshake = Handshake {
        base_key: base_key.public,
        responder_discovery_key: responder_prekey_bundle.discovery_key.public_key,
        prekey_reference: SealedFramePreKeyReference {
            discovery_epoch: responder_prekey_bundle.discovery_key.epoch,
            signed_prekey_public_key: *signed_prekey_public_key.as_bytes(),
            one_time_prekey_id: one_time_prekey.map(|prekey| prekey.id),
            one_time_prekey_public_key: one_time_prekey.map(|prekey| *prekey.public_key.as_bytes()),
        },
    };
    Ok((state, session_id, handshake))
}

/// Accepts a handshake with the responder's Discovery Key and the prekeys the handshake names.
///
/// This authenticates nobody: the caller checks the sender's proof with
/// [`verify_sender_proof`] after the first Message decrypts.
pub fn accept_handshake(
    handshake: &Handshake,
    responder_discovery_key: &DiscoveryKey,
    responder_signed_prekey: &SignedPreKey,
    responder_one_time_prekey: Option<OneTimePreKey>,
) -> Result<(RatchetState, SessionId), HandshakeError> {
    let reference = handshake.prekey_reference;
    let discovery_key_matches: bool = handshake
        .responder_discovery_key
        .as_bytes()
        .ct_eq(responder_discovery_key.public_key().as_bytes())
        .into();
    if !discovery_key_matches {
        return Err(HandshakeError::DiscoveryKeyMismatch);
    }
    if reference.discovery_epoch != responder_discovery_key.epoch()
        || responder_signed_prekey.epoch() != responder_discovery_key.epoch()
    {
        return Err(HandshakeError::StalePreKey);
    }
    let signed_prekey_matches: bool = reference
        .signed_prekey_public_key
        .ct_eq(responder_signed_prekey.public_key().as_bytes())
        .into();
    if !signed_prekey_matches {
        return Err(HandshakeError::SignedPreKeyMismatch);
    }
    let responder_one_time_prekey =
        validate_one_time_prekey(&reference, responder_one_time_prekey)?;

    let base_key = &handshake.base_key;
    let discovery_key_shared_secret =
        checked_shared_secret(responder_discovery_key.diffie_hellman(base_key))?;
    let signed_prekey_shared_secret =
        checked_shared_secret(responder_signed_prekey.diffie_hellman(base_key))?;
    let one_time_prekey_shared_secret = responder_one_time_prekey
        .as_ref()
        .map(|prekey| checked_shared_secret(prekey.diffie_hellman(base_key)))
        .transpose()?;
    let (root_key, session_id) = derive_root_key_and_session_id(
        &discovery_key_shared_secret,
        &signed_prekey_shared_secret,
        one_time_prekey_shared_secret.as_ref(),
    )?;
    let signed_prekey_key_pair =
        KeyPair::from_secret_bytes(*responder_signed_prekey.to_secret_bytes());
    let state = RatchetState::init_responder(root_key, signed_prekey_key_pair);
    Ok((state, session_id))
}

/// Proves that the sender holds the Identity Key named in `transcript`.
///
/// Only the holder of the responder's signed prekey can check the proof, so unlike a signature it
/// doesn't let the recipient prove to anyone else who contacted them.
pub fn prove_sender(
    sender_identity_key_pair: &KeyPair,
    transcript: &SenderProofTranscript<'_>,
) -> Result<Zeroizing<[u8; SENDER_PROOF_LEN]>, HandshakeError> {
    let signed_prekey_public_key = PublicKey::from(
        transcript
            .handshake
            .prekey_reference
            .signed_prekey_public_key,
    );
    let secret =
        checked_shared_secret(sender_identity_key_pair.diffie_hellman(&signed_prekey_public_key))?;
    derive_sender_proof(&secret, &sender_proof_transcript(transcript)?)
}

/// Checks a first Message's proof with the signed prekey its handshake used.
pub fn verify_sender_proof(
    responder_signed_prekey: &SignedPreKey,
    transcript: &SenderProofTranscript<'_>,
    proof: &[u8; SENDER_PROOF_LEN],
) -> Result<(), HandshakeError> {
    let secret = checked_shared_secret(
        responder_signed_prekey.diffie_hellman(&transcript.sender_identity_key.public_key),
    )?;
    let expected = derive_sender_proof(&secret, &sender_proof_transcript(transcript)?)?;
    let proof_matches: bool = expected.as_ref().ct_eq(proof).into();
    if !proof_matches {
        return Err(HandshakeError::SenderProofInvalid);
    }
    Ok(())
}

/// An error returned while starting or accepting an X3DH handshake or checking its proof.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// The handshake targets a different Discovery Key than the responder's.
    #[error("handshake targets another discovery key")]
    DiscoveryKeyMismatch,
    /// HKDF-SHA256 rejected the requested output length.
    #[error("hkdf-sha256 expand exceeded output limit")]
    HkdfExpand,
    /// An Identity Key, Discovery Key, or public signed pre-key failed validation.
    #[error("handshake public key validation failed")]
    PublicKey(#[from] PublicKeyError),
    /// Handshake names a one-time pre-key that was not supplied.
    #[error("handshake one-time pre-key is missing")]
    MissingOneTimePreKey,
    /// An X25519 exchange produced a non-contributory shared secret.
    #[error("x25519 shared secret was non-contributory")]
    NonContributorySharedSecret,
    /// Handshake one-time pre-key reference does not match the local one.
    #[error("handshake one-time pre-key reference does not match local one-time pre-key")]
    OneTimePreKeyMismatch,
    /// Seeding the ratchet failed.
    #[error("handshake ratchet operation failed")]
    Ratchet(#[from] RatchetError),
    /// A sender proof transcript field is too long to encode.
    #[error("sender proof field is {len} bytes, longer than {max}")]
    SenderProofFieldTooLong {
        /// Field length in bytes.
        len: usize,
        /// Longest encodable length in bytes.
        max: usize,
    },
    /// The sender key-possession proof does not validate.
    #[error("sender proof verification failed")]
    SenderProofInvalid,
    /// Handshake targets a different signed pre-key than the local one.
    #[error("handshake signed pre-key reference does not match local signed pre-key")]
    SignedPreKeyMismatch,
    /// Pre-key material belongs to a superseded discovery-key epoch.
    #[error("pre-key belongs to a superseded discovery-key epoch")]
    StalePreKey,
    /// Pre-key bundle uses a format version this build does not understand.
    #[error("unsupported pre-key bundle format version: {0}")]
    UnsupportedPreKeyBundleVersion(u8),
}

fn validate_bundle_epochs(bundle: &PreKeyBundle) -> Result<(), HandshakeError> {
    let epoch = bundle.discovery_key.epoch;
    if bundle.signed_prekey.epoch != epoch {
        return Err(HandshakeError::StalePreKey);
    }
    if let Some(one_time_prekey) = &bundle.one_time_prekey
        && one_time_prekey.epoch != epoch
    {
        return Err(HandshakeError::StalePreKey);
    }
    Ok(())
}

fn validate_one_time_prekey(
    reference: &SealedFramePreKeyReference,
    one_time_prekey: Option<OneTimePreKey>,
) -> Result<Option<OneTimePreKey>, HandshakeError> {
    match (
        reference.one_time_prekey_id,
        reference.one_time_prekey_public_key,
        one_time_prekey,
    ) {
        (None, None, _) => Ok(None),
        (Some(_), None, _) | (None, Some(_), _) => Err(HandshakeError::OneTimePreKeyMismatch),
        (Some(_), Some(_), None) => Err(HandshakeError::MissingOneTimePreKey),
        (Some(expected_id), Some(expected_public_key), Some(prekey)) => {
            let public_matches: bool = expected_public_key
                .ct_eq(prekey.public_key().as_bytes())
                .into();
            if prekey.id() != expected_id || !public_matches {
                return Err(HandshakeError::OneTimePreKeyMismatch);
            }
            if prekey.epoch() != reference.discovery_epoch {
                return Err(HandshakeError::StalePreKey);
            }
            Ok(Some(prekey))
        }
    }
}

fn checked_shared_secret(secret: SharedSecret) -> Result<SharedSecret, HandshakeError> {
    if !secret.was_contributory() {
        return Err(HandshakeError::NonContributorySharedSecret);
    }
    Ok(secret)
}

// Runs HKDF-SHA256 once over F_PREFIX || DH outputs and expands the root key and the SessionID
// under separate labels.
//
// Using no salt means the RFC 5869 zero salt. That is acceptable here because the input keying
// material is already uniformly random and the info strings provide domain separation.
fn derive_root_key_and_session_id(
    discovery_key_shared_secret: &SharedSecret,
    signed_prekey_shared_secret: &SharedSecret,
    one_time_prekey_shared_secret: Option<&SharedSecret>,
) -> Result<(RootKey, SessionId), HandshakeError> {
    let mut input_keying_material = Zeroizing::new([0u8; 32 * 4]);
    input_keying_material[..32].copy_from_slice(&F_PREFIX);
    input_keying_material[32..64].copy_from_slice(discovery_key_shared_secret.as_bytes());
    input_keying_material[64..96].copy_from_slice(signed_prekey_shared_secret.as_bytes());
    let (input_keying_material, root_key_info) = match one_time_prekey_shared_secret {
        Some(secret) => {
            input_keying_material[96..].copy_from_slice(secret.as_bytes());
            (&input_keying_material[..], HKDF_INFO_WITH_ONE_TIME_PREKEY)
        }
        None => (
            &input_keying_material[..96],
            HKDF_INFO_WITHOUT_ONE_TIME_PREKEY,
        ),
    };
    let hkdf = Hkdf::<Sha256>::new(None, input_keying_material);
    let mut root_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(root_key_info, root_key.as_mut())
        .map_err(|_| HandshakeError::HkdfExpand)?;
    let mut session_id = [0u8; 16];
    hkdf.expand(SESSION_ID_INFO, &mut session_id)
        .map_err(|_| HandshakeError::HkdfExpand)?;
    Ok((
        RootKey::from_bytes(*root_key),
        SessionId::from_bytes(session_id),
    ))
}

fn sender_proof_transcript(
    input: &SenderProofTranscript<'_>,
) -> Result<Zeroizing<Vec<u8>>, HandshakeError> {
    let handshake = input.handshake;
    let reference = handshake.prekey_reference;
    let mut transcript = Zeroizing::new(Vec::with_capacity(
        SENDER_PROOF_CONTEXT.len()
            + 32 * 8
            + 4
            + 1
            + 8
            + 4
            + input.sender_certificate.len()
            + 4
            + input.sender_certificate_signature.len(),
    ));
    transcript.extend_from_slice(SENDER_PROOF_CONTEXT);
    transcript.extend_from_slice(handshake.base_key.as_bytes());
    transcript.extend_from_slice(handshake.responder_discovery_key.as_bytes());
    transcript.extend_from_slice(&reference.discovery_epoch.to_be_bytes());
    transcript.extend_from_slice(&reference.signed_prekey_public_key);
    match (
        reference.one_time_prekey_id,
        reference.one_time_prekey_public_key,
    ) {
        (Some(id), Some(public_key)) => {
            transcript.push(1);
            transcript.extend_from_slice(&id.to_be_bytes());
            transcript.extend_from_slice(&public_key);
        }
        (None, None) => transcript.push(0),
        (Some(_), None) | (None, Some(_)) => return Err(HandshakeError::OneTimePreKeyMismatch),
    }
    transcript.extend_from_slice(input.sender_identity_key.public_key.as_bytes());
    transcript.extend_from_slice(input.sender_identity_key.verifying_key.as_bytes());
    transcript.extend_from_slice(input.sender_discovery_key.public_key.as_bytes());
    transcript.extend_from_slice(input.sender_discovery_key.verifying_key.as_bytes());
    extend_len_prefixed(&mut transcript, input.sender_certificate)?;
    extend_len_prefixed(&mut transcript, input.sender_certificate_signature)?;
    Ok(transcript)
}

fn extend_len_prefixed(transcript: &mut Vec<u8>, bytes: &[u8]) -> Result<(), HandshakeError> {
    let len = u32::try_from(bytes.len()).map_err(|_| HandshakeError::SenderProofFieldTooLong {
        len: bytes.len(),
        max: u32::MAX as usize,
    })?;
    transcript.extend_from_slice(&len.to_be_bytes());
    transcript.extend_from_slice(bytes);
    Ok(())
}

fn derive_sender_proof(
    sender_proof_secret: &SharedSecret,
    transcript: &[u8],
) -> Result<Zeroizing<[u8; SENDER_PROOF_LEN]>, HandshakeError> {
    let hkdf = Hkdf::<Sha256>::new(None, sender_proof_secret.as_bytes());
    let mut proof = Zeroizing::new([0u8; SENDER_PROOF_LEN]);
    hkdf.expand(transcript, proof.as_mut())
        .map_err(|_| HandshakeError::HkdfExpand)?;
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery_key::{
        DiscoveryKey, generate_discovery_key, generate_signed_prekey_for_discovery_key,
    };
    use crate::keys::{
        PublicIdentityKey, SigningKeyPair, generate_key_pair, generate_signing_key_pair,
        sign_identity_key_binding,
    };
    use crate::one_time_prekey::{OneTimePreKey, generate_one_time_prekey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use roost_protocol::SignatureError;

    const FIXED_TS: u64 = 1_700_000_000;
    const ASSOCIATED_DATA: &[u8] = b"associated data";

    struct Setup {
        alice_identity_key_pair: KeyPair,
        alice_identity_key: PublicIdentityKey,
        alice_discovery_key: DiscoveryKey,
        bob_identity_key: PublicIdentityKey,
        bob_discovery_key: DiscoveryKey,
        bob_signed_prekey: SignedPreKey,
        bob_one_time_prekey: OneTimePreKey,
    }

    fn setup() -> (Setup, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
        let alice_identity = generate_signing_key_pair(&mut rng);
        let alice_identity_key_pair = generate_key_pair(&mut rng);
        let alice_identity_key =
            public_identity_key(&alice_identity, alice_identity_key_pair.public);
        let alice_discovery_key =
            generate_discovery_key(&mut rng, &alice_identity, 2, FIXED_TS).unwrap();
        let bob_identity = generate_signing_key_pair(&mut rng);
        let bob_identity_key =
            public_identity_key(&bob_identity, generate_key_pair(&mut rng).public);
        let bob_discovery_key =
            generate_discovery_key(&mut rng, &bob_identity, 3, FIXED_TS).unwrap();
        let bob_signed_prekey =
            generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery_key, 0, FIXED_TS)
                .unwrap();
        let bob_one_time_prekey =
            generate_one_time_prekey(&mut rng, 9, bob_discovery_key.epoch(), FIXED_TS);
        let setup = Setup {
            alice_identity_key_pair,
            alice_identity_key,
            alice_discovery_key,
            bob_identity_key,
            bob_discovery_key,
            bob_signed_prekey,
            bob_one_time_prekey,
        };
        (setup, rng)
    }

    fn bundle(setup: &Setup, include_one_time: bool) -> PreKeyBundle {
        PreKeyBundle {
            version: PREKEY_BUNDLE_VERSION,
            discovery_key: setup.bob_discovery_key.public(),
            signed_prekey: setup.bob_signed_prekey.public(),
            one_time_prekey: include_one_time.then(|| setup.bob_one_time_prekey.public()),
        }
    }

    fn copy_one_time_prekey(prekey: &OneTimePreKey) -> OneTimePreKey {
        OneTimePreKey::from_secret_bytes(
            prekey.id(),
            *prekey.to_secret_bytes(),
            prekey.epoch(),
            prekey.created_at_secs(),
        )
    }

    fn public_identity_key(
        signing_key: &SigningKeyPair,
        public_key: PublicKey,
    ) -> PublicIdentityKey {
        let binding_signature = sign_identity_key_binding(signing_key, &public_key).unwrap();
        PublicIdentityKey {
            public_key,
            verifying_key: signing_key.verifying,
            binding_signature,
        }
    }

    fn proof_transcript<'a>(
        setup: &'a Setup,
        handshake: &'a Handshake,
        sender_discovery_key: &'a PublicDiscoveryKey,
    ) -> SenderProofTranscript<'a> {
        SenderProofTranscript {
            handshake,
            sender_identity_key: &setup.alice_identity_key,
            sender_discovery_key,
            sender_certificate: b"sender certificate",
            sender_certificate_signature: b"sender certificate signature",
        }
    }

    #[test]
    fn peers_derive_the_same_session_id_and_ratchet_keys() {
        for include_one_time in [true, false] {
            let (setup, mut rng) = setup();
            let (mut alice_state, alice_session_id, handshake) = initiate_handshake(
                &mut rng,
                &setup.bob_identity_key,
                &bundle(&setup, include_one_time),
            )
            .unwrap();
            let (mut bob_state, bob_session_id) = accept_handshake(
                &handshake,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                include_one_time.then(|| copy_one_time_prekey(&setup.bob_one_time_prekey)),
            )
            .unwrap();

            assert_eq!(bob_session_id, alice_session_id);
            let (header, ciphertext) = alice_state
                .ratchet_encrypt(b"hello bob", ASSOCIATED_DATA)
                .unwrap();
            let plaintext = bob_state
                .ratchet_decrypt(&mut rng, &ciphertext, &header, ASSOCIATED_DATA)
                .unwrap();
            assert_eq!(plaintext.as_slice(), b"hello bob");
        }
    }

    #[test]
    fn handshakes_with_one_bundle_get_distinct_session_ids() {
        let (setup, mut rng) = setup();
        let bundle = bundle(&setup, false);

        let (_, first, _) = initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle).unwrap();
        let (_, second, _) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn handshake_names_the_bundle_prekeys() {
        let (setup, mut rng) = setup();

        let (_, _, handshake) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle(&setup, true)).unwrap();

        assert_eq!(
            handshake.responder_discovery_key,
            *setup.bob_discovery_key.public_key()
        );
        assert_eq!(
            handshake.prekey_reference,
            SealedFramePreKeyReference {
                discovery_epoch: setup.bob_discovery_key.epoch(),
                signed_prekey_public_key: *setup.bob_signed_prekey.public_key().as_bytes(),
                one_time_prekey_id: Some(setup.bob_one_time_prekey.id()),
                one_time_prekey_public_key: Some(
                    *setup.bob_one_time_prekey.public_key().as_bytes()
                ),
            }
        );
    }

    #[test]
    fn root_key_and_session_id_change_with_each_key_agreement_input() {
        let secret = |seed: u8| {
            let mut rng = ChaCha20Rng::from_seed([seed; 32]);
            generate_key_pair(&mut rng).diffie_hellman(&generate_key_pair(&mut rng).public)
        };
        let (discovery, signed, one_time, other) = (secret(1), secret(2), secret(3), secret(4));
        let (root_key, session_id) =
            derive_root_key_and_session_id(&discovery, &signed, Some(&one_time)).unwrap();

        for (other_root_key, other_session_id) in [
            derive_root_key_and_session_id(&other, &signed, Some(&one_time)).unwrap(),
            derive_root_key_and_session_id(&discovery, &other, Some(&one_time)).unwrap(),
            derive_root_key_and_session_id(&discovery, &signed, Some(&other)).unwrap(),
            derive_root_key_and_session_id(&discovery, &signed, None).unwrap(),
        ] {
            assert_ne!(other_root_key.as_bytes(), root_key.as_bytes());
            assert_ne!(other_session_id, session_id);
        }
        assert_ne!(&root_key.as_bytes()[..16], session_id.as_bytes());
    }

    #[test]
    fn accept_rejects_missing_one_time_prekey() {
        let (setup, mut rng) = setup();
        let (_, _, handshake) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle(&setup, true)).unwrap();

        assert!(matches!(
            accept_handshake(
                &handshake,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None
            ),
            Err(HandshakeError::MissingOneTimePreKey)
        ));
    }

    #[test]
    fn accept_rejects_mismatched_one_time_prekey() {
        let (setup, mut rng) = setup();
        let wrong_one_time_prekey =
            generate_one_time_prekey(&mut rng, 10, setup.bob_discovery_key.epoch(), FIXED_TS);
        let (_, _, handshake) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle(&setup, true)).unwrap();

        assert!(matches!(
            accept_handshake(
                &handshake,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                Some(wrong_one_time_prekey),
            ),
            Err(HandshakeError::OneTimePreKeyMismatch)
        ));
    }

    #[test]
    fn accept_rejects_mismatched_signed_prekey() {
        let (setup, mut rng) = setup();
        let other_signed_prekey = generate_signed_prekey_for_discovery_key(
            &mut rng,
            &setup.bob_discovery_key,
            1,
            FIXED_TS,
        )
        .unwrap();
        let (_, _, handshake) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle(&setup, false)).unwrap();

        assert!(matches!(
            accept_handshake(
                &handshake,
                &setup.bob_discovery_key,
                &other_signed_prekey,
                None
            ),
            Err(HandshakeError::SignedPreKeyMismatch)
        ));
    }

    #[test]
    fn accept_rejects_another_discovery_key() {
        let (setup, mut rng) = setup();
        let (_, _, handshake) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle(&setup, false)).unwrap();

        assert!(matches!(
            accept_handshake(
                &handshake,
                &setup.alice_discovery_key,
                &setup.bob_signed_prekey,
                None
            ),
            Err(HandshakeError::DiscoveryKeyMismatch)
        ));
    }

    #[test]
    fn accept_rejects_a_non_contributory_base_key() {
        let (setup, mut rng) = setup();
        let (_, _, handshake) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle(&setup, false)).unwrap();
        let low_order = Handshake {
            base_key: PublicKey::from([0u8; 32]),
            ..handshake
        };

        assert!(matches!(
            accept_handshake(
                &low_order,
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None
            ),
            Err(HandshakeError::NonContributorySharedSecret)
        ));
    }

    #[test]
    fn initiate_rejects_stale_one_time_prekey_epoch() {
        let (setup, mut rng) = setup();
        let stale_one_time_prekey =
            generate_one_time_prekey(&mut rng, 10, setup.bob_discovery_key.epoch() + 1, FIXED_TS);
        let bundle = PreKeyBundle {
            one_time_prekey: Some(stale_one_time_prekey.public()),
            ..bundle(&setup, false)
        };

        assert!(matches!(
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle),
            Err(HandshakeError::StalePreKey)
        ));
    }

    #[test]
    fn initiate_rejects_unsupported_prekey_bundle_version() {
        let (setup, mut rng) = setup();
        let bundle = PreKeyBundle {
            version: PREKEY_BUNDLE_VERSION + 1,
            ..bundle(&setup, true)
        };

        assert!(matches!(
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle),
            Err(HandshakeError::UnsupportedPreKeyBundleVersion(version))
                if version == PREKEY_BUNDLE_VERSION + 1
        ));
    }

    #[test]
    fn initiate_rejects_bundle_signed_by_another_identity() {
        let (setup, mut rng) = setup();

        assert!(matches!(
            initiate_handshake(&mut rng, &setup.alice_identity_key, &bundle(&setup, true)),
            Err(HandshakeError::PublicKey(PublicKeyError::Signature(
                SignatureError::SignatureInvalid
            )))
        ));
    }

    #[test]
    fn sender_proof_verifies_with_the_signed_prekey() {
        let (setup, mut rng) = setup();
        let (_, _, handshake) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle(&setup, true)).unwrap();
        let sender_discovery_key = setup.alice_discovery_key.public();
        let transcript = proof_transcript(&setup, &handshake, &sender_discovery_key);

        let proof = prove_sender(&setup.alice_identity_key_pair, &transcript).unwrap();

        verify_sender_proof(&setup.bob_signed_prekey, &transcript, &proof).unwrap();
    }

    #[test]
    fn sender_proof_changes_with_each_transcript_field_and_the_identity_key() {
        let (setup, mut rng) = setup();
        let (_, _, handshake) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle(&setup, true)).unwrap();
        let sender_discovery_key = setup.alice_discovery_key.public();
        let transcript = proof_transcript(&setup, &handshake, &sender_discovery_key);
        let proof = prove_sender(&setup.alice_identity_key_pair, &transcript).unwrap();
        let other_key = generate_key_pair(&mut rng).public;
        let other_signing_key = generate_signing_key_pair(&mut rng);
        let mut other_one_time_prekey = handshake;
        other_one_time_prekey.prekey_reference.one_time_prekey_id = Some(10);
        let mut without_one_time_prekey = handshake;
        without_one_time_prekey.prekey_reference.one_time_prekey_id = None;
        without_one_time_prekey
            .prekey_reference
            .one_time_prekey_public_key = None;
        let mut other_one_time_prekey_key = handshake;
        other_one_time_prekey_key
            .prekey_reference
            .one_time_prekey_public_key = Some(*other_key.as_bytes());
        let mut other_signed_prekey = handshake;
        other_signed_prekey
            .prekey_reference
            .signed_prekey_public_key = *other_key.as_bytes();
        let mut other_epoch = handshake;
        other_epoch.prekey_reference.discovery_epoch += 1;
        let changed_handshakes = [
            Handshake {
                base_key: other_key,
                ..handshake
            },
            Handshake {
                responder_discovery_key: other_key,
                ..handshake
            },
            other_epoch,
            other_signed_prekey,
            other_one_time_prekey,
            other_one_time_prekey_key,
            without_one_time_prekey,
        ];
        let other_identity_x25519 = PublicIdentityKey {
            public_key: other_key,
            ..setup.alice_identity_key.clone()
        };
        let other_identity_ed25519 = PublicIdentityKey {
            verifying_key: other_signing_key.verifying,
            ..setup.alice_identity_key.clone()
        };
        let other_discovery_key = PublicDiscoveryKey {
            public_key: other_key,
            ..sender_discovery_key.clone()
        };
        let other_discovery_ed25519 = PublicDiscoveryKey {
            verifying_key: other_signing_key.verifying,
            ..sender_discovery_key.clone()
        };

        let mut changed = changed_handshakes
            .iter()
            .map(|handshake| SenderProofTranscript {
                handshake,
                ..proof_transcript(&setup, handshake, &sender_discovery_key)
            })
            .map(|transcript| *prove_sender(&setup.alice_identity_key_pair, &transcript).unwrap())
            .collect::<Vec<_>>();
        for transcript in [
            SenderProofTranscript {
                sender_identity_key: &other_identity_x25519,
                ..proof_transcript(&setup, &handshake, &sender_discovery_key)
            },
            SenderProofTranscript {
                sender_identity_key: &other_identity_ed25519,
                ..proof_transcript(&setup, &handshake, &sender_discovery_key)
            },
            SenderProofTranscript {
                sender_discovery_key: &other_discovery_key,
                ..proof_transcript(&setup, &handshake, &sender_discovery_key)
            },
            SenderProofTranscript {
                sender_discovery_key: &other_discovery_ed25519,
                ..proof_transcript(&setup, &handshake, &sender_discovery_key)
            },
            SenderProofTranscript {
                sender_certificate: b"other certificate",
                ..proof_transcript(&setup, &handshake, &sender_discovery_key)
            },
            SenderProofTranscript {
                sender_certificate_signature: b"other signature",
                ..proof_transcript(&setup, &handshake, &sender_discovery_key)
            },
        ] {
            changed.push(*prove_sender(&setup.alice_identity_key_pair, &transcript).unwrap());
        }
        changed.push(*prove_sender(&generate_key_pair(&mut rng), &transcript).unwrap());

        for other in changed {
            assert_ne!(other, *proof);
        }
    }

    #[test]
    fn sender_proof_rejects_a_claimed_identity_without_its_key() {
        let (setup, mut rng) = setup();
        let (_, _, handshake) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle(&setup, true)).unwrap();
        let sender_discovery_key = setup.alice_discovery_key.public();
        let transcript = proof_transcript(&setup, &handshake, &sender_discovery_key);
        let forged = prove_sender(&generate_key_pair(&mut rng), &transcript).unwrap();

        assert!(matches!(
            verify_sender_proof(&setup.bob_signed_prekey, &transcript, &forged),
            Err(HandshakeError::SenderProofInvalid)
        ));
    }
}
