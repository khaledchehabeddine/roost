//! Implements the X3DH handshake that starts Double Ratchet sessions, and the proof that a first
//! message's sender holds their identity key.

use crate::discovery_key::{DiscoveryKey, PublicDiscoveryKey, verify_public_discovery_key};
use crate::double_ratchet::{RatchetError, RatchetState, RootKey};
use crate::keys::{
    KeyPair, PublicIdentityKey, PublicKey, PublicKeyError, Signature, generate_key_pair,
    verify_public_identity_key,
};
use crate::one_time_prekey::{OneTimePreKey, PublicOneTimePreKey};
use crate::sealed_frame::{OneTimePreKeyReference, SealedFramePreKeyReference};
use crate::signed_prekey::{PublicSignedPreKey, SignedPreKey, verify_public_signed_prekey};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use roost_protocol::SessionId;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::SharedSecret;
use zeroize::Zeroizing;

const HKDF_INFO_WITHOUT_ONE_TIME_PREKEY: &[u8] = b"RoostX3DH-v1:without-opk";
const HKDF_INFO_WITH_ONE_TIME_PREKEY: &[u8] = b"RoostX3DH-v1:with-opk";
const SESSION_ID_INFO: &[u8] = b"RoostSessionId-v1:";
const SENDER_PROOF_CONTEXT: &[u8] = b"RoostX3DH-v1:sender-proof:";
/// Length of the proof a first message carries.
pub const SENDER_PROOF_LEN: usize = 32;

/// Public prekey material used by the initiator to start an X3DH session.
#[derive(Clone)]
pub struct PreKeyBundle {
    /// Responder discovery key, signed by the responder's identity key.
    pub discovery_key: PublicDiscoveryKey,
    /// Responder signed prekey, signed by the discovery key.
    pub signed_prekey: PublicSignedPreKey,
    /// Optional one-time prekey bound to the same discovery-key epoch.
    pub one_time_prekey: Option<PublicOneTimePreKey>,
}

/// The public half of a handshake, which each first message carries.
#[derive(Clone, Copy)]
pub struct Handshake {
    /// The initiator's ephemeral X25519 public key.
    pub base_key: PublicKey,
    /// The responder discovery key the handshake targets.
    pub responder_discovery_key: PublicKey,
    /// The responder prekeys the handshake used.
    pub prekey_reference: SealedFramePreKeyReference,
}

/// What a first message's sender proof covers.
pub struct SenderProofTranscript<'a> {
    /// The handshake the proof belongs to.
    pub handshake: &'a Handshake,
    /// The sender's identity key, whose agreement half makes the proof.
    pub sender_identity_key: &'a PublicIdentityKey,
    /// The sender's discovery key, sealed with the proof so the recipient can reply.
    pub sender_discovery_key: &'a PublicDiscoveryKey,
    /// The sender certificate sealed with the proof.
    pub sender_certificate: &'a [u8],
    /// The domain signature over the sender certificate.
    pub sender_certificate_signature: &'a [u8; Signature::BYTE_SIZE],
}

/// Starts a session with the responder whose bundle the initiator fetched.
///
/// The bundle's discovery key must be signed by `responder_identity_key` and its signed prekey by
/// that discovery key. Both peers derive the returned [`SessionId`], and nobody else can.
pub fn initiate_handshake<R: RngCore + CryptoRng>(
    rng: &mut R,
    responder_identity_key: &PublicIdentityKey,
    responder_prekey_bundle: &PreKeyBundle,
) -> Result<(RatchetState, SessionId, Handshake), HandshakeError> {
    verify_public_identity_key(responder_identity_key)?;
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
    let discovery_key_shared_secret = base_key
        .diffie_hellman(&responder_prekey_bundle.discovery_key.public_key)
        .ok_or(HandshakeError::NonContributorySharedSecret)?;
    let signed_prekey_shared_secret = base_key
        .diffie_hellman(&signed_prekey_public_key)
        .ok_or(HandshakeError::NonContributorySharedSecret)?;
    let one_time_prekey_shared_secret = one_time_prekey
        .map(|prekey| {
            base_key
                .diffie_hellman(&prekey.public_key)
                .ok_or(HandshakeError::NonContributorySharedSecret)
        })
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
            one_time_prekey: one_time_prekey.map(|prekey| OneTimePreKeyReference {
                id: prekey.id,
                public_key: *prekey.public_key.as_bytes(),
            }),
        },
    };
    Ok((state, session_id, handshake))
}

/// Accepts a handshake with the responder's discovery key and the prekeys the handshake names.
///
/// This authenticates nobody. The caller checks the sender's proof with [`verify_sender_proof`]
/// after the first message decrypts.
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
    check_epoch(reference.discovery_epoch, responder_discovery_key.epoch())?;
    check_epoch(
        responder_signed_prekey.epoch(),
        responder_discovery_key.epoch(),
    )?;
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
    let discovery_key_shared_secret = responder_discovery_key
        .diffie_hellman(base_key)
        .ok_or(HandshakeError::NonContributorySharedSecret)?;
    let signed_prekey_shared_secret = responder_signed_prekey
        .diffie_hellman(base_key)
        .ok_or(HandshakeError::NonContributorySharedSecret)?;
    let one_time_prekey_shared_secret = responder_one_time_prekey
        .as_ref()
        .map(|prekey| {
            prekey
                .diffie_hellman(base_key)
                .ok_or(HandshakeError::NonContributorySharedSecret)
        })
        .transpose()?;
    let (root_key, session_id) = derive_root_key_and_session_id(
        &discovery_key_shared_secret,
        &signed_prekey_shared_secret,
        one_time_prekey_shared_secret.as_ref(),
    )?;
    let signed_prekey_key_pair =
        KeyPair::from_secret_bytes(&responder_signed_prekey.to_secret_bytes());
    let state = RatchetState::init_responder(root_key, signed_prekey_key_pair);
    Ok((state, session_id))
}

/// Proves that the sender holds the identity key named in `transcript`.
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
    let secret = sender_identity_key_pair
        .diffie_hellman(&signed_prekey_public_key)
        .ok_or(HandshakeError::NonContributorySharedSecret)?;
    derive_sender_proof(&secret, &sender_proof_transcript(transcript)?)
}

/// Checks a first message's proof with the signed prekey its handshake used.
pub fn verify_sender_proof(
    responder_signed_prekey: &SignedPreKey,
    transcript: &SenderProofTranscript<'_>,
    proof: &[u8; SENDER_PROOF_LEN],
) -> Result<(), HandshakeError> {
    let secret = responder_signed_prekey
        .diffie_hellman(&transcript.sender_identity_key.public_key)
        .ok_or(HandshakeError::NonContributorySharedSecret)?;
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
    /// The handshake targets a different discovery key than the responder's.
    #[error("handshake targets another discovery key")]
    DiscoveryKeyMismatch,
    /// HKDF-SHA256 rejected the requested output length.
    #[error("hkdf-sha256 expand exceeded output limit")]
    HkdfExpand,
    /// An identity key, discovery key, or public signed prekey failed validation.
    #[error("handshake public key validation failed")]
    PublicKey(#[from] PublicKeyError),
    /// Handshake names a one-time prekey that was not supplied.
    #[error("handshake one-time prekey is missing")]
    MissingOneTimePreKey,
    /// An X25519 exchange produced a non-contributory shared secret.
    #[error("x25519 shared secret was non-contributory")]
    NonContributorySharedSecret,
    /// Handshake one-time prekey reference does not match the local one.
    #[error("handshake one-time prekey reference does not match local one-time prekey")]
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
    /// Handshake targets a different signed prekey than the local one.
    #[error("handshake signed prekey reference does not match local signed prekey")]
    SignedPreKeyMismatch,
    /// Prekey material belongs to another epoch than the discovery key.
    #[error("prekey epoch {epoch} doesn't match discovery key epoch {discovery_epoch}")]
    StalePreKey {
        /// The epoch of the prekey, or of the prekeys the handshake names.
        epoch: u32,
        /// The discovery key's epoch.
        discovery_epoch: u32,
    },
}

fn validate_bundle_epochs(bundle: &PreKeyBundle) -> Result<(), HandshakeError> {
    check_epoch(bundle.signed_prekey.epoch, bundle.discovery_key.epoch)?;
    if let Some(one_time_prekey) = &bundle.one_time_prekey {
        check_epoch(one_time_prekey.epoch, bundle.discovery_key.epoch)?;
    }
    Ok(())
}

fn check_epoch(epoch: u32, discovery_epoch: u32) -> Result<(), HandshakeError> {
    if epoch != discovery_epoch {
        return Err(HandshakeError::StalePreKey {
            epoch,
            discovery_epoch,
        });
    }
    Ok(())
}

fn validate_one_time_prekey(
    reference: &SealedFramePreKeyReference,
    one_time_prekey: Option<OneTimePreKey>,
) -> Result<Option<OneTimePreKey>, HandshakeError> {
    match (reference.one_time_prekey, one_time_prekey) {
        (None, _) => Ok(None),
        (Some(_), None) => Err(HandshakeError::MissingOneTimePreKey),
        (Some(expected), Some(prekey)) => {
            let public_matches: bool = expected
                .public_key
                .ct_eq(prekey.public_key().as_bytes())
                .into();
            if !public_matches {
                return Err(HandshakeError::OneTimePreKeyMismatch);
            }
            Ok(Some(prekey))
        }
    }
}

// No salt means RFC 5869's all-zero salt, which X3DH also uses.
fn derive_root_key_and_session_id(
    discovery_key_shared_secret: &SharedSecret,
    signed_prekey_shared_secret: &SharedSecret,
    one_time_prekey_shared_secret: Option<&SharedSecret>,
) -> Result<(RootKey, SessionId), HandshakeError> {
    let mut input_keying_material = Zeroizing::new([0u8; 32 * 3]);
    input_keying_material[..32].copy_from_slice(discovery_key_shared_secret.as_bytes());
    input_keying_material[32..64].copy_from_slice(signed_prekey_shared_secret.as_bytes());
    let (input_keying_material, root_key_info) = match one_time_prekey_shared_secret {
        Some(secret) => {
            input_keying_material[64..].copy_from_slice(secret.as_bytes());
            (&input_keying_material[..], HKDF_INFO_WITH_ONE_TIME_PREKEY)
        }
        None => (
            &input_keying_material[..64],
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
        RootKey::from_bytes(&root_key),
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
            + Signature::BYTE_SIZE,
    ));
    transcript.extend_from_slice(SENDER_PROOF_CONTEXT);
    transcript.extend_from_slice(handshake.base_key.as_bytes());
    transcript.extend_from_slice(handshake.responder_discovery_key.as_bytes());
    transcript.extend_from_slice(&reference.discovery_epoch.to_be_bytes());
    transcript.extend_from_slice(&reference.signed_prekey_public_key);
    match reference.one_time_prekey {
        Some(prekey) => {
            transcript.push(1);
            transcript.extend_from_slice(&prekey.id.to_be_bytes());
            transcript.extend_from_slice(&prekey.public_key);
        }
        None => transcript.push(0),
    }
    transcript.extend_from_slice(input.sender_identity_key.public_key.as_bytes());
    transcript.extend_from_slice(input.sender_identity_key.verifying_key.as_bytes());
    transcript.extend_from_slice(input.sender_discovery_key.public_key.as_bytes());
    transcript.extend_from_slice(input.sender_discovery_key.verifying_key.as_bytes());
    extend_len_prefixed(&mut transcript, input.sender_certificate)?;
    transcript.extend_from_slice(input.sender_certificate_signature);
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

    const FIXED_CREATED_AT_SECS: u64 = 1_700_000_000;

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
            generate_discovery_key(&mut rng, &alice_identity, 2, FIXED_CREATED_AT_SECS).unwrap();
        let bob_identity = generate_signing_key_pair(&mut rng);
        let bob_identity_key =
            public_identity_key(&bob_identity, generate_key_pair(&mut rng).public);
        let bob_discovery_key =
            generate_discovery_key(&mut rng, &bob_identity, 3, FIXED_CREATED_AT_SECS).unwrap();
        let bob_signed_prekey = generate_signed_prekey_for_discovery_key(
            &mut rng,
            &bob_discovery_key,
            0,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();
        let bob_one_time_prekey = generate_one_time_prekey(&mut rng, 9, bob_discovery_key.epoch());
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
            discovery_key: setup.bob_discovery_key.public(),
            signed_prekey: setup.bob_signed_prekey.public(),
            one_time_prekey: include_one_time.then(|| setup.bob_one_time_prekey.public()),
        }
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
            sender_certificate_signature: &[0x51; Signature::BYTE_SIZE],
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
    fn root_key_and_session_id_change_with_each_key_agreement_input() {
        let secret = |seed: u8| {
            let mut rng = ChaCha20Rng::from_seed([seed; 32]);
            generate_key_pair(&mut rng)
                .diffie_hellman(&generate_key_pair(&mut rng).public)
                .unwrap()
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
    fn accept_rejects_prekeys_and_base_keys_the_handshake_does_not_name() {
        let (setup, mut rng) = setup();
        let wrong_one_time_prekey =
            generate_one_time_prekey(&mut rng, 10, setup.bob_discovery_key.epoch());
        let other_signed_prekey = generate_signed_prekey_for_discovery_key(
            &mut rng,
            &setup.bob_discovery_key,
            1,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();
        let (_, _, with_one_time_prekey) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle(&setup, true)).unwrap();
        let (_, _, handshake) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle(&setup, false)).unwrap();
        let low_order = Handshake {
            base_key: PublicKey::from([0u8; 32]),
            ..handshake
        };
        let bob = (&setup.bob_discovery_key, &setup.bob_signed_prekey);

        for (handshake, (discovery_key, signed_prekey), one_time_prekey, rejected) in [
            (
                &with_one_time_prekey,
                bob,
                None,
                HandshakeError::MissingOneTimePreKey,
            ),
            (
                &with_one_time_prekey,
                bob,
                Some(wrong_one_time_prekey),
                HandshakeError::OneTimePreKeyMismatch,
            ),
            (
                &handshake,
                (&setup.bob_discovery_key, &other_signed_prekey),
                None,
                HandshakeError::SignedPreKeyMismatch,
            ),
            (
                &handshake,
                (&setup.alice_discovery_key, &setup.bob_signed_prekey),
                None,
                HandshakeError::DiscoveryKeyMismatch,
            ),
            (
                &low_order,
                bob,
                None,
                HandshakeError::NonContributorySharedSecret,
            ),
        ] {
            let Err(error) =
                accept_handshake(handshake, discovery_key, signed_prekey, one_time_prekey)
            else {
                panic!("expected {rejected}");
            };
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&rejected)
            );
        }
    }

    #[test]
    fn initiate_rejects_stale_one_time_prekey_epoch() {
        let (setup, mut rng) = setup();
        let stale_one_time_prekey =
            generate_one_time_prekey(&mut rng, 10, setup.bob_discovery_key.epoch() + 1);
        let bundle = PreKeyBundle {
            one_time_prekey: Some(stale_one_time_prekey.public()),
            ..bundle(&setup, false)
        };

        assert!(matches!(
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle),
            Err(HandshakeError::StalePreKey { epoch, discovery_epoch })
                if epoch == discovery_epoch + 1
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
    fn sender_proof_changes_with_each_transcript_field_and_the_identity_key() {
        let (setup, mut rng) = setup();
        let (_, _, handshake) =
            initiate_handshake(&mut rng, &setup.bob_identity_key, &bundle(&setup, true)).unwrap();
        let sender_discovery_key = setup.alice_discovery_key.public();
        let transcript = proof_transcript(&setup, &handshake, &sender_discovery_key);
        let proof = prove_sender(&setup.alice_identity_key_pair, &transcript).unwrap();
        let other_key = generate_key_pair(&mut rng).public;
        let other_signing_key = generate_signing_key_pair(&mut rng);
        let one_time_prekey = handshake.prekey_reference.one_time_prekey.unwrap();
        let mut other_one_time_prekey = handshake;
        other_one_time_prekey.prekey_reference.one_time_prekey = Some(OneTimePreKeyReference {
            id: 10,
            ..one_time_prekey
        });
        let mut without_one_time_prekey = handshake;
        without_one_time_prekey.prekey_reference.one_time_prekey = None;
        let mut other_one_time_prekey_key = handshake;
        other_one_time_prekey_key.prekey_reference.one_time_prekey = Some(OneTimePreKeyReference {
            public_key: *other_key.as_bytes(),
            ..one_time_prekey
        });
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
                sender_certificate_signature: &[0x52; Signature::BYTE_SIZE],
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
