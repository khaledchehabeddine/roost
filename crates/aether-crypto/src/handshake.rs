//! Implements the X3DH handshake that bootstraps Double Ratchet sessions.

use crate::discovery_key::{DiscoveryKey, DiscoveryKeyBundle, verify_discovery_key_bundle};
use crate::double_ratchet::{Header, RatchetState};
use crate::error::CryptoError;
use crate::keys::{KeyPair, PublicKey, SharedSecret, VerifyingKey, generate_key_pair};
use crate::one_time_prekey::{OneTimePreKey, OneTimePreKeyBundle};
use crate::ratchet::RootKey;
use crate::signed_prekey::{SignedPreKey, SignedPreKeyBundle, verify_signed_prekey_bundle};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// Fixed prefix on the HKDF input. Future incompatible handshake derivations should change these
// bytes so peers fail during the first decrypt.
const F_PREFIX: [u8; 32] = [0xFF; 32];
const HKDF_INFO_WITHOUT_ONE_TIME_PREKEY: &[u8] = b"AetherX3DH-v1:without-opk";
const HKDF_INFO_WITH_ONE_TIME_PREKEY: &[u8] = b"AetherX3DH-v1:with-opk";
const INPUT_KEYING_MATERIAL_LEN_WITHOUT_ONE_TIME_PREKEY: usize = 32 * 4;
const INPUT_KEYING_MATERIAL_LEN_WITH_ONE_TIME_PREKEY: usize = 32 * 5;

/// Public pre-key material used by the initiator to start an X3DH session.
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// Responder discovery key verified by the responder's identity key.
    pub discovery_key: DiscoveryKeyBundle,
    /// Responder signed pre-key verified by the discovery key.
    pub signed_prekey: SignedPreKeyBundle,
    /// Optional one-time pre-key bound to the same discovery-key epoch.
    pub one_time_prekey: Option<OneTimePreKeyBundle>,
}

/// A serialized handshake request from an initiator to a responder.
///
/// Holds public handshake material, the first ratchet header fields, and the first ciphertext.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HandshakeEnvelope {
    /// Initiator's X25519 discovery public key.
    pub initiator_discovery_public_key: [u8; 32],
    /// Initiator's X25519 ephemeral public key (fresh per handshake).
    pub initiator_ephemeral_public_key: [u8; 32],
    /// Responder discovery-key epoch the initiator targeted.
    pub responder_discovery_epoch: u32,
    /// X25519 public key of the responder's signed pre-key the initiator targeted.
    pub responder_signed_prekey_public_key: [u8; 32],
    /// Identifier of the responder one-time pre-key the initiator targeted, when present.
    pub one_time_prekey_id: Option<u64>,
    /// X25519 public key of the responder one-time pre-key the initiator targeted, when present.
    pub one_time_prekey_public_key: Option<[u8; 32]>,
    /// Ratchet public key for the first message.
    pub ratchet_public_key: [u8; 32],
    /// Number of messages sent in the previous chain.
    pub previous_chain_length: u32,
    /// Sequence number of this message in the current chain.
    pub message_number: u32,
    /// Ciphertext for the first handshake message.
    pub ciphertext: Vec<u8>,
}

/// Starts a handshake as the initiator and encrypts the first message.
///
/// The initiator's ephemeral key and first ratchet key are drawn from `rng`.
///
/// Pass the responder's permanent identity verifying key as `responder_identity_verifying_key`.
/// It verifies the discovery key in `responder_prekey_bundle`.
///
/// # Errors
/// - [`CryptoError::Aead`] when first-message encryption fails.
/// - [`CryptoError::HkdfExpand`] when the HKDF run for root-key derivation fails.
/// - [`CryptoError::InvalidState`] when ratchet seeding produces an invalid initial state.
/// - [`CryptoError::SignatureInvalid`] when the responder discovery key or signed pre-key
///   signature does not verify.
/// - [`CryptoError::StalePreKey`] when bundled pre-keys do not match the discovery-key epoch.
pub fn initiate<R: RngCore + CryptoRng>(
    rng: &mut R,
    initiator_discovery_key: &DiscoveryKey,
    responder_identity_verifying_key: &VerifyingKey,
    responder_prekey_bundle: &PreKeyBundle,
    plaintext: &[u8],
) -> Result<(RatchetState, HandshakeEnvelope), CryptoError> {
    verify_discovery_key_bundle(
        &responder_prekey_bundle.discovery_key,
        responder_identity_verifying_key,
    )?;
    verify_signed_prekey_bundle(
        &responder_prekey_bundle.signed_prekey,
        &responder_prekey_bundle.discovery_key.verifying_key,
    )?;
    validate_bundle_epochs(responder_prekey_bundle)?;

    let initiator_ephemeral_key = generate_key_pair(rng);
    let responder_signed_prekey_public_key = responder_prekey_bundle.signed_prekey.public_key;

    let root_key = derive_root_key_initiator(
        initiator_discovery_key,
        &initiator_ephemeral_key,
        &responder_prekey_bundle.discovery_key.public_key,
        &responder_signed_prekey_public_key,
        responder_prekey_bundle
            .one_time_prekey
            .as_ref()
            .map(|prekey| &prekey.public_key),
    )?;
    let mut state =
        RatchetState::init_initiator(rng, root_key, &responder_signed_prekey_public_key)?;

    let associated_data = initial_associated_data(
        initiator_discovery_key.public_key(),
        &responder_prekey_bundle.discovery_key.public_key,
        responder_prekey_bundle.discovery_key.epoch,
    );
    let (header, ciphertext) = state.ratchet_encrypt(plaintext, &associated_data)?;

    let envelope = HandshakeEnvelope {
        initiator_discovery_public_key: *initiator_discovery_key.public_key().as_bytes(),
        initiator_ephemeral_public_key: *initiator_ephemeral_key.public.as_bytes(),
        responder_discovery_epoch: responder_prekey_bundle.discovery_key.epoch,
        responder_signed_prekey_public_key: *responder_signed_prekey_public_key.as_bytes(),
        one_time_prekey_id: responder_prekey_bundle
            .one_time_prekey
            .as_ref()
            .map(|prekey| prekey.id),
        one_time_prekey_public_key: responder_prekey_bundle
            .one_time_prekey
            .as_ref()
            .map(|prekey| *prekey.public_key.as_bytes()),
        ratchet_public_key: *header.public_key.as_bytes(),
        previous_chain_length: header.previous_chain_length,
        message_number: header.message_number,
        ciphertext,
    };

    Ok((state, envelope))
}

/// Accepts a handshake envelope and decrypts the first message.
///
/// The responder's first ratchet key is drawn from `rng` during the initial DH ratchet step.
///
/// `responder_discovery_key` is the local responder's current X25519 discovery key.
///
/// Pass the initiator's permanent identity verifying key and discovery-key bundle together. The
/// bundle must verify under that identity and match the envelope's initiator discovery key.
///
/// This function checks that the envelope targets `responder_signed_prekey`, but it does not
/// verify the signed pre-key signature.
///
/// # Errors
/// - [`CryptoError::Aead`] when first-message decryption fails (tampered ciphertext, wrong
///   associated data, or wrong key).
/// - [`CryptoError::HandshakeDiscoveryKeyMismatch`] when
///   `envelope.initiator_discovery_public_key` does not match the verified initiator discovery
///   bundle.
/// - [`CryptoError::HandshakeSignedPreKeyMismatch`] when
///   `envelope.responder_signed_prekey_public_key` does not match
///   `responder_signed_prekey.public()`.
/// - [`CryptoError::HkdfExpand`] when the HKDF run for root-key derivation fails.
/// - [`CryptoError::InvalidState`] when ratchet decryption observes an invalid receiving state.
/// - [`CryptoError::MissingOneTimePreKey`] when the envelope names a one-time pre-key but the
///   caller supplies none.
/// - [`CryptoError::OneTimePreKeyMismatch`] when the supplied one-time pre-key does not match the
///   envelope reference.
/// - [`CryptoError::StalePreKey`] when the envelope or local pre-keys do not match the discovery
///   key epoch.
pub fn accept<R: RngCore + CryptoRng>(
    rng: &mut R,
    envelope: &HandshakeEnvelope,
    initiator_identity_verifying_key: &VerifyingKey,
    initiator_discovery_key_bundle: &DiscoveryKeyBundle,
    responder_discovery_key: &DiscoveryKey,
    responder_signed_prekey: &SignedPreKey,
    responder_one_time_prekey: Option<OneTimePreKey>,
) -> Result<(RatchetState, Zeroizing<Vec<u8>>), CryptoError> {
    verify_discovery_key_bundle(
        initiator_discovery_key_bundle,
        initiator_identity_verifying_key,
    )?;
    let initiator_discovery_matches: bool = envelope
        .initiator_discovery_public_key
        .ct_eq(initiator_discovery_key_bundle.public_key.as_bytes())
        .into();
    if !initiator_discovery_matches {
        return Err(CryptoError::HandshakeDiscoveryKeyMismatch);
    }
    if envelope.responder_discovery_epoch != responder_discovery_key.epoch()
        || responder_signed_prekey.epoch() != responder_discovery_key.epoch()
    {
        return Err(CryptoError::StalePreKey);
    }
    let signed_prekey_matches: bool = envelope
        .responder_signed_prekey_public_key
        .ct_eq(responder_signed_prekey.public().as_bytes())
        .into();
    if !signed_prekey_matches {
        return Err(CryptoError::HandshakeSignedPreKeyMismatch);
    }

    let responder_one_time_prekey =
        validate_envelope_one_time_prekey(envelope, responder_one_time_prekey)?;

    let initiator_discovery_public_key = initiator_discovery_key_bundle.public_key;
    let initiator_ephemeral_public_key = PublicKey::from(envelope.initiator_ephemeral_public_key);

    let root_key = derive_root_key_responder(
        &initiator_discovery_public_key,
        &initiator_ephemeral_public_key,
        responder_discovery_key,
        responder_signed_prekey,
        responder_one_time_prekey.as_ref(),
    )?;
    let signed_prekey_key_pair =
        KeyPair::from_secret_bytes(*responder_signed_prekey.to_secret_bytes());
    let mut state = RatchetState::init_responder(root_key, signed_prekey_key_pair);

    let header = Header {
        public_key: PublicKey::from(envelope.ratchet_public_key),
        previous_chain_length: envelope.previous_chain_length,
        message_number: envelope.message_number,
    };
    let associated_data = initial_associated_data(
        &initiator_discovery_public_key,
        responder_discovery_key.public_key(),
        responder_discovery_key.epoch(),
    );
    let plaintext = state.ratchet_decrypt(rng, &envelope.ciphertext, &header, &associated_data)?;

    Ok((state, plaintext))
}

fn validate_bundle_epochs(bundle: &PreKeyBundle) -> Result<(), CryptoError> {
    let epoch = bundle.discovery_key.epoch;
    if bundle.signed_prekey.epoch != epoch {
        return Err(CryptoError::StalePreKey);
    }
    if let Some(one_time_prekey) = &bundle.one_time_prekey
        && one_time_prekey.epoch != epoch
    {
        return Err(CryptoError::StalePreKey);
    }
    Ok(())
}

fn validate_envelope_one_time_prekey(
    envelope: &HandshakeEnvelope,
    one_time_prekey: Option<OneTimePreKey>,
) -> Result<Option<OneTimePreKey>, CryptoError> {
    match (
        envelope.one_time_prekey_id,
        envelope.one_time_prekey_public_key,
        one_time_prekey,
    ) {
        (None, None, _) => Ok(None),
        (Some(_), None, _) | (None, Some(_), _) => Err(CryptoError::OneTimePreKeyMismatch),
        (Some(_), Some(_), None) => Err(CryptoError::MissingOneTimePreKey),
        (Some(expected_id), Some(expected_public_key), Some(prekey)) => {
            let public_matches: bool = expected_public_key.ct_eq(prekey.public().as_bytes()).into();
            if prekey.id() != expected_id || !public_matches {
                return Err(CryptoError::OneTimePreKeyMismatch);
            }
            if prekey.epoch() != envelope.responder_discovery_epoch {
                return Err(CryptoError::StalePreKey);
            }
            Ok(Some(prekey))
        }
    }
}

// Derives the initiator-side root key from the X3DH Diffie-Hellman outputs:
// DH1 = DK_A * SPK_B, DH2 = EK_A * DK_B, DH3 = EK_A * SPK_B, DH4 = EK_A * OPK_B.
pub(crate) fn derive_root_key_initiator(
    initiator_discovery_key: &DiscoveryKey,
    initiator_ephemeral_key: &KeyPair,
    responder_discovery_public_key: &PublicKey,
    responder_signed_prekey_public_key: &PublicKey,
    responder_one_time_prekey_public_key: Option<&PublicKey>,
) -> Result<RootKey, CryptoError> {
    let dh1 = initiator_discovery_key.diffie_hellman(responder_signed_prekey_public_key);
    let dh2 = initiator_ephemeral_key.diffie_hellman(responder_discovery_public_key);
    let dh3 = initiator_ephemeral_key.diffie_hellman(responder_signed_prekey_public_key);
    let dh4 = responder_one_time_prekey_public_key
        .map(|public_key| initiator_ephemeral_key.diffie_hellman(public_key));
    derive_root_key_from_dh_outputs(&dh1, &dh2, &dh3, dh4.as_ref())
}

// Derives the responder-side root key from the X3DH Diffie-Hellman outputs:
// DH1 = SPK_B * DK_A, DH2 = DK_B * EK_A, DH3 = SPK_B * EK_A, DH4 = OPK_B * EK_A.
pub(crate) fn derive_root_key_responder(
    initiator_discovery_public_key: &PublicKey,
    initiator_ephemeral_public_key: &PublicKey,
    responder_discovery_key: &DiscoveryKey,
    responder_signed_prekey: &SignedPreKey,
    responder_one_time_prekey: Option<&OneTimePreKey>,
) -> Result<RootKey, CryptoError> {
    let dh1 = responder_signed_prekey.diffie_hellman(initiator_discovery_public_key);
    let dh2 = responder_discovery_key.diffie_hellman(initiator_ephemeral_public_key);
    let dh3 = responder_signed_prekey.diffie_hellman(initiator_ephemeral_public_key);
    let dh4 = responder_one_time_prekey
        .map(|prekey| prekey.diffie_hellman(initiator_ephemeral_public_key));
    derive_root_key_from_dh_outputs(&dh1, &dh2, &dh3, dh4.as_ref())
}

// Concatenates F_PREFIX || DH outputs and runs HKDF-SHA256 once.
fn derive_root_key_from_dh_outputs(
    dh1: &SharedSecret,
    dh2: &SharedSecret,
    dh3: &SharedSecret,
    dh4: Option<&SharedSecret>,
) -> Result<RootKey, CryptoError> {
    let capacity = if dh4.is_some() {
        INPUT_KEYING_MATERIAL_LEN_WITH_ONE_TIME_PREKEY
    } else {
        INPUT_KEYING_MATERIAL_LEN_WITHOUT_ONE_TIME_PREKEY
    };
    let mut input_keying_material: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(capacity));
    input_keying_material.extend_from_slice(&F_PREFIX);
    input_keying_material.extend_from_slice(dh1.as_bytes());
    input_keying_material.extend_from_slice(dh2.as_bytes());
    input_keying_material.extend_from_slice(dh3.as_bytes());
    if let Some(dh4) = dh4 {
        input_keying_material.extend_from_slice(dh4.as_bytes());
        derive_root_key_from_input_keying_material(
            &input_keying_material,
            HKDF_INFO_WITH_ONE_TIME_PREKEY,
        )
    } else {
        derive_root_key_from_input_keying_material(
            &input_keying_material,
            HKDF_INFO_WITHOUT_ONE_TIME_PREKEY,
        )
    }
}

/// Returns the associated data for the first ratcheted message.
///
/// The bytes are the initiator discovery public key, responder discovery public key, and responder
/// discovery-key epoch in big-endian order.
#[must_use]
pub fn initial_associated_data(
    initiator_discovery_public_key: &PublicKey,
    responder_discovery_public_key: &PublicKey,
    responder_discovery_epoch: u32,
) -> [u8; 68] {
    let mut associated_data = [0u8; 68];
    associated_data[..32].copy_from_slice(initiator_discovery_public_key.as_bytes());
    associated_data[32..64].copy_from_slice(responder_discovery_public_key.as_bytes());
    associated_data[64..].copy_from_slice(&responder_discovery_epoch.to_be_bytes());
    associated_data
}

// Derives the 32-byte ratchet root key from F_PREFIX || X3DH DH outputs.
//
// Using no salt means the RFC 5869 zero salt. That is acceptable here because the input keying
// material is already uniformly random and the info string provides domain separation.
fn derive_root_key_from_input_keying_material(
    input_keying_material: &[u8],
    info: &[u8],
) -> Result<RootKey, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, input_keying_material);
    let mut output_keying_material = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, output_keying_material.as_mut())
        .map_err(|_| CryptoError::HkdfExpand)?;
    Ok(RootKey::from_bytes(*output_keying_material))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery_key::{
        DiscoveryKey, generate_discovery_key, generate_signed_prekey_for_discovery_key,
    };
    use crate::keys::{SigningKeyPair, generate_key_pair, generate_signing_key_pair};
    use crate::one_time_prekey::{OneTimePreKey, generate_one_time_prekey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const FIXED_TS: u64 = 1_700_000_000;

    struct FullX3dhSetup {
        alice_identity: SigningKeyPair,
        alice_discovery_key: DiscoveryKey,
        bob_identity: SigningKeyPair,
        bob_discovery_key: DiscoveryKey,
        bob_signed_prekey: SignedPreKey,
        bob_one_time_prekey: OneTimePreKey,
    }

    fn full_x3dh_setup() -> (FullX3dhSetup, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
        let alice_identity = generate_signing_key_pair(&mut rng);
        let alice_discovery_key = generate_discovery_key(&mut rng, &alice_identity, 2, FIXED_TS);
        let bob_identity = generate_signing_key_pair(&mut rng);
        let bob_discovery_key = generate_discovery_key(&mut rng, &bob_identity, 3, FIXED_TS);
        let bob_signed_prekey =
            generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery_key, FIXED_TS);
        let bob_one_time_prekey =
            generate_one_time_prekey(&mut rng, 9, bob_discovery_key.epoch(), FIXED_TS);
        let setup = FullX3dhSetup {
            alice_identity,
            alice_discovery_key,
            bob_identity,
            bob_discovery_key,
            bob_signed_prekey,
            bob_one_time_prekey,
        };
        (setup, rng)
    }

    fn full_prekey_bundle(setup: &FullX3dhSetup, include_one_time: bool) -> PreKeyBundle {
        PreKeyBundle {
            discovery_key: setup.bob_discovery_key.bundle(),
            signed_prekey: setup.bob_signed_prekey.bundle(),
            one_time_prekey: include_one_time.then(|| setup.bob_one_time_prekey.bundle()),
        }
    }

    #[test]
    fn full_x3dh_associated_data_binds_discovery_keys_and_epoch() {
        let (setup, _) = full_x3dh_setup();
        let associated_data = initial_associated_data(
            setup.alice_discovery_key.public_key(),
            setup.bob_discovery_key.public_key(),
            setup.bob_discovery_key.epoch(),
        );
        assert_eq!(
            &associated_data[..32],
            setup.alice_discovery_key.public_key().as_bytes()
        );
        assert_eq!(
            &associated_data[32..64],
            setup.bob_discovery_key.public_key().as_bytes()
        );
        assert_eq!(
            &associated_data[64..],
            &setup.bob_discovery_key.epoch().to_be_bytes()
        );
    }

    #[test]
    fn initiate_accept_round_trip_with_one_time_prekey() {
        let (setup, mut rng) = full_x3dh_setup();
        let plaintext = b"hello full x3dh";
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.bob_identity.verifying,
            &bundle,
            plaintext,
        )
        .unwrap();
        assert_eq!(
            envelope.one_time_prekey_id,
            Some(setup.bob_one_time_prekey.id())
        );
        let (_, decrypted) = accept(
            &mut rng,
            &envelope,
            &setup.alice_identity.verifying,
            &setup.alice_discovery_key.bundle(),
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            Some(setup.bob_one_time_prekey),
        )
        .unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn initiate_accept_round_trip_without_one_time_prekey() {
        let (setup, mut rng) = full_x3dh_setup();
        let plaintext = b"hello signed prekey only";
        let bundle = full_prekey_bundle(&setup, false);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.bob_identity.verifying,
            &bundle,
            plaintext,
        )
        .unwrap();
        assert_eq!(envelope.one_time_prekey_id, None);
        let (_, decrypted) = accept(
            &mut rng,
            &envelope,
            &setup.alice_identity.verifying,
            &setup.alice_discovery_key.bundle(),
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            None,
        )
        .unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn accept_rejects_missing_one_time_prekey() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.bob_identity.verifying,
            &bundle,
            b"payload",
        )
        .unwrap();
        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                &setup.alice_identity.verifying,
                &setup.alice_discovery_key.bundle(),
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None,
            ),
            Err(CryptoError::MissingOneTimePreKey)
        ));
    }

    #[test]
    fn accept_rejects_mismatched_one_time_prekey() {
        let (setup, mut rng) = full_x3dh_setup();
        let wrong_one_time_prekey =
            generate_one_time_prekey(&mut rng, 10, setup.bob_discovery_key.epoch(), FIXED_TS);
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.bob_identity.verifying,
            &bundle,
            b"payload",
        )
        .unwrap();
        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                &setup.alice_identity.verifying,
                &setup.alice_discovery_key.bundle(),
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                Some(wrong_one_time_prekey),
            ),
            Err(CryptoError::OneTimePreKeyMismatch)
        ));
    }

    #[test]
    fn initiate_rejects_stale_one_time_prekey_epoch() {
        let (setup, mut rng) = full_x3dh_setup();
        let stale_one_time_prekey =
            generate_one_time_prekey(&mut rng, 10, setup.bob_discovery_key.epoch() + 1, FIXED_TS);
        let bundle = PreKeyBundle {
            discovery_key: setup.bob_discovery_key.bundle(),
            signed_prekey: setup.bob_signed_prekey.bundle(),
            one_time_prekey: Some(stale_one_time_prekey.bundle()),
        };
        assert!(matches!(
            initiate(
                &mut rng,
                &setup.alice_discovery_key,
                &setup.bob_identity.verifying,
                &bundle,
                b"payload",
            ),
            Err(CryptoError::StalePreKey)
        ));
    }

    #[test]
    fn initiator_and_responder_derive_identical_root_key() {
        let (setup, mut rng) = full_x3dh_setup();
        let alice_ephemeral_key = generate_key_pair(&mut rng);
        let initiator_root_key = derive_root_key_initiator(
            &setup.alice_discovery_key,
            &alice_ephemeral_key,
            setup.bob_discovery_key.public_key(),
            setup.bob_signed_prekey.public(),
            Some(setup.bob_one_time_prekey.public()),
        )
        .unwrap();
        let responder_root_key = derive_root_key_responder(
            setup.alice_discovery_key.public_key(),
            &alice_ephemeral_key.public,
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            Some(&setup.bob_one_time_prekey),
        )
        .unwrap();
        assert_eq!(initiator_root_key.as_bytes(), responder_root_key.as_bytes());
    }

    #[test]
    fn initiate_rejects_bundle_under_wrong_verifying_key() {
        let (setup, mut rng) = full_x3dh_setup();
        let wrong_signing_key = generate_signing_key_pair(&mut rng);
        let bundle = full_prekey_bundle(&setup, true);
        let result = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &wrong_signing_key.verifying,
            &bundle,
            b"payload",
        );
        assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn accept_rejects_mismatched_signed_prekey_public_key() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, false);
        let (_, mut envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.bob_identity.verifying,
            &bundle,
            b"payload",
        )
        .unwrap();
        envelope.responder_signed_prekey_public_key[0] ^= 0x01;
        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                &setup.alice_identity.verifying,
                &setup.alice_discovery_key.bundle(),
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None,
            ),
            Err(CryptoError::HandshakeSignedPreKeyMismatch)
        ));
    }

    #[test]
    fn accept_rejects_initiator_discovery_key_mismatch() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.bob_identity.verifying,
            &bundle,
            b"payload",
        )
        .unwrap();
        let mallory_identity = generate_signing_key_pair(&mut rng);
        let mallory_discovery_key =
            generate_discovery_key(&mut rng, &mallory_identity, 8, FIXED_TS);

        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                &mallory_identity.verifying,
                &mallory_discovery_key.bundle(),
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                Some(setup.bob_one_time_prekey),
            ),
            Err(CryptoError::HandshakeDiscoveryKeyMismatch)
        ));
    }

    #[test]
    fn accept_rejects_tampered_ciphertext() {
        let (setup, mut rng) = full_x3dh_setup();
        let bundle = full_prekey_bundle(&setup, false);
        let (_, mut envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.bob_identity.verifying,
            &bundle,
            b"tamper me",
        )
        .unwrap();
        envelope.ciphertext[0] ^= 0xFF;
        assert!(matches!(
            accept(
                &mut rng,
                &envelope,
                &setup.alice_identity.verifying,
                &setup.alice_discovery_key.bundle(),
                &setup.bob_discovery_key,
                &setup.bob_signed_prekey,
                None,
            ),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn envelope_survives_wire_round_trip() {
        let (setup, mut rng) = full_x3dh_setup();
        let plaintext = b"serialize me";
        let bundle = full_prekey_bundle(&setup, true);
        let (_, envelope) = initiate(
            &mut rng,
            &setup.alice_discovery_key,
            &setup.bob_identity.verifying,
            &bundle,
            plaintext,
        )
        .unwrap();
        let bytes = postcard::to_stdvec(&envelope).unwrap();

        let decoded_envelope: HandshakeEnvelope = postcard::from_bytes(&bytes).unwrap();
        let (_, decrypted) = accept(
            &mut rng,
            &decoded_envelope,
            &setup.alice_identity.verifying,
            &setup.alice_discovery_key.bundle(),
            &setup.bob_discovery_key,
            &setup.bob_signed_prekey,
            Some(setup.bob_one_time_prekey),
        )
        .unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }
}
