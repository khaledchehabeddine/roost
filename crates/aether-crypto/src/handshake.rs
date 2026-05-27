//! Implements the X3DH-lite handshake that bootstraps Double Ratchet sessions.

use crate::double_ratchet::{Header, RatchetState};
use crate::error::CryptoError;
use crate::keys::{KeyPair, PublicKey, SharedSecret, VerifyingKey, generate_key_pair};
use crate::ratchet::RootKey;
use crate::signed_prekey::{SignedPreKey, SignedPreKeyBundle, verify_bundle};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// Fixed prefix on the HKDF input. Future incompatible handshake derivations should change these
// bytes so peers fail during the first decrypt.
const F_PREFIX: [u8; 32] = [0xFF; 32];
// Domain separator for the handshake root-key derivation.
const HKDF_INFO: &[u8] = b"AetherX3DHLite";
// F_PREFIX || DH1 || DH2 || DH3, with each segment being 32 bytes.
const INPUT_KEYING_MATERIAL_LEN: usize = 32 * 4;

/// A serialized handshake request from an initiator to a responder.
///
/// Holds public handshake material, the first ratchet header fields, and the first ciphertext.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HandshakeEnvelope {
    /// Initiator's X25519 identity public key.
    pub initiator_identity_public_key: [u8; 32],
    /// Initiator's X25519 ephemeral public key (fresh per handshake).
    pub initiator_ephemeral_public_key: [u8; 32],
    /// X25519 public key of the responder's signed pre-key the initiator targeted.
    pub responder_signed_prekey_public_key: [u8; 32],
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
/// # Errors
/// - [`CryptoError::Aead`] when first-message encryption fails.
/// - [`CryptoError::HkdfExpand`] when the HKDF run for root-key derivation fails.
/// - [`CryptoError::InvalidState`] when ratchet seeding produces an invalid initial state.
/// - [`CryptoError::SignatureInvalid`] when `responder_signed_prekey_bundle` does not verify under
///   `responder_identity_verifying_key`.
pub fn initiate(
    initiator_identity_key: &KeyPair,
    responder_identity_verifying_key: &VerifyingKey,
    responder_identity_key: &PublicKey,
    responder_signed_prekey_bundle: &SignedPreKeyBundle,
    plaintext: &[u8],
) -> Result<(RatchetState, HandshakeEnvelope), CryptoError> {
    verify_bundle(
        responder_signed_prekey_bundle,
        responder_identity_verifying_key,
    )?;

    let initiator_ephemeral_key = generate_key_pair();
    let responder_signed_prekey_public_key = responder_signed_prekey_bundle.public_key;

    let root_key = derive_root_key_initiator(
        initiator_identity_key,
        &initiator_ephemeral_key,
        responder_identity_key,
        &responder_signed_prekey_public_key,
    )?;
    let mut state = RatchetState::init_initiator(root_key, &responder_signed_prekey_public_key)?;

    let associated_data =
        initial_associated_data(&initiator_identity_key.public, responder_identity_key);
    let (header, ciphertext) = state.ratchet_encrypt(plaintext, &associated_data)?;

    let envelope = HandshakeEnvelope {
        initiator_identity_public_key: *initiator_identity_key.public.as_bytes(),
        initiator_ephemeral_public_key: *initiator_ephemeral_key.public.as_bytes(),
        responder_signed_prekey_public_key: *responder_signed_prekey_public_key.as_bytes(),
        ratchet_public_key: *header.public_key.as_bytes(),
        previous_chain_length: header.previous_chain_length,
        message_number: header.message_number,
        ciphertext,
    };

    Ok((state, envelope))
}

/// Accepts a handshake envelope and decrypts the first message.
///
/// # Errors
/// - [`CryptoError::Aead`] when first-message decryption fails (tampered ciphertext, wrong
///   associated data, or wrong key).
/// - [`CryptoError::HandshakeSignedPreKeyMismatch`] when
///   `envelope.responder_signed_prekey_public_key` does not match
///   `responder_signed_prekey.public()`.
/// - [`CryptoError::HkdfExpand`] when the HKDF run for root-key derivation fails.
/// - [`CryptoError::InvalidState`] when ratchet decryption observes an invalid receiving state.
pub fn accept(
    envelope: &HandshakeEnvelope,
    responder_identity_key: &KeyPair,
    responder_signed_prekey: &SignedPreKey,
) -> Result<(RatchetState, Zeroizing<Vec<u8>>), CryptoError> {
    let signed_prekey_matches: bool = envelope
        .responder_signed_prekey_public_key
        .ct_eq(responder_signed_prekey.public().as_bytes())
        .into();
    if !signed_prekey_matches {
        return Err(CryptoError::HandshakeSignedPreKeyMismatch);
    }

    let initiator_identity_public_key = PublicKey::from(envelope.initiator_identity_public_key);
    let initiator_ephemeral_public_key = PublicKey::from(envelope.initiator_ephemeral_public_key);

    let root_key = derive_root_key_responder(
        &initiator_identity_public_key,
        &initiator_ephemeral_public_key,
        responder_identity_key,
        responder_signed_prekey,
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
        &initiator_identity_public_key,
        &responder_identity_key.public,
    );
    let plaintext = state.ratchet_decrypt(&envelope.ciphertext, &header, &associated_data)?;

    Ok((state, plaintext))
}

// Derives the initiator-side root key from the three X3DH-lite Diffie-Hellman outputs:
// DH1 = IK_A * SPK_B, DH2 = EK_A * IK_B, DH3 = EK_A * SPK_B.
pub(crate) fn derive_root_key_initiator(
    initiator_identity_key: &KeyPair,
    initiator_ephemeral_key: &KeyPair,
    responder_identity_public_key: &PublicKey,
    responder_signed_prekey_public_key: &PublicKey,
) -> Result<RootKey, CryptoError> {
    let dh1 = initiator_identity_key.diffie_hellman(responder_signed_prekey_public_key);
    let dh2 = initiator_ephemeral_key.diffie_hellman(responder_identity_public_key);
    let dh3 = initiator_ephemeral_key.diffie_hellman(responder_signed_prekey_public_key);
    derive_root_key_from_dh_outputs(&dh1, &dh2, &dh3)
}

// Derives the responder-side root key from the three X3DH-lite Diffie-Hellman outputs:
// DH1 = SPK_B * IK_A, DH2 = IK_B * EK_A, DH3 = SPK_B * EK_A.
pub(crate) fn derive_root_key_responder(
    initiator_identity_public_key: &PublicKey,
    initiator_ephemeral_public_key: &PublicKey,
    responder_identity_key: &KeyPair,
    responder_signed_prekey: &SignedPreKey,
) -> Result<RootKey, CryptoError> {
    let dh1 = responder_signed_prekey.diffie_hellman(initiator_identity_public_key);
    let dh2 = responder_identity_key.diffie_hellman(initiator_ephemeral_public_key);
    let dh3 = responder_signed_prekey.diffie_hellman(initiator_ephemeral_public_key);
    derive_root_key_from_dh_outputs(&dh1, &dh2, &dh3)
}

// Concatenates F_PREFIX || DH1 || DH2 || DH3 and runs HKDF-SHA256 once.
fn derive_root_key_from_dh_outputs(
    dh1: &SharedSecret,
    dh2: &SharedSecret,
    dh3: &SharedSecret,
) -> Result<RootKey, CryptoError> {
    let mut input_keying_material: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(INPUT_KEYING_MATERIAL_LEN));
    input_keying_material.extend_from_slice(&F_PREFIX);
    input_keying_material.extend_from_slice(dh1.as_bytes());
    input_keying_material.extend_from_slice(dh2.as_bytes());
    input_keying_material.extend_from_slice(dh3.as_bytes());
    derive_root_key_from_input_keying_material(&input_keying_material)
}

/// Returns the associated data for the first ratcheted message.
///
/// The bytes are the initiator X25519 identity public key followed by the responder X25519
/// identity public key.
#[must_use]
pub fn initial_associated_data(
    initiator_identity_public_key: &PublicKey,
    responder_identity_public_key: &PublicKey,
) -> [u8; 64] {
    let mut associated_data = [0u8; 64];
    associated_data[..32].copy_from_slice(initiator_identity_public_key.as_bytes());
    associated_data[32..].copy_from_slice(responder_identity_public_key.as_bytes());
    associated_data
}

// Derives the 32-byte ratchet root key from F_PREFIX || DH1 || DH2 || DH3.
//
// Using no salt means the RFC 5869 zero salt. That is acceptable here because the input keying
// material is already uniformly random and HKDF_INFO provides domain separation.
fn derive_root_key_from_input_keying_material(
    input_keying_material: &[u8],
) -> Result<RootKey, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, input_keying_material);
    let mut output_keying_material = Zeroizing::new([0u8; 32]);
    hkdf.expand(HKDF_INFO, output_keying_material.as_mut())
        .map_err(|_| CryptoError::HkdfExpand)?;
    Ok(RootKey::from_bytes(*output_keying_material))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{SigningKeyPair, generate_key_pair, generate_signing_key_pair};
    use crate::signed_prekey::generate_signed_prekey;

    const FIXED_TS: u64 = 1_700_000_000;

    struct Setup {
        alice_identity_key: KeyPair,
        bob_identity_key: KeyPair,
        bob_signing_key: SigningKeyPair,
        bob_signed_prekey: SignedPreKey,
    }

    fn setup() -> Setup {
        let bob_signing_key = generate_signing_key_pair();
        let bob_signed_prekey = generate_signed_prekey(&bob_signing_key, FIXED_TS);
        Setup {
            alice_identity_key: generate_key_pair(),
            bob_identity_key: generate_key_pair(),
            bob_signing_key,
            bob_signed_prekey,
        }
    }

    #[test]
    fn initial_associated_data_layout_is_initiator_then_responder() {
        let initiator_identity_key = generate_key_pair();
        let responder_identity_key = generate_key_pair();
        let associated_data = initial_associated_data(
            &initiator_identity_key.public,
            &responder_identity_key.public,
        );
        assert_eq!(
            &associated_data[..32],
            initiator_identity_key.public.as_bytes()
        );
        assert_eq!(
            &associated_data[32..],
            responder_identity_key.public.as_bytes()
        );
    }

    #[test]
    fn initiator_and_responder_derive_identical_root_key() {
        let setup = setup();
        let alice_ephemeral_key = generate_key_pair();
        let initiator_root_key = derive_root_key_initiator(
            &setup.alice_identity_key,
            &alice_ephemeral_key,
            &setup.bob_identity_key.public,
            setup.bob_signed_prekey.public(),
        )
        .unwrap();
        let responder_root_key = derive_root_key_responder(
            &setup.alice_identity_key.public,
            &alice_ephemeral_key.public,
            &setup.bob_identity_key,
            &setup.bob_signed_prekey,
        )
        .unwrap();
        assert_eq!(initiator_root_key.as_bytes(), responder_root_key.as_bytes());
    }

    #[test]
    fn initiate_accept_round_trip() {
        let setup = setup();
        let plaintext = b"hello from Alice";
        let (_, envelope) = initiate(
            &setup.alice_identity_key,
            &setup.bob_signing_key.verifying,
            &setup.bob_identity_key.public,
            &setup.bob_signed_prekey.bundle(),
            plaintext,
        )
        .unwrap();
        let (_, decrypted) =
            accept(&envelope, &setup.bob_identity_key, &setup.bob_signed_prekey).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn initiate_rejects_bundle_under_wrong_verifying_key() {
        let setup = setup();
        let wrong_signing_key = generate_signing_key_pair();
        let result = initiate(
            &setup.alice_identity_key,
            &wrong_signing_key.verifying,
            &setup.bob_identity_key.public,
            &setup.bob_signed_prekey.bundle(),
            b"payload",
        );
        assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn accept_rejects_mismatched_signed_prekey_public_key() {
        let setup = setup();
        let (_, mut envelope) = initiate(
            &setup.alice_identity_key,
            &setup.bob_signing_key.verifying,
            &setup.bob_identity_key.public,
            &setup.bob_signed_prekey.bundle(),
            b"payload",
        )
        .unwrap();
        envelope.responder_signed_prekey_public_key[0] ^= 0x01;
        assert!(matches!(
            accept(&envelope, &setup.bob_identity_key, &setup.bob_signed_prekey),
            Err(CryptoError::HandshakeSignedPreKeyMismatch)
        ));
    }

    #[test]
    fn accept_rejects_tampered_ciphertext() {
        let setup = setup();
        let (_, mut envelope) = initiate(
            &setup.alice_identity_key,
            &setup.bob_signing_key.verifying,
            &setup.bob_identity_key.public,
            &setup.bob_signed_prekey.bundle(),
            b"tamper me",
        )
        .unwrap();
        envelope.ciphertext[0] ^= 0xFF;
        assert!(matches!(
            accept(&envelope, &setup.bob_identity_key, &setup.bob_signed_prekey),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn envelope_survives_wire_round_trip() {
        let setup = setup();
        let plaintext = b"serialize me";
        let (_, envelope) = initiate(
            &setup.alice_identity_key,
            &setup.bob_signing_key.verifying,
            &setup.bob_identity_key.public,
            &setup.bob_signed_prekey.bundle(),
            plaintext,
        )
        .unwrap();
        let bytes = postcard::to_stdvec(&envelope).unwrap();

        let decoded_envelope: HandshakeEnvelope = postcard::from_bytes(&bytes).unwrap();
        let (_, decrypted) = accept(
            &decoded_envelope,
            &setup.bob_identity_key,
            &setup.bob_signed_prekey,
        )
        .unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }
}
