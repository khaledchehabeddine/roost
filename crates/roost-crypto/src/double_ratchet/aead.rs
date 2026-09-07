//! XChaCha20-Poly1305 encryption for Double Ratchet messages.
//!
//! Each message key expands into an encryption key and nonce with HKDF-SHA256. The caller's
//! associated data and the serialized header are authenticated with the ciphertext.

use super::header::Header;
use crate::error::CryptoError;
use crate::ratchet::MessageKey;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const MESSAGE_KEY_HKDF_INFO: &[u8] = b"AetherRatchet_MK";

pub(super) fn encrypt(
    plaintext: &[u8],
    associated_data: &[u8],
    header: &Header,
    message_key: &MessageKey,
) -> Result<Vec<u8>, CryptoError> {
    let (encryption_key, nonce) = expand_message_key(message_key)?;
    let cipher = XChaCha20Poly1305::new((&*encryption_key).into());
    let full_associated_data = build_associated_data(associated_data, header);
    let payload = Payload {
        msg: plaintext,
        aad: &full_associated_data,
    };
    cipher
        .encrypt(XNonce::from_slice(&nonce), payload)
        .map_err(|_| CryptoError::Aead)
}

pub(super) fn decrypt(
    ciphertext: &[u8],
    associated_data: &[u8],
    header: &Header,
    message_key: &MessageKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (encryption_key, nonce) = expand_message_key(message_key)?;
    let cipher = XChaCha20Poly1305::new((&*encryption_key).into());
    let full_associated_data = build_associated_data(associated_data, header);
    let payload = Payload {
        msg: ciphertext,
        aad: &full_associated_data,
    };
    cipher
        .decrypt(XNonce::from_slice(&nonce), payload)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Aead)
}

fn expand_message_key(
    message_key: &MessageKey,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 24]), CryptoError> {
    // The message key is already pseudo-random from the chain KDF, so no salt is needed.
    let hkdf = Hkdf::<Sha256>::new(None, message_key.as_bytes());
    let mut output_key_material = Zeroizing::new([0u8; 56]);
    hkdf.expand(MESSAGE_KEY_HKDF_INFO, output_key_material.as_mut())
        .map_err(|_| CryptoError::HkdfExpand)?;

    let mut encryption_key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 24];
    encryption_key.copy_from_slice(&output_key_material[..32]);
    nonce.copy_from_slice(&output_key_material[32..56]);
    Ok((encryption_key, nonce))
}

fn build_associated_data(associated_data: &[u8], header: &Header) -> Vec<u8> {
    let serialized = header.serialize();
    let mut authenticated_data = Vec::with_capacity(associated_data.len() + serialized.len());
    authenticated_data.extend_from_slice(associated_data);
    authenticated_data.extend_from_slice(&serialized);
    authenticated_data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    /// Expected ciphertext for the AEAD KAT.
    const AEAD_KAT_EXPECTED_CIPHERTEXT: [u8; 44] = [
        0x9f, 0xd4, 0xab, 0x7d, 0xc3, 0x6e, 0x50, 0xb4, 0x3a, 0xff, 0xe5, 0x6f, 0xff, 0x9d, 0xe2,
        0xf2, 0x49, 0x38, 0xc2, 0x68, 0xd2, 0x5a, 0xb3, 0x58, 0x9d, 0x56, 0xd3, 0x7c, 0xb1, 0x94,
        0x0b, 0x8a, 0x0c, 0xbc, 0x25, 0x4e, 0x82, 0xc1, 0xc2, 0xdc, 0x99, 0xde, 0xc5, 0x87,
    ];

    /// Expected encryption key for the `expand_message_key` KAT.
    const EXPAND_MESSAGE_KEY_KAT_EXPECTED_ENCRYPTION_KEY: [u8; 32] = [
        0xf2, 0xb1, 0x58, 0x07, 0x8e, 0xde, 0x49, 0x22, 0x2f, 0x74, 0x5b, 0x71, 0xb7, 0xb0, 0x23,
        0x44, 0xf3, 0x8a, 0xe2, 0xc6, 0x50, 0x77, 0x4e, 0x2a, 0x61, 0xed, 0xe0, 0xae, 0x5a, 0xd5,
        0x47, 0x64,
    ];

    /// Expected nonce for the `expand_message_key` KAT.
    const EXPAND_MESSAGE_KEY_KAT_EXPECTED_NONCE: [u8; 24] = [
        0x95, 0xa3, 0xa8, 0xac, 0x37, 0x14, 0xf5, 0xcc, 0x49, 0xa6, 0xd5, 0xfa, 0x6e, 0x39, 0x8c,
        0x41, 0x69, 0xc0, 0x95, 0xb3, 0x57, 0x1d, 0xc7, 0xd7,
    ];

    /// Known-answer test for `expand_message_key`.
    ///
    /// Source: pyca/cryptography 46 `HKDF(...).derive`
    ///
    /// Inputs:
    /// - `message_key = MessageKey([0; 32])`
    /// - `info = MESSAGE_KEY_HKDF_INFO`
    ///
    /// Derivation:
    /// ```text
    /// HKDF-SHA256(
    ///   salt = None,
    ///   ikm = message_key,
    ///   info = MESSAGE_KEY_HKDF_INFO,
    ///   L = 56
    /// )
    /// ```
    ///
    /// Output:
    /// - `output_key_material[0..32] = encryption_key`
    /// - `output_key_material[32..56] = nonce`
    #[test]
    fn expand_message_key_known_answer() {
        let message_key = MessageKey([0u8; 32]);
        let (encryption_key, nonce) = expand_message_key(&message_key).unwrap();
        assert_eq!(
            encryption_key.as_slice(),
            &EXPAND_MESSAGE_KEY_KAT_EXPECTED_ENCRYPTION_KEY
        );
        assert_eq!(nonce, EXPAND_MESSAGE_KEY_KAT_EXPECTED_NONCE);
    }

    /// Known-answer test for `encrypt`.
    ///
    /// Source: PyNaCl 1.5 `crypto_aead_xchacha20poly1305_ietf_encrypt`
    ///
    /// Inputs:
    /// - `message_key = MessageKey([0; 32])`
    /// - `plaintext = b"Aether test vector plaintext"` (28 bytes)
    /// - `associated_data = b"initiator_identity||responder_identity"`
    /// - `header.public_key = KeyPair::from_secret_bytes([0x99; 32]).public` — the stored public
    ///   is the X25519-clamped scalar multiplication result, not the raw input bytes.
    /// - `header.previous_chain_length = 0`
    /// - `header.message_number = 0`
    ///
    /// Derivation:
    /// ```text
    /// encryption_key, nonce = expand_message_key(message_key)
    /// authenticated_data = associated_data || header.serialize()
    /// ciphertext = XChaCha20-Poly1305-Encrypt(
    ///   encryption_key, nonce, plaintext, authenticated_data
    /// )
    /// ```
    ///
    /// Output: `ciphertext = AEAD_KAT_EXPECTED_CIPHERTEXT`
    #[test]
    fn aead_encrypt_known_answer() {
        let message_key = MessageKey([0u8; 32]);
        let plaintext = b"Aether test vector plaintext";
        let associated_data = b"initiator_identity||responder_identity";
        let header = Header {
            public_key: KeyPair::from_secret_bytes([0x99u8; 32]).public,
            previous_chain_length: 0,
            message_number: 0,
        };
        let ciphertext = encrypt(plaintext, associated_data, &header, &message_key).unwrap();
        assert_eq!(ciphertext.as_slice(), &AEAD_KAT_EXPECTED_CIPHERTEXT);
    }

    /// Known-answer test for `decrypt`.
    ///
    /// Source: PyNaCl 1.5 `crypto_aead_xchacha20poly1305_ietf_encrypt`
    ///
    /// Inputs:
    /// - `message_key = MessageKey([0; 32])`
    /// - `ciphertext = AEAD_KAT_EXPECTED_CIPHERTEXT`
    /// - `associated_data = b"initiator_identity||responder_identity"`
    /// - `header.public_key = KeyPair::from_secret_bytes([0x99; 32]).public`
    /// - `header.previous_chain_length = 0`
    /// - `header.message_number = 0`
    ///
    /// Derivation:
    /// ```text
    /// encryption_key, nonce = expand_message_key(message_key)
    /// authenticated_data = associated_data || header.serialize()
    /// plaintext = XChaCha20-Poly1305-Decrypt(
    ///   encryption_key, nonce, ciphertext, authenticated_data
    /// )
    /// ```
    ///
    /// Output: `plaintext = b"Aether test vector plaintext"`
    #[test]
    fn aead_decrypt_known_answer() {
        let message_key = MessageKey([0u8; 32]);
        let expected_plaintext = b"Aether test vector plaintext";
        let associated_data = b"initiator_identity||responder_identity";
        let header = Header {
            public_key: KeyPair::from_secret_bytes([0x99u8; 32]).public,
            previous_chain_length: 0,
            message_number: 0,
        };
        let recovered = decrypt(
            &AEAD_KAT_EXPECTED_CIPHERTEXT,
            associated_data,
            &header,
            &message_key,
        )
        .unwrap();
        assert_eq!(recovered.as_slice(), expected_plaintext);
    }
}
