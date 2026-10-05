//! XChaCha20-Poly1305 encryption for Double Ratchet messages.
//!
//! Each message key expands into an encryption key and nonce with HKDF-SHA256. The caller's
//! associated data and the serialized header are authenticated with the ciphertext.

use super::header::Header;
use super::state::RatchetError;
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
) -> Result<Vec<u8>, RatchetError> {
    let (encryption_key, nonce) = expand_message_key(message_key)?;
    let cipher = XChaCha20Poly1305::new((&*encryption_key).into());
    let full_associated_data = build_associated_data(associated_data, header);
    let payload = Payload {
        msg: plaintext,
        aad: &full_associated_data,
    };
    cipher
        .encrypt(XNonce::from_slice(&nonce), payload)
        .map_err(|_| RatchetError::Aead)
}

pub(super) fn decrypt(
    ciphertext: &[u8],
    associated_data: &[u8],
    header: &Header,
    message_key: &MessageKey,
) -> Result<Zeroizing<Vec<u8>>, RatchetError> {
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
        .map_err(|_| RatchetError::Aead)
}

fn expand_message_key(
    message_key: &MessageKey,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 24]), RatchetError> {
    // The message key is already pseudo-random from the chain KDF, so no salt is needed.
    let hkdf = Hkdf::<Sha256>::new(None, message_key.as_bytes());
    let mut output_key_material = Zeroizing::new([0u8; 56]);
    hkdf.expand(MESSAGE_KEY_HKDF_INFO, output_key_material.as_mut())
        .map_err(|_| RatchetError::HkdfExpand)?;

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

    #[test]
    fn message_key_expansion_changes_with_the_message_key() {
        let (encryption_key, nonce) = expand_message_key(&MessageKey([1; 32])).unwrap();
        let (other_encryption_key, other_nonce) = expand_message_key(&MessageKey([2; 32])).unwrap();

        assert_ne!(*other_encryption_key, *encryption_key);
        assert_ne!(other_nonce, nonce);
    }
}
