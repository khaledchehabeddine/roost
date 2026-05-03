use super::header::Header;
use crate::error::CryptoError;
use crate::ratchet::MessageKey;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const HKDF_MK_INFO: &[u8] = b"HermesRatchet_MK";

/// Encrypts plaintext with XChaCha20-Poly1305 using a derived encryption key and nonce.
pub(super) fn encrypt(
    plaintext: &[u8],
    ad: &[u8],
    header: &Header,
    mk: &MessageKey,
) -> Result<Vec<u8>, CryptoError> {
    let (enc_key, nonce) = expand_message_key(mk)?;
    let cipher = XChaCha20Poly1305::new((&*enc_key).into());
    let full_ad = build_full_ad(ad, header);
    let payload = Payload {
        msg: plaintext,
        aad: &full_ad,
    };
    cipher
        .encrypt(XNonce::from_slice(&nonce), payload)
        .map_err(|_| CryptoError::Aead)
}

/// Decrypts ciphertext with XChaCha20-Poly1305 using a derived encryption key and nonce.
pub(super) fn decrypt(
    ciphertext: &[u8],
    ad: &[u8],
    header: &Header,
    mk: &MessageKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (enc_key, nonce) = expand_message_key(mk)?;
    let cipher = XChaCha20Poly1305::new((&*enc_key).into());
    let full_ad = build_full_ad(ad, header);
    let payload = Payload {
        msg: ciphertext,
        aad: &full_ad,
    };
    cipher
        .decrypt(XNonce::from_slice(&nonce), payload)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Aead)
}

/// Expands a message key into a 32-byte encryption key and 24-byte nonce via HKDF-SHA256.
fn expand_message_key(mk: &MessageKey) -> Result<(Zeroizing<[u8; 32]>, [u8; 24]), CryptoError> {
    // MK is already pseudo-random from the chain KDF, so no salt is needed (RFC 5869 §3.1).
    let hkdf = Hkdf::<Sha256>::new(None, mk.as_bytes());
    let mut okm = Zeroizing::new([0u8; 56]);
    hkdf.expand(HKDF_MK_INFO, okm.as_mut())
        .map_err(|_| CryptoError::HkdfExpand)?;

    let mut enc_key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 24];
    enc_key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..56]);

    Ok((enc_key, nonce))
}

/// Builds the full associated data: caller-provided AD concatenated with the serialized header.
fn build_full_ad(ad: &[u8], header: &Header) -> Vec<u8> {
    let serialized = header.serialize();
    let mut full_ad = Vec::with_capacity(ad.len() + serialized.len());
    full_ad.extend_from_slice(ad);
    full_ad.extend_from_slice(&serialized);
    full_ad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    /// The libsodium-reference ciphertext for the fixed AEAD KAT inputs.
    ///
    /// Referenced by both [`aead_encrypt_known_answer`] and [`aead_decrypt_known_answer`], so the
    /// two tests cannot drift silently if one is regenerated without the other.
    const AEAD_KAT_EXPECTED_CIPHERTEXT: [u8; 44] = [
        0x91, 0x16, 0x40, 0xd9, 0xfd, 0xe7, 0xe2, 0xea, 0x55, 0x82, 0xd5, 0x28, 0xd8, 0x6c, 0x14,
        0x7a, 0xab, 0xe0, 0x97, 0x1b, 0xd6, 0x6c, 0xe1, 0x92, 0x0b, 0x2d, 0x98, 0x59, 0x43, 0x13,
        0xe5, 0xbf, 0xd0, 0x8e, 0xdf, 0x7e, 0xec, 0xbf, 0x8a, 0xe2, 0x2a, 0x21, 0x42, 0x9d,
    ];

    /// Expected encryption key from [`expand_message_key`] applied to `MessageKey([0; 32])`.
    /// Derived with pyca/cryptography 46 (HKDF-SHA256).
    const EXPAND_MK_KAT_EXPECTED_ENC_KEY: [u8; 32] = [
        0x59, 0x97, 0xfd, 0xfa, 0x34, 0xf8, 0x50, 0x6f, 0xe9, 0xdd, 0x5a, 0x04, 0x63, 0x2f, 0x66,
        0x23, 0xff, 0xc1, 0x7f, 0x89, 0x80, 0x0b, 0xbc, 0x33, 0x5b, 0xa1, 0xbc, 0xa9, 0x69, 0x2c,
        0x61, 0x5b,
    ];

    /// Expected nonce from [`expand_message_key`] applied to `MessageKey([0; 32])`.
    /// Derived with pyca/cryptography 46 (HKDF-SHA256).
    const EXPAND_MK_KAT_EXPECTED_NONCE: [u8; 24] = [
        0x24, 0xa8, 0xcc, 0x09, 0x24, 0x67, 0xef, 0xa0, 0x06, 0x9e, 0xb9, 0x58, 0x64, 0x4f, 0x82,
        0x58, 0x88, 0x58, 0x95, 0xad, 0x2e, 0x20, 0x1b, 0x80,
    ];

    /// Known-answer test for [`expand_message_key`].
    ///
    /// Inputs: `mk = MessageKey([0; 32])`.
    ///
    /// Algorithm: HKDF-SHA256(salt = None, ikm = mk, info = [`HKDF_MK_INFO`], L = 56).
    /// Output split: `okm[0..32] = enc_key`, `okm[32..56] = nonce` (24-byte XNonce).
    #[test]
    fn expand_message_key_known_answer() {
        let mk = MessageKey([0u8; 32]);
        let (enc_key, nonce) = expand_message_key(&mk).unwrap();

        assert_eq!(enc_key.as_slice(), &EXPAND_MK_KAT_EXPECTED_ENC_KEY);
        assert_eq!(nonce, EXPAND_MK_KAT_EXPECTED_NONCE);
    }

    /// Known-answer test for [`encrypt`] (XChaCha20-Poly1305 with header AD).
    ///
    /// Inputs:
    /// - `mk = MessageKey([0; 32])` (`enc_key` and `nonce` match
    ///   [`expand_message_key_known_answer`]).
    /// - `plaintext = b"Hermes test vector plaintext"` (28 bytes).
    /// - `caller_ad = b"initiator_identity||responder_identity"`.
    /// - `header.public_key = KeyPair::from_secret_bytes([0x99; 32]).public` — the stored public
    ///   is the X25519-clamped scalar multiplication result, not the raw input bytes.
    /// - `header.pn = 0`, `header.n = 0`.
    ///
    /// AD construction: `full_ad = caller_ad || header.serialize()`, where `serialize`
    /// emits `public_key (32) || pn_be (4) || n_be (4)` (big-endian u32 counters; see
    /// [`Header::serialize`]). A byte-order refactor of the header would silently invalidate
    /// this vector.
    ///
    /// Expected ciphertext derived with libsodium (pynacl 1.5's
    /// `crypto_aead_xchacha20poly1305_ietf_encrypt`) — deliberately a different implementation
    /// than the RustCrypto `chacha20poly1305` crate under test.
    ///
    /// The decrypt direction has a paired KAT at [`aead_decrypt_known_answer`].
    #[test]
    fn aead_encrypt_known_answer() {
        let mk = MessageKey([0u8; 32]);
        let plaintext = b"Hermes test vector plaintext";
        let caller_ad = b"initiator_identity||responder_identity";
        let header = Header {
            public_key: KeyPair::from_secret_bytes([0x99u8; 32]).public,
            pn: 0,
            n: 0,
        };

        let ciphertext = encrypt(plaintext, caller_ad, &header, &mk).unwrap();
        assert_eq!(ciphertext.as_slice(), &AEAD_KAT_EXPECTED_CIPHERTEXT);
    }

    /// Known-answer test for [`decrypt`] (XChaCha20-Poly1305 with header AD).
    ///
    /// Inputs: the same `mk`, `caller_ad`, and `header` as [`aead_encrypt_known_answer`], with
    /// [`AEAD_KAT_EXPECTED_CIPHERTEXT`] as the ciphertext input.
    ///
    /// Covers the class of bug where `encrypt` and `decrypt` share a matching fault (e.g., a
    /// future refactor of `build_full_ad` affecting both call sites) — round-trip tests would
    /// pass in that case because both sides agree. This KAT catches the divergence from
    /// libsodium's reference.
    #[test]
    fn aead_decrypt_known_answer() {
        let mk = MessageKey([0u8; 32]);
        let expected_plaintext = b"Hermes test vector plaintext";
        let caller_ad = b"initiator_identity||responder_identity";
        let header = Header {
            public_key: KeyPair::from_secret_bytes([0x99u8; 32]).public,
            pn: 0,
            n: 0,
        };

        let recovered = decrypt(&AEAD_KAT_EXPECTED_CIPHERTEXT, caller_ad, &header, &mk).unwrap();
        assert_eq!(recovered.as_slice(), expected_plaintext);
    }
}
