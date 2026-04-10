use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{CryptoError, KeyPair, PublicKey, SharedSecret};

const RK_INFO: &[u8] = b"HermesRatchet_RK";

/// Root key for the Double Ratchet root chain.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootKey(pub(crate) [u8; 32]);

/// Chain key for the Double Ratchet sending/receiving chain.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChainKey(pub(crate) [u8; 32]);

/// Single-use message encryption key derived from a chain key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MessageKey(pub(crate) [u8; 32]);

impl RootKey {
    /// Creates a `RootKey` from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes of this root key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ChainKey {
    /// Creates a `ChainKey` from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes of this chain key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl MessageKey {
    /// Returns the raw bytes of this message key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Performs an X25519 Diffie–Hellman key agreement.
///
/// This is the `DH()` function from the Double Ratchet specification.
/// Not yet called outside tests — the ratchet state machine will use it.
#[allow(dead_code)]
pub(crate) fn dh(key_pair: &KeyPair, their_public: &PublicKey) -> SharedSecret {
    key_pair.diffie_hellman(their_public)
}

/// Root-chain KDF: derives a new root key and chain key from a root key and DH output.
///
/// Uses HKDF-SHA256 with the root key as salt, DH output as input keying material,
/// and `b"HermesRatchet_RK"` as the info string. Produces 64 bytes of output, split
/// into a 32-byte root key and a 32-byte chain key.
#[must_use = "derived key material must not be silently discarded"]
pub fn kdf_rk(
    root_key: &RootKey,
    dh_output: &SharedSecret,
) -> Result<(RootKey, ChainKey), CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(&root_key.0), dh_output.as_bytes());
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(RK_INFO, okm.as_mut()).map_err(|_| CryptoError::HkdfExpand)?;

    let mut rk = Zeroizing::new([0u8; 32]);
    let mut ck = Zeroizing::new([0u8; 32]);
    rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);

    Ok((RootKey(*rk), ChainKey(*ck)))
}

/// Symmetric-chain KDF: derives the next chain key and a message key from a chain key.
///
/// Uses HMAC-SHA256 with the chain key as the HMAC key:
/// - Message key = HMAC(chain_key, 0x01)
/// - Next chain key = HMAC(chain_key, 0x02)
#[must_use = "derived key material must not be silently discarded"]
pub fn kdf_ck(chain_key: &ChainKey) -> Result<(ChainKey, MessageKey), CryptoError> {
    let mut mac_mk =
        Hmac::<Sha256>::new_from_slice(&chain_key.0).map_err(|_| CryptoError::InvalidHmacKey)?;
    mac_mk.update(&[0x01]);
    let mut mk_result = mac_mk.finalize().into_bytes();

    let mut mac_ck =
        Hmac::<Sha256>::new_from_slice(&chain_key.0).map_err(|_| CryptoError::InvalidHmacKey)?;
    mac_ck.update(&[0x02]);
    let mut ck_result = mac_ck.finalize().into_bytes();

    let mut mk = Zeroizing::new([0u8; 32]);
    let mut ck = Zeroizing::new([0u8; 32]);
    mk.copy_from_slice(&mk_result);
    ck.copy_from_slice(&ck_result);

    mk_result.zeroize();
    ck_result.zeroize();

    Ok((ChainKey(*ck), MessageKey(*mk)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_key_pair;

    // --- DH tests ---

    #[test]
    fn dh_produces_same_shared_secret_as_method() {
        let alice = generate_key_pair();
        let bob = generate_key_pair();
        let via_fn = dh(&alice, &bob.public);
        let via_method = alice.diffie_hellman(&bob.public);
        assert_eq!(via_fn.as_bytes(), via_method.as_bytes());
    }

    #[test]
    fn dh_is_symmetric() {
        let alice = generate_key_pair();
        let bob = generate_key_pair();
        assert_eq!(
            dh(&alice, &bob.public).as_bytes(),
            dh(&bob, &alice.public).as_bytes()
        );
    }

    // --- KDF_RK known-answer test ---

    #[test]
    fn kdf_rk_known_answer() {
        let root_key = RootKey([0u8; 32]);

        // Use a real SharedSecret from a known DH exchange
        let alice = crate::KeyPair::from_secret_bytes([0x77u8; 32]);
        let bob = crate::KeyPair::from_secret_bytes([0x88u8; 32]);
        let dh_output = dh(&alice, &bob.public);

        // Compute expected with the actual DH output independently
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), dh_output.as_bytes());
        let mut expected_okm = [0u8; 64];
        hk.expand(b"HermesRatchet_RK", &mut expected_okm).unwrap();

        let (new_rk, new_ck) = kdf_rk(&root_key, &dh_output).unwrap();
        assert_eq!(new_rk.as_bytes(), &expected_okm[..32]);
        assert_eq!(new_ck.as_bytes(), &expected_okm[32..]);
    }

    #[test]
    fn kdf_rk_deterministic() {
        let alice = crate::KeyPair::from_secret_bytes([0xAAu8; 32]);
        let bob = crate::KeyPair::from_secret_bytes([0xBBu8; 32]);
        let dh_output = dh(&alice, &bob.public);
        let root_key = RootKey([0x42u8; 32]);

        let (rk1, ck1) = kdf_rk(&root_key, &dh_output).unwrap();

        // Re-derive with same inputs
        let root_key2 = RootKey([0x42u8; 32]);
        let dh_output2 = dh(&alice, &bob.public);
        let (rk2, ck2) = kdf_rk(&root_key2, &dh_output2).unwrap();

        assert_eq!(rk1.as_bytes(), rk2.as_bytes());
        assert_eq!(ck1.as_bytes(), ck2.as_bytes());
    }

    #[test]
    fn kdf_rk_different_root_keys_produce_different_output() {
        let alice = crate::KeyPair::from_secret_bytes([0xAAu8; 32]);
        let bob = crate::KeyPair::from_secret_bytes([0xBBu8; 32]);
        let dh_output = dh(&alice, &bob.public);

        let (rk1, ck1) = kdf_rk(&RootKey([0x00u8; 32]), &dh_output).unwrap();
        let (rk2, ck2) = kdf_rk(&RootKey([0xFFu8; 32]), &dh_output).unwrap();

        assert_ne!(rk1.as_bytes(), rk2.as_bytes());
        assert_ne!(ck1.as_bytes(), ck2.as_bytes());
    }

    // --- KDF_CK known-answer test ---

    #[test]
    fn kdf_ck_known_answer() {
        let chain_key = ChainKey([0u8; 32]);

        // Compute expected values independently
        let mut mac = Hmac::<Sha256>::new_from_slice(&[0u8; 32]).unwrap();
        mac.update(&[0x01]);
        let expected_mk: [u8; 32] = mac.finalize().into_bytes().into();

        let mut mac = Hmac::<Sha256>::new_from_slice(&[0u8; 32]).unwrap();
        mac.update(&[0x02]);
        let expected_ck: [u8; 32] = mac.finalize().into_bytes().into();

        let (new_ck, mk) = kdf_ck(&chain_key).unwrap();
        assert_eq!(mk.as_bytes(), &expected_mk);
        assert_eq!(new_ck.as_bytes(), &expected_ck);
    }

    #[test]
    fn kdf_ck_known_answer_hex() {
        // HMAC-SHA256 with key = 32 zero bytes:
        //   message_key = HMAC(0x00..00, [0x01])
        //   chain_key   = HMAC(0x00..00, [0x02])
        let expected_mk = hex::decode(
            "3d7afb663124ecbf2c953f863d4fc8796eeb2d372b64aad58697ec5264649cdb",
        )
        .unwrap();
        let expected_ck = hex::decode(
            "4ee7be0c7872360ca67414608081e9bd60fd580a7bbd209701d2a5a0b4316d0d",
        )
        .unwrap();

        let chain_key = ChainKey([0u8; 32]);
        let (new_ck, mk) = kdf_ck(&chain_key).unwrap();

        assert_eq!(mk.as_bytes().as_slice(), expected_mk.as_slice());
        assert_eq!(new_ck.as_bytes().as_slice(), expected_ck.as_slice());
    }

    #[test]
    fn kdf_ck_chain_advances() {
        let ck0 = ChainKey([0x42u8; 32]);
        let (ck1, mk1) = kdf_ck(&ck0).unwrap();
        let (ck2, mk2) = kdf_ck(&ck1).unwrap();

        // Each step produces different keys
        assert_ne!(ck1.as_bytes(), ck0.as_bytes());
        assert_ne!(ck2.as_bytes(), ck1.as_bytes());
        assert_ne!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn kdf_ck_message_key_differs_from_chain_key() {
        let ck = ChainKey([0xABu8; 32]);
        let (new_ck, mk) = kdf_ck(&ck).unwrap();
        assert_ne!(new_ck.as_bytes(), mk.as_bytes());
    }
}
