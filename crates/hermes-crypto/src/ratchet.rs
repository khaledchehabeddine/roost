use crate::{CryptoError, SharedSecret};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const RK_INFO: &[u8] = b"HermesRatchet_RK";
const CK_MESSAGE_KEY_INPUT: &[u8] = &[0x01];
const CK_CHAIN_KEY_INPUT: &[u8] = &[0x02];

/// Root key for the Double Ratchet root chain.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey(pub(crate) [u8; 32]);

/// Chain key for the Double Ratchet sending/receiving chain.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey(pub(crate) [u8; 32]);

/// Single-use message encryption key derived from a chain key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey(pub(crate) [u8; 32]);

impl RootKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ChainKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl MessageKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Root-chain KDF: derives a new root key and chain key from a root key and DH output.
///
/// Uses HKDF-SHA256 with the root key as salt, DH output as input keying material, and [`RK_INFO`]
/// as the info string. Produces 64 bytes of output, split into a 32-byte root key and a 32-byte
/// chain key.
pub fn kdf_rk(
    root_key: &RootKey,
    dh_output: &SharedSecret,
) -> Result<(RootKey, ChainKey), CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&root_key.0), dh_output.as_bytes());
    let mut okm = Zeroizing::new([0u8; 64]);
    hkdf.expand(RK_INFO, okm.as_mut())
        .map_err(|_| CryptoError::HkdfExpand)?;

    let mut rk = Zeroizing::new([0u8; 32]);
    let mut ck = Zeroizing::new([0u8; 32]);
    rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);

    Ok((RootKey(*rk), ChainKey(*ck)))
}

/// Symmetric-chain KDF: derives the next chain key and a message key from a chain key.
///
/// Uses HMAC-SHA256 with the chain key as the HMAC key:
/// - Message key = HMAC(chain_key, [`CK_MESSAGE_KEY_INPUT`])
/// - Next chain key = HMAC(chain_key, [`CK_CHAIN_KEY_INPUT`])
pub fn kdf_ck(chain_key: &ChainKey) -> Result<(ChainKey, MessageKey), CryptoError> {
    let mut mac_mk =
        Hmac::<Sha256>::new_from_slice(&chain_key.0).map_err(|_| CryptoError::InvalidHmacKey)?;
    mac_mk.update(CK_MESSAGE_KEY_INPUT);
    let mut mk_result = mac_mk.finalize().into_bytes();

    let mut mac_ck =
        Hmac::<Sha256>::new_from_slice(&chain_key.0).map_err(|_| CryptoError::InvalidHmacKey)?;
    mac_ck.update(CK_CHAIN_KEY_INPUT);
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

    #[test]
    fn kdf_rk_known_answer_hex() {
        let alice = crate::KeyPair::from_secret_bytes([0x77u8; 32]);
        let bob = crate::KeyPair::from_secret_bytes([0x88u8; 32]);
        let dh_output = alice.diffie_hellman(&bob.public);

        let expected_rk =
            hex::decode("efc95c2639954681b1c881ab6159eecb12affd1e504e9cf1ef3a44c9b102f717")
                .unwrap();
        let expected_ck =
            hex::decode("f008650ba6b74d24da7f648a0b2bbe6c0019604ea3308990c0cad7271ae41f7b")
                .unwrap();

        let (new_rk, new_ck) = kdf_rk(&RootKey([0u8; 32]), &dh_output).unwrap();

        assert_eq!(new_rk.as_bytes().as_slice(), expected_rk.as_slice());
        assert_eq!(new_ck.as_bytes().as_slice(), expected_ck.as_slice());
    }

    #[test]
    fn kdf_rk_deterministic() {
        let alice = crate::KeyPair::from_secret_bytes([0xAAu8; 32]);
        let bob = crate::KeyPair::from_secret_bytes([0xBBu8; 32]);
        let dh_output = alice.diffie_hellman(&bob.public);

        let root_key = RootKey([0x42u8; 32]);
        let (rk1, ck1) = kdf_rk(&root_key, &dh_output).unwrap();
        let (rk2, ck2) = kdf_rk(&root_key, &dh_output).unwrap();

        assert_eq!(rk1.as_bytes(), rk2.as_bytes());
        assert_eq!(ck1.as_bytes(), ck2.as_bytes());
    }

    #[test]
    fn kdf_rk_different_root_keys_produce_different_output() {
        let alice = crate::KeyPair::from_secret_bytes([0xAAu8; 32]);
        let bob = crate::KeyPair::from_secret_bytes([0xBBu8; 32]);
        let dh_output = alice.diffie_hellman(&bob.public);

        let (rk1, ck1) = kdf_rk(&RootKey([0x00u8; 32]), &dh_output).unwrap();
        let (rk2, ck2) = kdf_rk(&RootKey([0xFFu8; 32]), &dh_output).unwrap();

        assert_ne!(rk1.as_bytes(), rk2.as_bytes());
        assert_ne!(ck1.as_bytes(), ck2.as_bytes());
    }

    #[test]
    fn kdf_ck_known_answer_hex() {
        let expected_mk =
            hex::decode("3d7afb663124ecbf2c953f863d4fc8796eeb2d372b64aad58697ec5264649cdb")
                .unwrap();
        let expected_ck =
            hex::decode("4ee7be0c7872360ca67414608081e9bd60fd580a7bbd209701d2a5a0b4316d0d")
                .unwrap();

        let (new_ck, mk) = kdf_ck(&ChainKey([0u8; 32])).unwrap();

        assert_eq!(mk.as_bytes().as_slice(), expected_mk.as_slice());
        assert_eq!(new_ck.as_bytes().as_slice(), expected_ck.as_slice());
    }

    #[test]
    fn kdf_ck_chain_advances() {
        let ck0 = ChainKey([0x42u8; 32]);
        let (ck1, mk1) = kdf_ck(&ck0).unwrap();
        let (ck2, mk2) = kdf_ck(&ck1).unwrap();

        assert_ne!(ck1.as_bytes(), ck0.as_bytes());
        assert_ne!(ck2.as_bytes(), ck1.as_bytes());
        assert_ne!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn kdf_ck_message_key_differs_from_chain_key() {
        let (ck, mk) = kdf_ck(&ChainKey([0xABu8; 32])).unwrap();
        assert_ne!(ck.as_bytes(), mk.as_bytes());
    }
}
