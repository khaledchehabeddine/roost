use super::state::RatchetError;
use hkdf::Hkdf;
use hmac::digest::FixedOutput;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::SharedSecret;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const ROOT_KEY_INFO: &[u8] = b"RoostRatchet_RK";
const MESSAGE_KEY_INPUT: &[u8] = &[0x01];
const NEXT_CHAIN_KEY_INPUT: &[u8] = &[0x02];

// Root key for the Double Ratchet root chain.
// Clone stays crate-private for ratchet rollback and chain advancement snapshots.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct RootKey([u8; 32]);

impl RootKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Chain key for the Double Ratchet sending/receiving chain.
// Clone stays crate-private for ratchet rollback and chain advancement snapshots.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(super) struct ChainKey([u8; 32]);

impl ChainKey {
    pub(super) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Single-use message encryption key derived from a chain key.
// Clone stays crate-private for skipped-key rollback after failed authentication.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(super) struct MessageKey([u8; 32]);

impl MessageKey {
    pub(super) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Implements `KDF_RK` from the Double Ratchet specification
// (https://signal.org/docs/specifications/doubleratchet/): derives the next root key and a chain
// key from a root key and DH output.
//
// Uses HKDF-SHA256 with the root key as salt, DH output as input keying material, and
// ROOT_KEY_INFO as the info string. Produces 64 bytes of output, split into a 32-byte root key and
// a 32-byte chain key.
pub(super) fn derive_root_and_chain_keys(
    root_key: &RootKey,
    dh_output: &SharedSecret,
) -> Result<(RootKey, ChainKey), RatchetError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&root_key.0), dh_output.as_bytes());
    let mut output_keying_material = Zeroizing::new([0u8; 64]);
    hkdf.expand(ROOT_KEY_INFO, output_keying_material.as_mut())
        .map_err(|_| RatchetError::HkdfExpand)?;

    let mut next_root_key = Zeroizing::new([0u8; 32]);
    let mut chain_key = Zeroizing::new([0u8; 32]);
    next_root_key.copy_from_slice(&output_keying_material[..32]);
    chain_key.copy_from_slice(&output_keying_material[32..]);

    Ok((RootKey(*next_root_key), ChainKey(*chain_key)))
}

// Implements `KDF_CK` from the Double Ratchet specification: derives the next chain key and a
// message key from a chain key.
//
// Uses HMAC-SHA256 with the chain key as the HMAC key.
pub(super) fn derive_chain_and_message_keys(
    chain_key: &ChainKey,
) -> Result<(ChainKey, MessageKey), RatchetError> {
    let mut message_key_mac =
        Hmac::<Sha256>::new_from_slice(&chain_key.0).map_err(|_| RatchetError::InvalidHmacKey)?;
    message_key_mac.update(MESSAGE_KEY_INPUT);
    let mut message_key = Zeroizing::new([0u8; 32]);
    message_key_mac.finalize_into((&mut *message_key).into());

    let mut chain_key_mac =
        Hmac::<Sha256>::new_from_slice(&chain_key.0).map_err(|_| RatchetError::InvalidHmacKey)?;
    chain_key_mac.update(NEXT_CHAIN_KEY_INPUT);
    let mut next_chain_key = Zeroizing::new([0u8; 32]);
    chain_key_mac.finalize_into((&mut *next_chain_key).into());

    Ok((ChainKey(*next_chain_key), MessageKey(*message_key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_key_pair;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn dh_output(seed: u8) -> SharedSecret {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let local = generate_key_pair(&mut rng).unwrap();
        let remote = generate_key_pair(&mut rng).unwrap();
        local.diffie_hellman(&remote.public).unwrap()
    }

    #[test]
    fn root_and_chain_keys_change_with_each_input() {
        let (root_key, chain_key) =
            derive_root_and_chain_keys(&RootKey([1; 32]), &dh_output(1)).unwrap();

        for (other_root_key, other_chain_key) in [
            derive_root_and_chain_keys(&RootKey([2; 32]), &dh_output(1)).unwrap(),
            derive_root_and_chain_keys(&RootKey([1; 32]), &dh_output(2)).unwrap(),
        ] {
            assert_ne!(other_root_key.as_bytes(), root_key.as_bytes());
            assert_ne!(other_chain_key.as_bytes(), chain_key.as_bytes());
        }
        assert_ne!(root_key.as_bytes(), chain_key.as_bytes());
    }

    #[test]
    fn chain_and_message_keys_change_with_the_chain_key() {
        let (next_chain_key, message_key) =
            derive_chain_and_message_keys(&ChainKey([1; 32])).unwrap();
        let (other_next_chain_key, other_message_key) =
            derive_chain_and_message_keys(&ChainKey([2; 32])).unwrap();

        assert_ne!(other_next_chain_key.as_bytes(), next_chain_key.as_bytes());
        assert_ne!(other_message_key.as_bytes(), message_key.as_bytes());
        assert_ne!(next_chain_key.as_bytes(), message_key.as_bytes());
    }
}
