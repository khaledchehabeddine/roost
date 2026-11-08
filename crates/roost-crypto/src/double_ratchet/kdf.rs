use super::state::RatchetError;
use hkdf::Hkdf;
use hmac::digest::FixedOutput;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::SharedSecret;
use zeroize::{ZeroizeOnDrop, Zeroizing};

const ROOT_KEY_INFO: &[u8] = b"RoostRatchetRootKey-v1:";
const MESSAGE_KEY_INPUT: &[u8] = &[0x01];
const NEXT_CHAIN_KEY_INPUT: &[u8] = &[0x02];

// `RatchetState::snapshot` clones it to decrypt on a copy of the state.
#[derive(Clone, ZeroizeOnDrop)]
pub(crate) struct RootKey([u8; 32]);

impl RootKey {
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// `RatchetState` clones it to decrypt on a copy of the state and to derive skipped keys.
#[derive(Clone, ZeroizeOnDrop)]
pub(super) struct ChainKey([u8; 32]);

impl ChainKey {
    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Single-use message encryption key derived from a chain key.
// `RatchetState::snapshot` clones the skipped message keys to decrypt on a copy of the state.
#[derive(Clone, ZeroizeOnDrop)]
pub(super) struct MessageKey([u8; 32]);

impl MessageKey {
    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Implements `KDF_RK` from the Double Ratchet specification
// (https://signal.org/docs/specifications/doubleratchet/).
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

// Implements `KDF_CK` from the Double Ratchet specification.
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
        let local = generate_key_pair(&mut rng);
        let remote = generate_key_pair(&mut rng);
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
