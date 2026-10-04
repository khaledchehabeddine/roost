use crate::{RatchetError, SharedSecret};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const ROOT_KEY_INFO: &[u8] = b"AetherRatchet_RK";
const MESSAGE_KEY_INPUT: &[u8] = &[0x01];
const NEXT_CHAIN_KEY_INPUT: &[u8] = &[0x02];

// Root key for the Double Ratchet root chain.
// Clone stays crate-private for ratchet rollback and chain advancement snapshots.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct RootKey(pub(crate) [u8; 32]);

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
pub(crate) struct ChainKey(pub(crate) [u8; 32]);

impl ChainKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Single-use message encryption key derived from a chain key.
// Clone stays crate-private for skipped-key rollback after failed authentication.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct MessageKey(pub(crate) [u8; 32]);

impl MessageKey {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
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
pub(crate) fn derive_root_and_chain_keys(
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
pub(crate) fn derive_chain_and_message_keys(
    chain_key: &ChainKey,
) -> Result<(ChainKey, MessageKey), RatchetError> {
    let mut message_key_mac =
        Hmac::<Sha256>::new_from_slice(&chain_key.0).map_err(|_| RatchetError::InvalidHmacKey)?;
    message_key_mac.update(MESSAGE_KEY_INPUT);
    let mut message_key_output = message_key_mac.finalize().into_bytes();

    let mut chain_key_mac =
        Hmac::<Sha256>::new_from_slice(&chain_key.0).map_err(|_| RatchetError::InvalidHmacKey)?;
    chain_key_mac.update(NEXT_CHAIN_KEY_INPUT);
    let mut chain_key_output = chain_key_mac.finalize().into_bytes();

    let mut message_key = Zeroizing::new([0u8; 32]);
    let mut next_chain_key = Zeroizing::new([0u8; 32]);
    message_key.copy_from_slice(&message_key_output);
    next_chain_key.copy_from_slice(&chain_key_output);

    message_key_output.zeroize();
    chain_key_output.zeroize();

    Ok((ChainKey(*next_chain_key), MessageKey(*message_key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    /// Expected root key output for the `derive_root_and_chain_keys` KAT.
    const ROOT_AND_CHAIN_KEYS_KAT_EXPECTED_ROOT_KEY: [u8; 32] = [
        0x77, 0x32, 0x6c, 0xfc, 0x61, 0x37, 0x21, 0x8a, 0x4c, 0xd4, 0x42, 0x0a, 0xa3, 0xa7, 0x23,
        0xc0, 0x98, 0x13, 0xb5, 0xe1, 0x42, 0x3f, 0xee, 0x01, 0xed, 0x4e, 0x2c, 0x1e, 0x18, 0xf8,
        0xfd, 0xd2,
    ];

    /// Expected chain key output for the `derive_root_and_chain_keys` KAT.
    const ROOT_AND_CHAIN_KEYS_KAT_EXPECTED_CHAIN_KEY: [u8; 32] = [
        0x36, 0xf3, 0xf2, 0x4a, 0x90, 0x50, 0x4a, 0x7c, 0x46, 0xfc, 0xfc, 0x6d, 0x69, 0xf8, 0x86,
        0x5e, 0xb1, 0xbd, 0xd3, 0xb2, 0xb9, 0xd4, 0x59, 0xf6, 0x96, 0x03, 0x35, 0x93, 0x80, 0xf4,
        0x48, 0xfa,
    ];

    /// Expected chain key output for the initial `derive_chain_and_message_keys` KAT.
    const CHAIN_AND_MESSAGE_KEYS_KAT_EXPECTED_CHAIN_KEY_INIT: [u8; 32] = [
        0x4e, 0xe7, 0xbe, 0x0c, 0x78, 0x72, 0x36, 0x0c, 0xa6, 0x74, 0x14, 0x60, 0x80, 0x81, 0xe9,
        0xbd, 0x60, 0xfd, 0x58, 0x0a, 0x7b, 0xbd, 0x20, 0x97, 0x01, 0xd2, 0xa5, 0xa0, 0xb4, 0x31,
        0x6d, 0x0d,
    ];

    /// Expected message key output for the initial `derive_chain_and_message_keys` KAT.
    const CHAIN_AND_MESSAGE_KEYS_KAT_EXPECTED_MESSAGE_KEY_INIT: [u8; 32] = [
        0x3d, 0x7a, 0xfb, 0x66, 0x31, 0x24, 0xec, 0xbf, 0x2c, 0x95, 0x3f, 0x86, 0x3d, 0x4f, 0xc8,
        0x79, 0x6e, 0xeb, 0x2d, 0x37, 0x2b, 0x64, 0xaa, 0xd5, 0x86, 0x97, 0xec, 0x52, 0x64, 0x64,
        0x9c, 0xdb,
    ];

    /// Expected chain steps for the `derive_chain_and_message_keys` chain-advancement KAT.
    const CHAIN_AND_MESSAGE_KEYS_KAT_EXPECTED_CHAIN_STEPS: [([u8; 32], [u8; 32]); 3] = [
        (
            CHAIN_AND_MESSAGE_KEYS_KAT_EXPECTED_CHAIN_KEY_INIT,
            CHAIN_AND_MESSAGE_KEYS_KAT_EXPECTED_MESSAGE_KEY_INIT,
        ),
        (
            [
                0x4d, 0x86, 0x45, 0x4c, 0x5e, 0xfc, 0xc9, 0xba, 0x57, 0xd8, 0x0a, 0xea, 0xe3, 0xcb,
                0x31, 0x18, 0x62, 0xe5, 0x1d, 0xad, 0x69, 0x19, 0xaf, 0xf0, 0xfb, 0x35, 0xf4, 0xbd,
                0xaf, 0xe5, 0x7d, 0x53,
            ],
            [
                0xe4, 0x3c, 0xd1, 0xfa, 0xe5, 0x5c, 0xf9, 0x44, 0x82, 0x83, 0x36, 0xe2, 0x77, 0x73,
                0x8f, 0x68, 0x4c, 0x1e, 0x22, 0x17, 0x77, 0xe6, 0xea, 0x5f, 0x03, 0x66, 0x42, 0xc1,
                0x00, 0x53, 0xf1, 0x58,
            ],
        ),
        (
            [
                0x87, 0x72, 0x99, 0x96, 0x3d, 0x64, 0x63, 0xdd, 0x22, 0xb7, 0x14, 0xf7, 0x13, 0x6a,
                0xce, 0x2e, 0x7a, 0x00, 0x9d, 0x7c, 0x28, 0x49, 0x46, 0xa6, 0x2b, 0xdc, 0x0b, 0x5e,
                0x75, 0x40, 0x39, 0x77,
            ],
            [
                0x77, 0x18, 0x29, 0x5d, 0x45, 0xe4, 0x16, 0x4b, 0x6a, 0x1e, 0x75, 0xb3, 0xa1, 0xd8,
                0x8c, 0x56, 0x84, 0xfb, 0x02, 0x89, 0xc9, 0x77, 0xbc, 0x10, 0xe8, 0xab, 0xeb, 0x74,
                0xea, 0xd7, 0x60, 0x1b,
            ],
        ),
    ];

    fn fixed_key_pairs() -> (KeyPair, KeyPair) {
        (
            KeyPair::from_secret_bytes([0x77u8; 32]),
            KeyPair::from_secret_bytes([0x88u8; 32]),
        )
    }

    /// Known-answer test for [`derive_root_and_chain_keys`].
    ///
    /// Source: pyca/cryptography 46 `HKDF.derive` and `X25519PrivateKey.exchange`
    ///
    /// Inputs:
    /// - `root_key = RootKey([0; 32])`
    /// - `alice_secret = [0x77; 32]`
    /// - `bob_secret = [0x88; 32]`
    ///
    /// Derivation:
    /// ```text
    /// dh_output = X25519(alice_secret, public_key(bob_secret))
    /// output_keying_material = HKDF-SHA256(salt = root_key, input_keying_material = dh_output, info = ROOT_KEY_INFO, L = 64)
    /// ```
    ///
    /// Output:
    /// - `output_keying_material[0..32] = ROOT_AND_CHAIN_KEYS_KAT_EXPECTED_ROOT_KEY`
    /// - `output_keying_material[32..64] = ROOT_AND_CHAIN_KEYS_KAT_EXPECTED_CHAIN_KEY`
    #[test]
    fn derive_root_and_chain_keys_known_answer() {
        let (alice, bob) = fixed_key_pairs();
        let dh_output = alice.diffie_hellman(&bob.public);
        let (next_root_key, next_chain_key) =
            derive_root_and_chain_keys(&RootKey([0u8; 32]), &dh_output).unwrap();
        assert_eq!(
            next_root_key.as_bytes(),
            &ROOT_AND_CHAIN_KEYS_KAT_EXPECTED_ROOT_KEY
        );
        assert_eq!(
            next_chain_key.as_bytes(),
            &ROOT_AND_CHAIN_KEYS_KAT_EXPECTED_CHAIN_KEY
        );
    }

    /// Known-answer test for [`derive_chain_and_message_keys`].
    ///
    /// Source: Python 3.13 standard library `hmac.digest(key, msg, "sha256")`
    ///
    /// Inputs:
    /// - `chain_key = ChainKey([0; 32])`
    ///
    /// Derivation:
    /// ```text
    /// message_key = HMAC-SHA256(key = chain_key, data = MESSAGE_KEY_INPUT)
    /// next_chain_key = HMAC-SHA256(key = chain_key, data = NEXT_CHAIN_KEY_INPUT)
    /// ```
    ///
    /// Output:
    /// - `message_key = CHAIN_AND_MESSAGE_KEYS_KAT_EXPECTED_MESSAGE_KEY_INIT`
    /// - `next_chain_key = CHAIN_AND_MESSAGE_KEYS_KAT_EXPECTED_CHAIN_KEY_INIT`
    #[test]
    fn derive_chain_and_message_keys_known_answer() {
        let (next_chain_key, message_key) =
            derive_chain_and_message_keys(&ChainKey([0u8; 32])).unwrap();
        assert_eq!(
            message_key.as_bytes(),
            &CHAIN_AND_MESSAGE_KEYS_KAT_EXPECTED_MESSAGE_KEY_INIT
        );
        assert_eq!(
            next_chain_key.as_bytes(),
            &CHAIN_AND_MESSAGE_KEYS_KAT_EXPECTED_CHAIN_KEY_INIT
        );
    }

    /// Known-answer test for three `derive_chain_and_message_keys` chain-advancement steps.
    ///
    /// Source: Python 3.13 standard library `hmac.digest(key, msg, "sha256")`
    ///
    /// Inputs:
    /// - `ck_0 = ChainKey([0; 32])`
    ///
    /// Derivation:
    /// ```text
    /// for each step i:
    ///   mk_i = HMAC-SHA256(key = ck_i, data = MESSAGE_KEY_INPUT)
    ///   ck_{i+1} = HMAC-SHA256(key = ck_i, data = NEXT_CHAIN_KEY_INPUT)
    /// ```
    ///
    /// Output: `CHAIN_AND_MESSAGE_KEYS_KAT_EXPECTED_CHAIN_STEPS`
    #[test]
    fn derive_chain_and_message_keys_chain_advancement_known_answer() {
        let mut chain_key = ChainKey([0u8; 32]);
        for (i, (expected_chain_key, expected_message_key)) in
            CHAIN_AND_MESSAGE_KEYS_KAT_EXPECTED_CHAIN_STEPS
                .iter()
                .enumerate()
        {
            let (next_chain_key, message_key) = derive_chain_and_message_keys(&chain_key).unwrap();
            assert_eq!(
                next_chain_key.as_bytes(),
                expected_chain_key,
                "step {i}: chain key mismatch"
            );
            assert_eq!(
                message_key.as_bytes(),
                expected_message_key,
                "step {i}: message key mismatch"
            );
            chain_key = next_chain_key;
        }
    }
}
