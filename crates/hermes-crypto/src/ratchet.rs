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
pub(crate) struct RootKey(pub(crate) [u8; 32]);

/// Chain key for the Double Ratchet sending/receiving chain.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ChainKey(pub(crate) [u8; 32]);

/// Single-use message encryption key derived from a chain key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct MessageKey(pub(crate) [u8; 32]);

impl RootKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ChainKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl MessageKey {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Root-chain KDF: derives a new root key and chain key from a root key and DH output.
///
/// Uses HKDF-SHA256 with the root key as salt, DH output as input keying material, and [`RK_INFO`]
/// as the info string. Produces 64 bytes of output, split into a 32-byte root key and a 32-byte
/// chain key.
pub(crate) fn kdf_rk(
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
pub(crate) fn kdf_ck(chain_key: &ChainKey) -> Result<(ChainKey, MessageKey), CryptoError> {
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
    use crate::KeyPair;

    /// The message key `mk_0` and next chain key `ck_1` produced by `kdf_ck([0u8; 32])`.
    ///
    /// Referenced by both [`kdf_ck_known_answer`] and step 0 of
    /// [`kdf_ck_chain_advancement_known_answer`], so the two tests cannot drift silently if one is
    /// regenerated without the other.
    const KDF_CK_INIT_EXPECTED_MK: [u8; 32] = [
        0x3d, 0x7a, 0xfb, 0x66, 0x31, 0x24, 0xec, 0xbf, 0x2c, 0x95, 0x3f, 0x86, 0x3d, 0x4f, 0xc8,
        0x79, 0x6e, 0xeb, 0x2d, 0x37, 0x2b, 0x64, 0xaa, 0xd5, 0x86, 0x97, 0xec, 0x52, 0x64, 0x64,
        0x9c, 0xdb,
    ];
    const KDF_CK_INIT_EXPECTED_CK: [u8; 32] = [
        0x4e, 0xe7, 0xbe, 0x0c, 0x78, 0x72, 0x36, 0x0c, 0xa6, 0x74, 0x14, 0x60, 0x80, 0x81, 0xe9,
        0xbd, 0x60, 0xfd, 0x58, 0x0a, 0x7b, 0xbd, 0x20, 0x97, 0x01, 0xd2, 0xa5, 0xa0, 0xb4, 0x31,
        0x6d, 0x0d,
    ];

    /// Alice [0x77; 32] and Bob [0x88; 32] — fixed keypair pair used by the kdf_rk KAT and its
    /// determinism check.
    fn fixed_keypairs() -> (KeyPair, KeyPair) {
        (
            KeyPair::from_secret_bytes([0x77u8; 32]),
            KeyPair::from_secret_bytes([0x88u8; 32]),
        )
    }

    /// Known-answer test for [`kdf_rk`].
    ///
    /// Inputs: `root_key = [0; 32]`, `alice_secret = [0x77; 32]`, `bob_secret = [0x88; 32]`,
    /// `dh_output = X25519(alice_secret, clamped_public_of(bob_secret))`.
    ///
    /// Algorithm: HKDF-SHA256(salt = root_key, ikm = dh_output, info = [`RK_INFO`], L = 64).
    /// Output split: `okm[0..32] = new_rk`, `okm[32..64] = new_ck`.
    ///
    /// Expected values derived with pyca/cryptography 46 (HKDF, X25519).
    #[test]
    fn kdf_rk_known_answer() {
        const EXPECTED_RK: [u8; 32] = [
            0xef, 0xc9, 0x5c, 0x26, 0x39, 0x95, 0x46, 0x81, 0xb1, 0xc8, 0x81, 0xab, 0x61, 0x59,
            0xee, 0xcb, 0x12, 0xaf, 0xfd, 0x1e, 0x50, 0x4e, 0x9c, 0xf1, 0xef, 0x3a, 0x44, 0xc9,
            0xb1, 0x02, 0xf7, 0x17,
        ];
        const EXPECTED_CK: [u8; 32] = [
            0xf0, 0x08, 0x65, 0x0b, 0xa6, 0xb7, 0x4d, 0x24, 0xda, 0x7f, 0x64, 0x8a, 0x0b, 0x2b,
            0xbe, 0x6c, 0x00, 0x19, 0x60, 0x4e, 0xa3, 0x30, 0x89, 0x90, 0xc0, 0xca, 0xd7, 0x27,
            0x1a, 0xe4, 0x1f, 0x7b,
        ];

        let (alice, bob) = fixed_keypairs();
        let dh_output = alice.diffie_hellman(&bob.public);

        let (new_rk, new_ck) = kdf_rk(&RootKey([0u8; 32]), &dh_output).unwrap();

        assert_eq!(new_rk.as_bytes(), &EXPECTED_RK);
        assert_eq!(new_ck.as_bytes(), &EXPECTED_CK);
    }

    #[test]
    fn kdf_rk_deterministic() {
        let (alice, bob) = fixed_keypairs();
        let dh_output = alice.diffie_hellman(&bob.public);

        let root_key = RootKey([0x42u8; 32]);
        let (rk1, ck1) = kdf_rk(&root_key, &dh_output).unwrap();
        let (rk2, ck2) = kdf_rk(&root_key, &dh_output).unwrap();

        assert_eq!(rk1.as_bytes(), rk2.as_bytes());
        assert_eq!(ck1.as_bytes(), ck2.as_bytes());
    }

    /// Known-answer test for [`kdf_ck`].
    ///
    /// Inputs: `chain_key = [0; 32]`.
    ///
    /// Algorithm:
    /// - Message key = HMAC-SHA256(key = chain_key, data = [`CK_MESSAGE_KEY_INPUT`]);
    /// - Next chain key = HMAC-SHA256(key = chain_key, data = [`CK_CHAIN_KEY_INPUT`]).
    ///
    /// Expected values derived with Python's `hmac` module against SHA-256.
    #[test]
    fn kdf_ck_known_answer() {
        let (new_ck, mk) = kdf_ck(&ChainKey([0u8; 32])).unwrap();

        assert_eq!(mk.as_bytes(), &KDF_CK_INIT_EXPECTED_MK);
        assert_eq!(new_ck.as_bytes(), &KDF_CK_INIT_EXPECTED_CK);
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

    /// Chain-advancement known-answer test: 3 successive [`kdf_ck`] applications from a known
    /// starting chain key.
    ///
    /// Inputs: `ck_0 = [0; 32]`.
    ///
    /// Algorithm at each step `i`: `(ck_{i+1}, mk_i) = kdf_ck(ck_i)`. See [`kdf_ck_known_answer`]
    /// for the single-step HMAC derivation. Step 0's `(ck_1, mk_0)` is identical to
    /// [`kdf_ck_known_answer`]'s output, providing an internal consistency check across the two
    /// tests.
    ///
    /// Expected values derived from Python's `hmac` module.
    #[test]
    fn kdf_ck_chain_advancement_known_answer() {
        // Each entry is `(expected_ck_{i+1}, expected_mk_i)`.
        const EXPECTED: [([u8; 32], [u8; 32]); 3] = [
            (KDF_CK_INIT_EXPECTED_CK, KDF_CK_INIT_EXPECTED_MK),
            (
                [
                    0x4d, 0x86, 0x45, 0x4c, 0x5e, 0xfc, 0xc9, 0xba, 0x57, 0xd8, 0x0a, 0xea, 0xe3,
                    0xcb, 0x31, 0x18, 0x62, 0xe5, 0x1d, 0xad, 0x69, 0x19, 0xaf, 0xf0, 0xfb, 0x35,
                    0xf4, 0xbd, 0xaf, 0xe5, 0x7d, 0x53,
                ],
                [
                    0xe4, 0x3c, 0xd1, 0xfa, 0xe5, 0x5c, 0xf9, 0x44, 0x82, 0x83, 0x36, 0xe2, 0x77,
                    0x73, 0x8f, 0x68, 0x4c, 0x1e, 0x22, 0x17, 0x77, 0xe6, 0xea, 0x5f, 0x03, 0x66,
                    0x42, 0xc1, 0x00, 0x53, 0xf1, 0x58,
                ],
            ),
            (
                [
                    0x87, 0x72, 0x99, 0x96, 0x3d, 0x64, 0x63, 0xdd, 0x22, 0xb7, 0x14, 0xf7, 0x13,
                    0x6a, 0xce, 0x2e, 0x7a, 0x00, 0x9d, 0x7c, 0x28, 0x49, 0x46, 0xa6, 0x2b, 0xdc,
                    0x0b, 0x5e, 0x75, 0x40, 0x39, 0x77,
                ],
                [
                    0x77, 0x18, 0x29, 0x5d, 0x45, 0xe4, 0x16, 0x4b, 0x6a, 0x1e, 0x75, 0xb3, 0xa1,
                    0xd8, 0x8c, 0x56, 0x84, 0xfb, 0x02, 0x89, 0xc9, 0x77, 0xbc, 0x10, 0xe8, 0xab,
                    0xeb, 0x74, 0xea, 0xd7, 0x60, 0x1b,
                ],
            ),
        ];

        let mut ck = ChainKey([0u8; 32]);
        for (i, (expected_ck, expected_mk)) in EXPECTED.iter().enumerate() {
            let (next_ck, mk) = kdf_ck(&ck).unwrap();
            assert_eq!(next_ck.as_bytes(), expected_ck, "step {i}: ck mismatch");
            assert_eq!(mk.as_bytes(), expected_mk, "step {i}: mk mismatch");
            ck = next_ck;
        }
    }
}
