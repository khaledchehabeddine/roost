//! Fixed signed prekey bytes across Crypto's signing and verification boundary.

use roost_crypto::{SignedPreKey, SigningKeyPair, verify_signed_prekey_bundle};

#[test]
fn signed_prekey_known_answer() {
    // Source: the original project-derived signed_prekeys_v1 fixture.
    // Inputs: test-only signing seed 0x51, prekey seed 0x52, epoch 7, timestamp 1700000000.
    // Derivation: Ed25519 over AetherSPK-v1:, the public key, epoch, and creation time.
    // Output: fixed signed bytes and signature below, retained independently of this run.
    let signing_key = SigningKeyPair::from_signing_bytes([0x51; 32]);
    let signed_bytes = hex::decode("41657468657253504b2d76313af68b05ba03f7185e1ba88878682f8dd0b15158f6050889c9481d79c2d7d2fa0700000007000000006553f100").unwrap();
    let signature: [u8; 64] = hex::decode("3d357f15e22e999c7cdd1ed27e2f3c52b6479ccf23f9681d0de1d27bb05fc4f1accbf3a4addf077d25c8e773ab99a52731745a5d70144e86519d71d79f183701").unwrap().try_into().unwrap();
    let prekey = SignedPreKey::from_secret_bytes([0x52; 32], signature, 0, 7, 1_700_000_000);
    let mut encoded = b"AetherSPK-v1:".to_vec();
    encoded.extend_from_slice(prekey.public().as_bytes());
    encoded.extend_from_slice(&7u32.to_be_bytes());
    encoded.extend_from_slice(&1_700_000_000u64.to_be_bytes());
    assert_eq!(encoded, signed_bytes);
    assert_eq!(signing_key.sign(&signed_bytes).to_bytes(), signature);
    verify_signed_prekey_bundle(&prekey.bundle(), &signing_key.verifying).unwrap();
}
