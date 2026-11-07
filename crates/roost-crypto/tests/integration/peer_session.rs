//! Session-level integration tests for peers bootstrapped through the X3DH handshake.
//!
//! These scenarios cross the handshake, signed prekey, and Double Ratchet modules through the
//! public API the way a downstream crate would.

use crate::support::{ASSOCIATED_DATA, bootstrap, setup};
use roost_crypto::{
    HandshakeError, Header, OneTimePreKey, PreKeyBundle, PublicKeyError, RatchetError, Signature,
    initiate_handshake,
};
use roost_protocol::SignatureError;

#[test]
fn tampered_signed_prekey_signature_rejects_before_any_key_work() {
    let (setup, mut rng) = setup([0x33; 32]);
    let mut bundle = setup.bob_signed_prekey.public();
    let mut signature_bytes = bundle.signature.to_bytes();
    signature_bytes[0] ^= 0x01;
    bundle.signature = Signature::from_bytes(&signature_bytes);
    let prekey_bundle = PreKeyBundle {
        version: roost_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: setup.bob_discovery_key.public(),
        signed_prekey: bundle,
        one_time_prekey: setup
            .bob_one_time_prekey
            .as_ref()
            .map(OneTimePreKey::public),
    };
    let result = initiate_handshake(&mut rng, &setup.bob_identity_key, &prekey_bundle);
    assert!(matches!(
        result,
        Err(HandshakeError::PublicKey(PublicKeyError::Signature(
            SignatureError::SignatureInvalid
        )))
    ));
}

#[test]
fn tampered_header_rolls_back_state() {
    let (mut setup, mut rng) = setup([0x33; 32]);
    let (mut alice, mut bob) = bootstrap(&mut setup, &mut rng, true, b"msg-0");
    let associated_data = ASSOCIATED_DATA;

    let (header, ciphertext) = alice.ratchet_encrypt(b"legit", associated_data).unwrap();
    let before = bob.to_bytes().unwrap();
    let tampered = Header {
        public_key: header.public_key,
        previous_chain_length: header.previous_chain_length,
        message_number: header.message_number + 10,
    };
    assert!(matches!(
        bob.ratchet_decrypt(&mut rng, &ciphertext, &tampered, associated_data),
        Err(RatchetError::Aead)
    ));
    assert_eq!(*bob.to_bytes().unwrap(), *before);

    let decrypted = bob
        .ratchet_decrypt(&mut rng, &ciphertext, &header, associated_data)
        .unwrap();
    assert_eq!(decrypted.as_slice(), b"legit");
}
