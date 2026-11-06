//! Bob's published keys, and the sessions Alice starts from them through the X3DH handshake.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_crypto::{
    DiscoveryKey, OneTimePreKey, PreKeyBundle, PublicIdentityKey, RatchetState, SignedPreKey,
    SigningKeyPair, accept_handshake, generate_discovery_key, generate_key_pair,
    generate_one_time_prekey, generate_signed_prekey_for_discovery_key, generate_signing_key_pair,
    initiate_handshake, sign_identity_key_binding,
};

pub(crate) const CREATED_AT_SECS: u64 = 1_700_000_000;
pub(crate) const ASSOCIATED_DATA: &[u8] = b"associated data";

pub(crate) struct Setup {
    pub(crate) bob_identity_key: PublicIdentityKey,
    pub(crate) bob_discovery_key: DiscoveryKey,
    pub(crate) bob_signed_prekey: SignedPreKey,
    pub(crate) bob_one_time_prekey: Option<OneTimePreKey>,
}

/// Returns Bob's keys drawn from `seed`, and the generator to draw the rest from.
pub(crate) fn setup(seed: [u8; 32]) -> (Setup, ChaCha20Rng) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let bob_identity = generate_signing_key_pair(&mut rng);
    let bob_identity_key = public_identity_key(&mut rng, &bob_identity);
    let bob_discovery_key =
        generate_discovery_key(&mut rng, &bob_identity, 2, CREATED_AT_SECS).unwrap();
    let bob_signed_prekey =
        generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery_key, 0, CREATED_AT_SECS)
            .unwrap();
    let bob_one_time_prekey =
        generate_one_time_prekey(&mut rng, 7, bob_discovery_key.epoch(), CREATED_AT_SECS);
    (
        Setup {
            bob_identity_key,
            bob_discovery_key,
            bob_signed_prekey,
            bob_one_time_prekey: Some(bob_one_time_prekey),
        },
        rng,
    )
}

/// Starts a session from Alice to Bob, and has Bob decrypt Alice's first message on it.
pub(crate) fn bootstrap(
    setup: &mut Setup,
    rng: &mut ChaCha20Rng,
    include_one_time_prekey: bool,
    plaintext: &[u8],
) -> (RatchetState, RatchetState) {
    let one_time_prekey_bundle =
        include_one_time_prekey.then(|| setup.bob_one_time_prekey.as_ref().unwrap().public());
    let prekey_bundle = PreKeyBundle {
        version: roost_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: setup.bob_discovery_key.public(),
        signed_prekey: setup.bob_signed_prekey.public(),
        one_time_prekey: one_time_prekey_bundle,
    };
    let (mut alice, alice_session_id, handshake) =
        initiate_handshake(rng, &setup.bob_identity_key, &prekey_bundle).unwrap();
    let bob_one_time_prekey =
        include_one_time_prekey.then(|| setup.bob_one_time_prekey.take().unwrap());
    let (mut bob, bob_session_id) = accept_handshake(
        &handshake,
        &setup.bob_discovery_key,
        &setup.bob_signed_prekey,
        bob_one_time_prekey,
    )
    .unwrap();
    assert_eq!(bob_session_id, alice_session_id);
    let (header, ciphertext) = alice.ratchet_encrypt(plaintext, ASSOCIATED_DATA).unwrap();
    let decrypted = bob
        .ratchet_decrypt(rng, &ciphertext, &header, ASSOCIATED_DATA)
        .unwrap();
    assert_eq!(decrypted.as_slice(), plaintext);
    (alice, bob)
}

fn public_identity_key(rng: &mut ChaCha20Rng, signing_key: &SigningKeyPair) -> PublicIdentityKey {
    let agreement_key = generate_key_pair(rng);
    let binding_signature = sign_identity_key_binding(signing_key, &agreement_key.public).unwrap();
    PublicIdentityKey {
        public_key: agreement_key.public,
        verifying_key: signing_key.verifying,
        binding_signature,
    }
}
