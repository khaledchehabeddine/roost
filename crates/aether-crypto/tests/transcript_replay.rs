//! Replays a recorded session transcript through handshake and Double Ratchet public APIs.

use aether_crypto::{
    HandshakeEnvelope, Header, PreKeyBundle, PublicKey, accept, generate_discovery_key,
    generate_one_time_prekey, generate_signed_prekey_for_discovery_key, generate_signing_key_pair,
    initial_associated_data, initiate,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Transcript {
    rng_seed: [u8; 32],
    created_at: u64,
    alice_discovery_epoch: u32,
    bob_discovery_epoch: u32,
    bob_one_time_prekey_id: u64,
    handshake_plaintext: String,
    handshake_envelope: WireHandshakeEnvelope,
    messages: Vec<Message>,
    expected_alice_state_sha256: String,
    expected_bob_state_sha256: String,
}

#[derive(Deserialize)]
struct Message {
    sender: Sender,
    plaintext: String,
    header: WireHeader,
    ciphertext_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Sender {
    Alice,
    Bob,
}

#[derive(Deserialize)]
struct WireHandshakeEnvelope {
    initiator_discovery_public_key: [u8; 32],
    initiator_ephemeral_public_key: [u8; 32],
    responder_discovery_epoch: u32,
    responder_signed_prekey_public_key: [u8; 32],
    one_time_prekey_id: Option<u64>,
    one_time_prekey_public_key: Option<[u8; 32]>,
    ratchet_public_key: [u8; 32],
    previous_chain_length: u32,
    message_number: u32,
    ciphertext_hex: String,
}

impl WireHandshakeEnvelope {
    fn envelope(&self) -> HandshakeEnvelope {
        HandshakeEnvelope {
            initiator_discovery_public_key: self.initiator_discovery_public_key,
            initiator_ephemeral_public_key: self.initiator_ephemeral_public_key,
            responder_discovery_epoch: self.responder_discovery_epoch,
            responder_signed_prekey_public_key: self.responder_signed_prekey_public_key,
            one_time_prekey_id: self.one_time_prekey_id,
            one_time_prekey_public_key: self.one_time_prekey_public_key,
            ratchet_public_key: self.ratchet_public_key,
            previous_chain_length: self.previous_chain_length,
            message_number: self.message_number,
            ciphertext: hex::decode(&self.ciphertext_hex).unwrap(),
        }
    }
}

#[derive(Deserialize)]
struct WireHeader {
    public_key: [u8; 32],
    previous_chain_length: u32,
    message_number: u32,
}

impl WireHeader {
    fn header(&self) -> Header {
        Header {
            public_key: PublicKey::from(self.public_key),
            previous_chain_length: self.previous_chain_length,
            message_number: self.message_number,
        }
    }
}

#[test]
fn recorded_session_transcript_reaches_expected_state() {
    let transcript: Transcript =
        serde_json::from_str(include_str!("fixtures/session_transcript_v1.json")).unwrap();
    let mut rng = ChaCha20Rng::from_seed(transcript.rng_seed);

    let alice_identity = generate_signing_key_pair(&mut rng);
    let alice_discovery_key = generate_discovery_key(
        &mut rng,
        &alice_identity,
        transcript.alice_discovery_epoch,
        transcript.created_at,
    );
    let bob_identity = generate_signing_key_pair(&mut rng);
    let bob_discovery_key = generate_discovery_key(
        &mut rng,
        &bob_identity,
        transcript.bob_discovery_epoch,
        transcript.created_at,
    );
    let bob_signed_prekey = generate_signed_prekey_for_discovery_key(
        &mut rng,
        &bob_discovery_key,
        transcript.created_at,
    );
    let bob_one_time_prekey = generate_one_time_prekey(
        &mut rng,
        transcript.bob_one_time_prekey_id,
        bob_discovery_key.epoch(),
        transcript.created_at,
    );
    let prekey_bundle = PreKeyBundle {
        discovery_key: bob_discovery_key.bundle(),
        signed_prekey: bob_signed_prekey.bundle(),
        one_time_prekey: Some(bob_one_time_prekey.bundle()),
    };
    let associated_data = initial_associated_data(
        alice_discovery_key.public_key(),
        bob_discovery_key.public_key(),
        bob_discovery_key.epoch(),
    );
    let expected_envelope = transcript.handshake_envelope.envelope();

    let (mut alice, generated_envelope) = initiate(
        &mut rng,
        &alice_discovery_key,
        &bob_identity.verifying,
        &prekey_bundle,
        transcript.handshake_plaintext.as_bytes(),
    )
    .unwrap();
    assert_envelope_eq(&generated_envelope, &expected_envelope);

    let (mut bob, handshake_plaintext) = accept(
        &mut rng,
        &expected_envelope,
        &alice_identity.verifying,
        &alice_discovery_key.bundle(),
        &bob_discovery_key,
        &bob_signed_prekey,
        Some(bob_one_time_prekey),
    )
    .unwrap();
    assert_eq!(
        handshake_plaintext.as_slice(),
        transcript.handshake_plaintext.as_bytes()
    );

    for message in transcript.messages {
        let expected_header = message.header.header();
        let expected_ciphertext = hex::decode(&message.ciphertext_hex).unwrap();
        match message.sender {
            Sender::Alice => {
                let (generated_header, generated_ciphertext) = alice
                    .ratchet_encrypt(message.plaintext.as_bytes(), &associated_data)
                    .unwrap();
                assert_header_eq(&generated_header, &expected_header);
                assert_eq!(generated_ciphertext, expected_ciphertext);
                let plaintext = bob
                    .ratchet_decrypt(
                        &mut rng,
                        &expected_ciphertext,
                        &expected_header,
                        &associated_data,
                    )
                    .unwrap();
                assert_eq!(plaintext.as_slice(), message.plaintext.as_bytes());
            }
            Sender::Bob => {
                let (generated_header, generated_ciphertext) = bob
                    .ratchet_encrypt(message.plaintext.as_bytes(), &associated_data)
                    .unwrap();
                assert_header_eq(&generated_header, &expected_header);
                assert_eq!(generated_ciphertext, expected_ciphertext);
                let plaintext = alice
                    .ratchet_decrypt(
                        &mut rng,
                        &expected_ciphertext,
                        &expected_header,
                        &associated_data,
                    )
                    .unwrap();
                assert_eq!(plaintext.as_slice(), message.plaintext.as_bytes());
            }
        }
    }

    assert_eq!(
        state_digest_hex(&alice),
        transcript.expected_alice_state_sha256
    );
    assert_eq!(state_digest_hex(&bob), transcript.expected_bob_state_sha256);
}

fn assert_envelope_eq(actual: &HandshakeEnvelope, expected: &HandshakeEnvelope) {
    assert_eq!(
        actual.initiator_discovery_public_key,
        expected.initiator_discovery_public_key
    );
    assert_eq!(
        actual.initiator_ephemeral_public_key,
        expected.initiator_ephemeral_public_key
    );
    assert_eq!(
        actual.responder_discovery_epoch,
        expected.responder_discovery_epoch
    );
    assert_eq!(
        actual.responder_signed_prekey_public_key,
        expected.responder_signed_prekey_public_key
    );
    assert_eq!(actual.one_time_prekey_id, expected.one_time_prekey_id);
    assert_eq!(
        actual.one_time_prekey_public_key,
        expected.one_time_prekey_public_key
    );
    assert_eq!(actual.ratchet_public_key, expected.ratchet_public_key);
    assert_eq!(actual.previous_chain_length, expected.previous_chain_length);
    assert_eq!(actual.message_number, expected.message_number);
    assert_eq!(actual.ciphertext, expected.ciphertext);
}

fn assert_header_eq(actual: &Header, expected: &Header) {
    assert_eq!(actual.public_key.as_bytes(), expected.public_key.as_bytes());
    assert_eq!(actual.previous_chain_length, expected.previous_chain_length);
    assert_eq!(actual.message_number, expected.message_number);
}

fn state_digest_hex(state: &aether_crypto::RatchetState) -> String {
    let bytes = state.to_bytes().unwrap();
    hex::encode(Sha256::digest(bytes.as_slice()))
}
