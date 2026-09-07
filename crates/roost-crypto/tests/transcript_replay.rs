//! Replays a recorded session transcript through handshake and Double Ratchet public APIs.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_crypto::{
    HandshakeEnvelope, Header, IdentityKeyBundle, InitialPlaintext, PreKeyBundle, PublicKey,
    SealedFramePreKeyReference, SigningKeyPair, accept, generate_discovery_key, generate_key_pair,
    generate_one_time_prekey, generate_signed_prekey_for_discovery_key, generate_signing_key_pair,
    initial_associated_data, initiate, sign_identity_key_binding,
};
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
    handshake_envelope_encoded_hex: String,
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
    version: u8,
    recipient_public_key: [u8; 32],
    prekey_reference: Option<WirePreKeyReference>,
    ephemeral_public_key: [u8; 32],
    ciphertext_hex: String,
}

#[derive(Clone, Copy, Deserialize)]
struct WirePreKeyReference {
    discovery_epoch: u32,
    signed_prekey_public_key: [u8; 32],
    one_time_prekey_id: Option<u64>,
    one_time_prekey_public_key: Option<[u8; 32]>,
}

impl WireHandshakeEnvelope {
    fn envelope(&self) -> HandshakeEnvelope {
        HandshakeEnvelope {
            version: self.version,
            recipient_public_key: self.recipient_public_key,
            prekey_reference: self
                .prekey_reference
                .map(|reference| SealedFramePreKeyReference {
                    discovery_epoch: reference.discovery_epoch,
                    signed_prekey_public_key: reference.signed_prekey_public_key,
                    one_time_prekey_id: reference.one_time_prekey_id,
                    one_time_prekey_public_key: reference.one_time_prekey_public_key,
                }),
            ephemeral_public_key: self.ephemeral_public_key,
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
    let alice_identity_key = identity_key_bundle(&mut rng, &alice_identity);
    let alice_discovery_key = generate_discovery_key(
        &mut rng,
        &alice_identity,
        transcript.alice_discovery_epoch,
        transcript.created_at,
    );
    let bob_identity = generate_signing_key_pair(&mut rng);
    let bob_identity_key = identity_key_bundle(&mut rng, &bob_identity);
    let bob_discovery_key = generate_discovery_key(
        &mut rng,
        &bob_identity,
        transcript.bob_discovery_epoch,
        transcript.created_at,
    );
    let bob_signed_prekey = generate_signed_prekey_for_discovery_key(
        &mut rng,
        &bob_discovery_key,
        0,
        transcript.created_at,
    );
    let bob_one_time_prekey = generate_one_time_prekey(
        &mut rng,
        transcript.bob_one_time_prekey_id,
        bob_discovery_key.epoch(),
        transcript.created_at,
    );
    let prekey_bundle = PreKeyBundle {
        version: roost_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: bob_discovery_key.bundle(),
        signed_prekey: bob_signed_prekey.bundle(),
        one_time_prekey: Some(bob_one_time_prekey.bundle()),
    };
    let associated_data =
        initial_associated_data(bob_discovery_key.public_key(), bob_discovery_key.epoch());
    let expected_envelope = transcript.handshake_envelope.envelope();

    let (mut alice, generated_envelope) = initiate(
        &mut rng,
        &alice_discovery_key,
        &alice_identity_key,
        &bob_identity_key,
        &prekey_bundle,
        initial_plaintext(transcript.handshake_plaintext.as_bytes()),
    )
    .unwrap();
    assert_envelope_eq(&generated_envelope, &expected_envelope);
    let encoded_envelope = generated_envelope.to_bytes().unwrap();
    assert_eq!(
        hex::encode(&encoded_envelope),
        transcript.handshake_envelope_encoded_hex
    );
    let decoded_envelope = HandshakeEnvelope::from_bytes(&encoded_envelope).unwrap();
    assert_envelope_eq(&decoded_envelope, &expected_envelope);

    let (mut bob, handshake_plaintext) = accept(
        &mut rng,
        &expected_envelope,
        Some(&alice_identity_key),
        &bob_identity_key,
        &bob_discovery_key,
        &bob_signed_prekey,
        Some(bob_one_time_prekey),
    )
    .unwrap();
    assert_eq!(
        handshake_plaintext.plaintext.as_slice(),
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

/// Reprints the two handshake fields of `session_transcript_v1.json` after a
/// wire-format change, replaying the fixture's own seed so everything else in
/// the file stays valid.
///
/// Only these two move when the *frame* changes: the Double Ratchet output the
/// frame wraps is unaffected, so message ciphertexts, headers and both state
/// digests are still whatever the file already records — which is why this
/// prints two fields rather than rewriting the document. If a change moves more
/// than the frame, the replay below will still fail after these are pasted in,
/// and that failure is the signal to widen this.
///
/// The fixture had no regenerator and was hand-edited through #171 and #174;
/// this exists so the next wire change does not repeat that.
#[test]
#[ignore = "reprints session_transcript_v1.json handshake fields; run explicitly"]
fn regenerate_session_transcript_handshake_fields() {
    let transcript: Transcript =
        serde_json::from_str(include_str!("fixtures/session_transcript_v1.json")).unwrap();
    let mut rng = ChaCha20Rng::from_seed(transcript.rng_seed);

    let alice_identity = generate_signing_key_pair(&mut rng);
    let alice_identity_key = identity_key_bundle(&mut rng, &alice_identity);
    let alice_discovery_key = generate_discovery_key(
        &mut rng,
        &alice_identity,
        transcript.alice_discovery_epoch,
        transcript.created_at,
    );
    let bob_identity = generate_signing_key_pair(&mut rng);
    let bob_identity_key = identity_key_bundle(&mut rng, &bob_identity);
    let bob_discovery_key = generate_discovery_key(
        &mut rng,
        &bob_identity,
        transcript.bob_discovery_epoch,
        transcript.created_at,
    );
    let bob_signed_prekey = generate_signed_prekey_for_discovery_key(
        &mut rng,
        &bob_discovery_key,
        0,
        transcript.created_at,
    );
    let bob_one_time_prekey = generate_one_time_prekey(
        &mut rng,
        transcript.bob_one_time_prekey_id,
        bob_discovery_key.epoch(),
        transcript.created_at,
    );
    let prekey_bundle = PreKeyBundle {
        version: roost_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: bob_discovery_key.bundle(),
        signed_prekey: bob_signed_prekey.bundle(),
        one_time_prekey: Some(bob_one_time_prekey.bundle()),
    };

    let (_, envelope) = initiate(
        &mut rng,
        &alice_discovery_key,
        &alice_identity_key,
        &bob_identity_key,
        &prekey_bundle,
        initial_plaintext(transcript.handshake_plaintext.as_bytes()),
    )
    .unwrap();

    println!("handshake_envelope.ciphertext_hex:");
    println!("{}", hex::encode(&envelope.ciphertext));
    println!("handshake_envelope_encoded_hex:");
    println!("{}", hex::encode(envelope.to_bytes().unwrap()));
}

fn assert_envelope_eq(actual: &HandshakeEnvelope, expected: &HandshakeEnvelope) {
    assert_eq!(actual.version, expected.version);
    assert_eq!(actual.recipient_public_key, expected.recipient_public_key);
    assert_eq!(actual.prekey_reference, expected.prekey_reference);
    assert_eq!(actual.ephemeral_public_key, expected.ephemeral_public_key);
    assert_eq!(actual.ciphertext, expected.ciphertext);
}

fn initial_plaintext(plaintext: &[u8]) -> InitialPlaintext<'_> {
    InitialPlaintext {
        sender_certificate: b"sender certificate",
        sender_signature: b"sender signature",
        plaintext,
    }
}

fn identity_key_bundle(rng: &mut ChaCha20Rng, signing_key: &SigningKeyPair) -> IdentityKeyBundle {
    let agreement_key = generate_key_pair(rng);
    let binding_signature = sign_identity_key_binding(signing_key, &agreement_key.public).unwrap();
    IdentityKeyBundle {
        public_key: agreement_key.public,
        verifying_key: signing_key.verifying,
        binding_signature,
    }
}

fn assert_header_eq(actual: &Header, expected: &Header) {
    assert_eq!(actual.public_key.as_bytes(), expected.public_key.as_bytes());
    assert_eq!(actual.previous_chain_length, expected.previous_chain_length);
    assert_eq!(actual.message_number, expected.message_number);
}

fn state_digest_hex(state: &roost_crypto::RatchetState) -> String {
    let bytes = state.to_bytes().unwrap();
    hex::encode(Sha256::digest(bytes.as_slice()))
}
