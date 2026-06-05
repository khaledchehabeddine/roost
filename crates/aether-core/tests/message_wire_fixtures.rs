//! Verifies checked-in Message wire fixtures across the public Core encode/decode API.

use aether_core::{Message, PayloadKind};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureFile {
    version: u8,
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
struct Fixture {
    name: String,
    encoded_hex: String,
    decoded: DecodedFixture,
}

#[derive(Deserialize)]
struct DecodedFixture {
    id_hex: String,
    recipient_public_key_hex: String,
    timestamp_millis: u64,
    payload_kind: String,
    payload_hex: String,
}

#[test]
fn checked_in_fixtures_decode_and_reencode() {
    let fixture_file: FixtureFile =
        serde_json::from_str(include_str!("fixtures/message_wire_v1.json")).unwrap();

    assert_eq!(fixture_file.version, 1);
    assert_eq!(fixture_file.fixtures.len(), 4);
    for fixture in fixture_file.fixtures {
        let encoded = hex::decode(&fixture.encoded_hex).unwrap();
        let message = Message::from_bytes(&encoded).unwrap();

        assert_eq!(
            message.id.as_bytes(),
            &hex_array::<16>(&fixture.decoded.id_hex),
            "{} id",
            fixture.name
        );
        assert_eq!(
            message.recipient_public_key,
            hex_array::<32>(&fixture.decoded.recipient_public_key_hex),
            "{} recipient public key",
            fixture.name
        );
        assert_eq!(
            message.timestamp_millis, fixture.decoded.timestamp_millis,
            "{} timestamp",
            fixture.name
        );
        assert_eq!(
            message.payload_kind,
            payload_kind(&fixture.decoded.payload_kind),
            "{} payload kind",
            fixture.name
        );
        assert_eq!(
            message.payload,
            hex::decode(&fixture.decoded.payload_hex).unwrap(),
            "{} payload",
            fixture.name
        );
        assert_eq!(
            hex::encode(message.to_bytes().unwrap()),
            fixture.encoded_hex,
            "{} re-encoded bytes",
            fixture.name
        );
    }
}

fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

fn payload_kind(kind: &str) -> PayloadKind {
    match kind {
        "text" => PayloadKind::EncryptedText,
        "acknowledgment" => PayloadKind::Acknowledgment,
        "key_exchange" => PayloadKind::KeyExchange,
        "ratchet_header" => PayloadKind::RatchetHeader,
        _ => panic!("unknown payload kind in fixture: {kind}"),
    }
}
