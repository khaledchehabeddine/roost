//! Verifies checked-in Message wire fixtures across the public Core encode/decode API.

use aether_core::Message;
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
    version: u8,
    recipient_public_key_hex: String,
    prekey_reference: Option<DecodedPreKeyReference>,
    ephemeral_public_key_hex: String,
    ciphertext_hex: String,
}

#[derive(Deserialize)]
struct DecodedPreKeyReference {
    discovery_epoch: u32,
    signed_prekey_public_key_hex: String,
    one_time_prekey_id: Option<u64>,
    one_time_prekey_public_key_hex: Option<String>,
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
            message.version, fixture.decoded.version,
            "{} version",
            fixture.name
        );
        assert_eq!(
            message.recipient_public_key,
            hex_array::<32>(&fixture.decoded.recipient_public_key_hex),
            "{} recipient public key",
            fixture.name
        );
        assert_prekey_reference_eq(message.prekey_reference, fixture.decoded.prekey_reference);
        assert_eq!(
            message.ephemeral_public_key,
            hex_array::<32>(&fixture.decoded.ephemeral_public_key_hex),
            "{} ephemeral public key",
            fixture.name
        );
        assert_eq!(
            message.ciphertext,
            hex::decode(&fixture.decoded.ciphertext_hex).unwrap()
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

fn assert_prekey_reference_eq(
    actual: Option<aether_crypto::SealedFramePreKeyReference>,
    expected: Option<DecodedPreKeyReference>,
) {
    match (actual, expected) {
        (None, None) => {}
        (Some(actual), Some(expected)) => {
            assert_eq!(actual.discovery_epoch, expected.discovery_epoch);
            assert_eq!(
                actual.signed_prekey_public_key,
                hex_array::<32>(&expected.signed_prekey_public_key_hex)
            );
            assert_eq!(actual.one_time_prekey_id, expected.one_time_prekey_id);
            assert_eq!(
                actual.one_time_prekey_public_key,
                expected
                    .one_time_prekey_public_key_hex
                    .as_deref()
                    .map(hex_array::<32>)
            );
        }
        _ => panic!("prekey reference mismatch"),
    }
}
