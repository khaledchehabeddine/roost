//! Replays checked-in Safety Number fixtures across the public Core API.

use roost_core::{IdentityKey, derive_safety_number};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureFile {
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
struct Fixture {
    name: String,
    first_identity: IdentityKeyFixture,
    second_identity: IdentityKeyFixture,
    initial_discovery_x25519_public_key_hex: Option<String>,
    rotated_discovery_x25519_public_key_hex: Option<String>,
    expected: ExpectedFixture,
}

#[derive(Deserialize)]
struct IdentityKeyFixture {
    x25519_public_key_hex: String,
    ed25519_verifying_key_hex: String,
}

#[derive(Deserialize)]
struct ExpectedFixture {
    raw_hex: String,
    grouped_decimal: String,
}

#[test]
fn checked_in_safety_number_fixtures_replay() {
    let fixture_file: FixtureFile =
        serde_json::from_str(include_str!("fixtures/safety_numbers_v1.json")).unwrap();

    assert_eq!(fixture_file.fixtures.len(), 3);
    for fixture in fixture_file.fixtures {
        let first = identity_key(&fixture.first_identity);
        let second = identity_key(&fixture.second_identity);
        let safety_number = derive_safety_number(first, second).unwrap();

        assert_eq!(
            hex::encode(safety_number.raw_bytes),
            fixture.expected.raw_hex,
            "{} raw bytes changed",
            fixture.name
        );
        assert_eq!(
            safety_number.grouped_decimal, fixture.expected.grouped_decimal,
            "{} display changed",
            fixture.name
        );
        if fixture.name == "dk_rotation_alpha" {
            assert_ne!(
                fixture.initial_discovery_x25519_public_key_hex,
                fixture.rotated_discovery_x25519_public_key_hex
            );
        }
    }
}

fn identity_key(fixture: &IdentityKeyFixture) -> IdentityKey {
    IdentityKey {
        x25519_public_key: hex32(&fixture.x25519_public_key_hex),
        ed25519_verifying_key: hex32(&fixture.ed25519_verifying_key_hex),
    }
}

fn hex32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}
