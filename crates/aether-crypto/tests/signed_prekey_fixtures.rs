//! Replays checked-in signed pre-key fixtures across the public Crypto API.

use aether_crypto::{SignedPreKey, SigningKeyPair, verify_signed_prekey_bundle};
use serde::Deserialize;

const SIGNED_PREKEY_SIGNED_BYTES_PREFIX: &[u8] = b"AetherSPK-v1:";

#[derive(Deserialize)]
struct FixtureFile {
    version: u8,
    provenance: String,
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
struct Fixture {
    name: String,
    signing_key_seed_hex: String,
    signed_prekey_secret_hex: String,
    epoch: u32,
    created_at: u64,
    signed_bytes_hex: String,
    signature_hex: String,
}

#[test]
fn checked_in_signed_prekey_fixtures_verify() {
    let fixture_file: FixtureFile =
        serde_json::from_str(include_str!("fixtures/signed_prekeys_v1.json")).unwrap();

    assert_eq!(fixture_file.version, 1);
    assert!(fixture_file.provenance.contains("test-only"));
    assert_eq!(fixture_file.fixtures.len(), 1);
    for fixture in fixture_file.fixtures {
        replay_fixture(&fixture);
    }
}

fn replay_fixture(fixture: &Fixture) {
    let signing_key = SigningKeyPair::from_signing_bytes(hex_array(&fixture.signing_key_seed_hex));
    let secret = hex_array(&fixture.signed_prekey_secret_hex);
    let unsigned =
        SignedPreKey::from_secret_bytes(secret, [0u8; 64], fixture.epoch, fixture.created_at);
    let signed_bytes = signed_prekey_signed_bytes(
        unsigned.public().as_bytes(),
        fixture.epoch,
        fixture.created_at,
    );

    assert_eq!(
        hex::encode(&signed_bytes),
        fixture.signed_bytes_hex,
        "{} signed bytes",
        fixture.name
    );
    assert_eq!(
        hex::encode(signing_key.sign(&signed_bytes).to_bytes()),
        fixture.signature_hex,
        "{} signature",
        fixture.name
    );

    let signed_prekey = SignedPreKey::from_secret_bytes(
        secret,
        hex_array(&fixture.signature_hex),
        fixture.epoch,
        fixture.created_at,
    );
    verify_signed_prekey_bundle(&signed_prekey.bundle(), &signing_key.verifying).unwrap();
}

fn signed_prekey_signed_bytes(public_key: &[u8; 32], epoch: u32, created_at: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SIGNED_PREKEY_SIGNED_BYTES_PREFIX.len() + 32 + 4 + 8);
    bytes.extend_from_slice(SIGNED_PREKEY_SIGNED_BYTES_PREFIX);
    bytes.extend_from_slice(public_key);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&created_at.to_be_bytes());
    bytes
}

fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}
