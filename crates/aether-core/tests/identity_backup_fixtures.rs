//! Replays the checked-in identity backup fixture across the public Core import API.

use aether_core::{InMemorySecureStorage, KeyStore};
use serde::Deserialize;
use unicode_normalization::UnicodeNormalization;

const HEADER_LEN: usize = 53;

#[derive(Deserialize)]
struct FixtureFile {
    version: u8,
    backup_format_version: u8,
    argon2id: Argon2idParams,
    passphrase_normalization: String,
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
struct Argon2idParams {
    memory_cost_kib: u32,
    iterations: u32,
    parallelism: u32,
    minimum_memory_cost_kib: u32,
}

#[derive(Deserialize)]
struct Fixture {
    name: String,
    passphrase: String,
    normalized_passphrase: String,
    backup_hex: String,
    header_hex: String,
    ciphertext_hex: String,
    decoded: Decoded,
}

#[derive(Deserialize)]
struct Decoded {
    identity_x25519_public_key_hex: String,
    identity_ed25519_verifying_key_hex: String,
    discovery_epoch: u32,
    discovery_x25519_public_key_hex: String,
    discovery_ed25519_verifying_key_hex: String,
}

#[test]
fn checked_in_identity_backup_fixtures_replay() {
    let fixture_file: FixtureFile =
        serde_json::from_str(include_str!("fixtures/identity_backup_v2.json")).unwrap();

    assert_eq!(fixture_file.version, 2);
    assert_eq!(fixture_file.backup_format_version, 2);
    assert_eq!(fixture_file.argon2id.memory_cost_kib, 65_536);
    assert_eq!(fixture_file.argon2id.iterations, 3);
    assert_eq!(fixture_file.argon2id.parallelism, 1);
    assert_eq!(fixture_file.argon2id.minimum_memory_cost_kib, 65_536);
    assert_eq!(fixture_file.passphrase_normalization, "NFC");
    assert_eq!(fixture_file.fixtures.len(), 1);
    for fixture in &fixture_file.fixtures {
        replay_fixture(&fixture_file, fixture);
    }
}

fn replay_fixture(fixture_file: &FixtureFile, fixture: &Fixture) {
    let backup = hex::decode(&fixture.backup_hex).unwrap();
    let header = hex::decode(&fixture.header_hex).unwrap();
    let ciphertext = hex::decode(&fixture.ciphertext_hex).unwrap();
    assert_eq!(
        fixture.passphrase.nfc().collect::<String>(),
        fixture.normalized_passphrase,
        "{} normalized passphrase",
        fixture.name
    );
    assert_eq!(header.len(), HEADER_LEN, "{} header length", fixture.name);
    assert_eq!(
        backup,
        [header.as_slice(), ciphertext.as_slice()].concat(),
        "{} backup split",
        fixture.name
    );
    assert_eq!(
        header[0], fixture_file.backup_format_version,
        "{} format version",
        fixture.name
    );
    assert_eq!(
        u32::from_be_bytes(header[1..5].try_into().unwrap()),
        fixture_file.argon2id.memory_cost_kib,
        "{} Argon2id memory cost",
        fixture.name
    );
    assert_eq!(
        u32::from_be_bytes(header[5..9].try_into().unwrap()),
        fixture_file.argon2id.iterations,
        "{} Argon2id iterations",
        fixture.name
    );
    assert_eq!(
        u32::from_be_bytes(header[9..13].try_into().unwrap()),
        fixture_file.argon2id.parallelism,
        "{} Argon2id parallelism",
        fixture.name
    );

    let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
    store
        .import_encrypted_backup(&backup, &fixture.passphrase)
        .unwrap_or_else(|e| panic!("{} import: {e}", fixture.name));

    let identity = store.load_identity().unwrap();
    assert_eq!(
        hex::encode(identity.public_key().as_bytes()),
        fixture.decoded.identity_x25519_public_key_hex,
        "{} identity x25519",
        fixture.name
    );
    assert_eq!(
        hex::encode(identity.verifying_key().as_bytes()),
        fixture.decoded.identity_ed25519_verifying_key_hex,
        "{} identity ed25519",
        fixture.name
    );

    // Verified against the restored identity, and pins the carried epoch lineage (not a reset).
    let discovery = store.current_discovery_key_bundle().unwrap();
    assert_eq!(
        discovery.epoch, fixture.decoded.discovery_epoch,
        "{} discovery epoch",
        fixture.name
    );
    assert_eq!(
        hex::encode(discovery.public_key.as_bytes()),
        fixture.decoded.discovery_x25519_public_key_hex,
        "{} discovery x25519",
        fixture.name
    );
    assert_eq!(
        hex::encode(discovery.verifying_key.as_bytes()),
        fixture.decoded.discovery_ed25519_verifying_key_hex,
        "{} discovery ed25519",
        fixture.name
    );
}
