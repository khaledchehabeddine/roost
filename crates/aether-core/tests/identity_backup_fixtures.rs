//! Replays the checked-in identity backup fixture across the public Core import API.

use aether_core::{InMemorySecureStorage, KeyStore};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureFile {
    version: u8,
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
struct Fixture {
    name: String,
    passphrase: String,
    backup_hex: String,
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
        serde_json::from_str(include_str!("fixtures/identity_backup_v1.json")).unwrap();

    assert_eq!(fixture_file.version, 1);
    assert_eq!(fixture_file.fixtures.len(), 1);
    for fixture in &fixture_file.fixtures {
        replay_fixture(fixture);
    }
}

fn replay_fixture(fixture: &Fixture) {
    let backup = hex::decode(&fixture.backup_hex).unwrap();
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
