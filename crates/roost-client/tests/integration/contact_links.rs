//! An app puts its contact publication in a contact link, and another app checks the link.

use crate::support::{complete, published_identity};
use roost_client::{
    IdentityContext, PublicDiscoveryKey, RoostError, decode_contact_publication,
    is_newer_discovery_key,
};

// Returns the discovery key in the context's current contact link.
fn linked_discovery_key(context: &IdentityContext) -> PublicDiscoveryKey {
    decode_contact_publication(context.encode_contact_publication().unwrap())
        .unwrap()
        .discovery_key
}

#[test]
fn a_contact_publication_decodes_to_its_identity_and_current_discovery_key() {
    let alice = published_identity();
    let publication =
        decode_contact_publication(alice.encode_contact_publication().unwrap()).unwrap();
    assert_eq!(Some(publication.identity), alice.identity().unwrap());
    assert_eq!(
        publication.discovery_key,
        alice.current_publication().unwrap().discovery_key
    );
}

#[test]
fn a_newer_format_version_fails_apart_from_malformed_bytes() {
    let bytes = published_identity().encode_contact_publication().unwrap();
    let mut newer = bytes.clone();
    newer[0] += 1;
    let mut longer = bytes.clone();
    longer.push(0);

    assert!(matches!(
        decode_contact_publication(newer),
        Err(RoostError::UnsupportedVersion { .. })
    ));
    for (label, malformed) in [
        ("empty", Vec::new()),
        ("version 0", [&[0], &bytes[1..]].concat()),
        ("truncated", bytes[..bytes.len() - 1].to_vec()),
        ("longer", longer),
    ] {
        let result = decode_contact_publication(malformed);
        assert!(
            matches!(result, Err(RoostError::InvalidData { .. })),
            "{label}: {result:?}"
        );
    }
}

#[test]
fn a_contact_publication_with_any_bit_flipped_fails() {
    let bytes = published_identity().encode_contact_publication().unwrap();

    // The first byte is the format version, which the test above covers.
    for index in 1..bytes.len() {
        for bit in 0..8 {
            let mut tampered = bytes.clone();
            tampered[index] ^= 1 << bit;
            let result = decode_contact_publication(tampered);
            assert!(
                matches!(
                    result,
                    Err(RoostError::AuthenticationFailed { .. } | RoostError::InvalidData { .. })
                ),
                "byte {index}, bit {bit}: {result:?}"
            );
        }
    }
}

#[test]
fn a_padded_epoch_fails_as_malformed() {
    let bytes = published_identity().encode_contact_publication().unwrap();
    // The format version, the identity key's 128 bytes, then the discovery key's two 32-byte keys.
    const EPOCH_AT: usize = 1 + 128 + 32 + 32;
    // A new identity's first epoch takes one byte, and writing it in two leaves its value alone.
    assert_eq!(bytes[EPOCH_AT], 1);

    let padded = [&bytes[..EPOCH_AT], &[0x81, 0x00], &bytes[EPOCH_AT + 1..]].concat();

    assert!(matches!(
        decode_contact_publication(padded),
        Err(RoostError::InvalidData { .. })
    ));
}

#[test]
fn a_discovery_key_under_another_identity_fails_authentication() {
    let alice = published_identity().encode_contact_publication().unwrap();
    let mallory = published_identity().encode_contact_publication().unwrap();
    // The format version, then the identity key's two 32-byte keys and 64-byte binding signature.
    const IDENTITY_END: usize = 1 + 32 + 32 + 64;

    let forged = [&alice[..IDENTITY_END], &mallory[IDENTITY_END..]].concat();

    assert!(matches!(
        decode_contact_publication(forged),
        Err(RoostError::AuthenticationFailed { .. })
    ));
}

#[test]
fn a_link_made_after_an_inbox_rotation_has_a_newer_discovery_key() {
    let alice = published_identity();
    let older = linked_discovery_key(&alice);
    let rotation = alice.prepare_inbox_rotation().unwrap();
    complete(&alice, rotation.operation_id);
    let newer = linked_discovery_key(&alice);
    assert!(is_newer_discovery_key(newer.clone(), Some(older.clone())).unwrap());
    assert!(!is_newer_discovery_key(older.clone(), Some(newer)).unwrap());
    assert!(!is_newer_discovery_key(older.clone(), Some(older)).unwrap());
}

#[test]
fn any_discovery_key_is_newer_than_none_stored() {
    let key = linked_discovery_key(&published_identity());
    assert!(is_newer_discovery_key(key, None).unwrap());
}
