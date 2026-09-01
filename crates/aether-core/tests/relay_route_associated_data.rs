//! Replays the Relay route associated-data vectors through the public Core interface.

use aether_core::{RelayPreKeyReference, RelayRoute, RelayRouteError};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureFile {
    version: u8,
    provenance: String,
    vectors: Vec<RouteFixture>,
}

#[derive(Deserialize)]
struct RouteFixture {
    name: String,
    inputs: RouteInputs,
    expected_associated_data_hex: String,
}

#[derive(Deserialize)]
struct RouteInputs {
    protocol_version: u16,
    route_kind: String,
    recipient_signing_key_hex: String,
    signed_prekey_id: Option<u64>,
    one_time_prekey_id: Option<u64>,
}

#[test]
fn checked_in_relay_route_vectors_replay_through_public_core_interface() {
    let fixture: FixtureFile =
        serde_json::from_str(include_str!("fixtures/relay_route_associated_data_v1.json")).unwrap();
    assert_eq!(fixture.version, 1);
    assert!(fixture.provenance.contains("REL-TRN-43"));
    assert_eq!(fixture.vectors.len(), 3);

    for vector in fixture.vectors {
        let route = route(&vector.inputs);
        let expected = hex::decode(&vector.expected_associated_data_hex).unwrap();

        assert_eq!(
            route.associated_data(),
            expected,
            "{} canonical bytes",
            vector.name
        );
        assert_eq!(
            route.verify_associated_data(&expected),
            Ok(()),
            "{} receive verification",
            vector.name
        );
    }
}

#[test]
fn relay_route_verification_rejects_noncanonical_or_tampered_bytes() {
    let route = RelayRoute::initial(
        1,
        [0x44; 32],
        RelayPreKeyReference {
            signed_prekey_id: 7,
            one_time_prekey_id: None,
        },
    );
    let canonical = route.associated_data();
    let mut wrong_kind = canonical.clone();
    wrong_kind[16] = 2;
    let mut wrong_prekey_length = canonical.clone();
    wrong_prekey_length[50] = 16;
    let mut invalid_presence = canonical.clone();
    invalid_presence[59] = 2;
    let mut nonzero_absent_padding = canonical.clone();
    nonzero_absent_padding[67] = 1;
    let mut trailing = canonical.clone();
    trailing.push(0);

    for candidate in [
        wrong_kind,
        wrong_prekey_length,
        invalid_presence,
        nonzero_absent_padding,
        trailing,
        canonical[..canonical.len() - 1].to_vec(),
    ] {
        assert_eq!(
            route.verify_associated_data(&candidate),
            Err(RelayRouteError::AssociatedDataMismatch)
        );
    }
}

#[test]
fn relay_route_preserves_unsigned_64_bit_identifier_boundaries() {
    let route = RelayRoute::initial(
        u16::MAX,
        [0x44; 32],
        RelayPreKeyReference {
            signed_prekey_id: u64::MAX,
            one_time_prekey_id: Some(u64::MAX),
        },
    );
    let associated_data = route.associated_data();

    assert_eq!(&associated_data[14..16], &u16::MAX.to_be_bytes());
    assert_eq!(&associated_data[51..59], &u64::MAX.to_be_bytes());
    assert_eq!(associated_data[59], 1);
    assert_eq!(&associated_data[60..68], &u64::MAX.to_be_bytes());
    assert_eq!(route.verify_associated_data(&associated_data), Ok(()));
}

fn route(inputs: &RouteInputs) -> RelayRoute {
    let recipient_signing_key: [u8; 32] = hex::decode(&inputs.recipient_signing_key_hex)
        .unwrap()
        .try_into()
        .unwrap();
    match inputs.route_kind.as_str() {
        "initial" => RelayRoute::initial(
            inputs.protocol_version,
            recipient_signing_key,
            RelayPreKeyReference {
                signed_prekey_id: inputs.signed_prekey_id.unwrap(),
                one_time_prekey_id: inputs.one_time_prekey_id,
            },
        ),
        "established" => {
            assert_eq!(inputs.signed_prekey_id, None);
            assert_eq!(inputs.one_time_prekey_id, None);
            RelayRoute::established(inputs.protocol_version, recipient_signing_key)
        }
        kind => panic!("unknown route kind in fixture: {kind}"),
    }
}
