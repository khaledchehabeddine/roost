//! Contact calls that take a contact's one record, and the decoders apps read contacts through.

use crate::support::HostCommitError;
use crate::support::device::{Device, Relay};
use roost_core::{
    ContactIdentityKey, ContactSafetyNumberConfirmation, ContactTrustState, InboundMessageOutcome,
    ProtocolStateBlob, ProtocolStateError, ProtocolStateKind, derive_safety_number,
};

// Alice asks Bob, Bob accepts, and Alice receives the acceptance.
fn befriended(relay: &Relay) -> (Device, Device) {
    let mut alice = Device::new(relay, 0xa1);
    let mut bob = Device::new(relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");
    bob.receive(&request.message);
    let acceptance = bob.accept_request(&alice, b"welcome");
    alice.receive(&acceptance.message);
    (alice, bob)
}

// Confirms `peer`'s Safety Number on `device` and commits the result.
fn verify(device: &mut Device, peer: &Device) {
    let safety_number = derive_safety_number(device.identity_key(), peer.identity_key()).unwrap();
    let confirmation = device
        .store
        .protocol_engine()
        .confirm_contact_safety_number(
            device.identity_key(),
            peer.identity_key(),
            device.contact_record(peer.identity_key()).as_ref(),
            &safety_number.grouped_decimal,
        )
        .unwrap();
    let ContactSafetyNumberConfirmation::Matched(changes) = confirmation else {
        panic!("safety number did not match");
    };
    device.commit_changes(changes).unwrap();
}

#[test]
fn decoders_read_every_contact_record_and_refuse_other_kinds() {
    let relay = Relay::new();
    let (alice, bob) = befriended(&relay);
    let engine = *alice.store.protocol_engine();
    let contacts: Vec<_> = alice
        .host
        .snapshot_bytes()
        .into_iter()
        .filter(|(address, _)| address.kind() == ProtocolStateKind::ContactState)
        .map(|(address, blob)| {
            engine
                .decode_contact(&address, &ProtocolStateBlob::from_bytes(blob))
                .unwrap()
        })
        .collect();

    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].identity_key, bob.identity_key());
    assert_eq!(contacts[0].trust_state, ContactTrustState::Unverified);
    let sessions = alice.sessions_address(bob.identity_key());
    assert!(matches!(
        engine.decode_contact(
            &sessions,
            &ProtocolStateBlob::from_bytes(alice.host.blob_bytes(&sessions).unwrap())
        ),
        Err(ProtocolStateError::InvalidStateBinding { .. })
    ));
}

#[test]
fn a_contact_record_under_another_identitys_address_is_a_fault() {
    let relay = Relay::new();
    let (alice, bob) = befriended(&relay);
    let stranger = Device::new(&relay, 0xc0);
    let address = alice.contact_address(bob.identity_key());
    let blob = alice.host.blob_bytes(&address).unwrap();
    let mut torn = blob.clone();
    torn.pop();

    assert!(matches!(
        alice.store.protocol_engine().decode_contact(
            &alice.contact_address(stranger.identity_key()),
            &ProtocolStateBlob::from_bytes(blob)
        ),
        Err(ProtocolStateError::BlobDecode { .. })
    ));
    assert!(matches!(
        alice
            .store
            .protocol_engine()
            .decode_contact(&address, &ProtocolStateBlob::from_bytes(torn)),
        Err(ProtocolStateError::BlobDecode { .. })
    ));
}

#[test]
fn a_pending_contact_cannot_be_verified() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    alice.request(&bob, b"hi bob");
    let safety_number = derive_safety_number(alice.identity_key(), bob.identity_key()).unwrap();

    assert!(matches!(
        alice.store.protocol_engine().confirm_contact_safety_number(
            alice.identity_key(),
            bob.identity_key(),
            alice.contact_record(bob.identity_key()).as_ref(),
            &safety_number.grouped_decimal,
        ),
        Err(ProtocolStateError::InvalidStateBinding { .. })
    ));
}

#[test]
fn a_mismatched_safety_number_changes_nothing() {
    let relay = Relay::new();
    let (mut alice, bob) = befriended(&relay);
    for verified in [false, true] {
        if verified {
            verify(&mut alice, &bob);
        }
        let before = alice.contact(&bob).unwrap().trust_state;

        let confirmation = alice
            .store
            .protocol_engine()
            .confirm_contact_safety_number(
                alice.identity_key(),
                bob.identity_key(),
                alice.contact_record(bob.identity_key()).as_ref(),
                "00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00000",
            )
            .unwrap();

        assert!(matches!(
            confirmation,
            ContactSafetyNumberConfirmation::Mismatched
        ));
        assert_eq!(alice.contact(&bob).unwrap().trust_state, before);
    }
}

#[test]
fn confirming_without_a_record_is_a_fault() {
    let relay = Relay::new();
    let alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    let safety_number = derive_safety_number(alice.identity_key(), bob.identity_key()).unwrap();

    assert!(matches!(
        alice.store.protocol_engine().confirm_contact_safety_number(
            alice.identity_key(),
            bob.identity_key(),
            None,
            &safety_number.grouped_decimal,
        ),
        Err(ProtocolStateError::MissingRequiredState { .. })
    ));
}

#[test]
fn a_confirmation_cannot_commit_after_the_record_changed() {
    let relay = Relay::new();
    let (mut alice, bob) = befriended(&relay);
    let safety_number = derive_safety_number(alice.identity_key(), bob.identity_key()).unwrap();
    let ContactSafetyNumberConfirmation::Matched(stale) = alice
        .store
        .protocol_engine()
        .confirm_contact_safety_number(
            alice.identity_key(),
            bob.identity_key(),
            alice.contact_record(bob.identity_key()).as_ref(),
            &safety_number.grouped_decimal,
        )
        .unwrap()
    else {
        panic!("safety number did not match");
    };
    alice.block(bob.identity_key());

    assert_eq!(
        alice.commit_changes(stale).err(),
        Some(HostCommitError::StaleCondition)
    );
    let contact = alice.contact(&bob).unwrap();
    assert!(contact.blocked);
    assert_eq!(contact.trust_state, ContactTrustState::Unverified);
}

#[test]
fn blocking_and_unblocking_keep_every_trust_state() {
    for trust_state in [
        ContactTrustState::Pending,
        ContactTrustState::Unverified,
        ContactTrustState::Verified,
    ] {
        let relay = Relay::new();
        let (mut alice, bob) = match trust_state {
            ContactTrustState::Pending => {
                let mut alice = Device::new(&relay, 0xa1);
                let bob = Device::new(&relay, 0xb0);
                alice.request(&bob, b"hi bob");
                (alice, bob)
            }
            ContactTrustState::Unverified | ContactTrustState::Verified => befriended(&relay),
        };
        if trust_state == ContactTrustState::Verified {
            verify(&mut alice, &bob);
        }

        alice.block(bob.identity_key());
        let blocked = alice.contact(&bob).unwrap();
        alice.unblock(bob.identity_key());
        let unblocked = alice.contact(&bob).unwrap();

        assert!(blocked.blocked);
        assert!(!unblocked.blocked);
        assert_eq!(blocked.trust_state, trust_state);
        assert_eq!(unblocked.trust_state, trust_state);
    }
}

#[test]
fn unblocking_a_stranger_blocked_before_they_sent_anything_forgets_them() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let stranger = Device::new(&relay, 0xc0);
    alice.block(stranger.identity_key());
    assert!(alice.contact(&stranger).unwrap().blocked);

    alice.unblock(stranger.identity_key());

    assert!(alice.contact(&stranger).is_none());
    let changes = alice
        .store
        .protocol_engine()
        .unblock_contact(stranger.identity_key(), None)
        .unwrap();
    assert!(changes.into_updates().is_empty());
}

#[test]
fn a_new_discovery_key_keeps_trust_blocking_and_the_safety_number() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    verify(&mut alice, &bob);
    let safety_number = derive_safety_number(alice.identity_key(), bob.identity_key()).unwrap();
    let rotation = bob.store.prepare_inbox_rotation().unwrap();
    bob.store.reserve_operation(rotation.id).unwrap();
    bob.store.finalize_operation(rotation.id).unwrap();
    let message = bob.send(&alice, b"new inbox");

    assert!(matches!(
        alice.receive(&message.message),
        InboundMessageOutcome::Accepted(_)
    ));

    let contact = alice.contact(&bob).unwrap();
    assert_eq!(
        contact.discovery_key.unwrap().x25519_public_key,
        *rotation.output.discovery_key.public_key.as_bytes()
    );
    assert_eq!(contact.trust_state, ContactTrustState::Verified);
    assert!(!contact.blocked);
    assert_eq!(
        derive_safety_number(alice.identity_key(), bob.identity_key()).unwrap(),
        safety_number
    );
    assert_eq!(
        alice.send(&bob, b"still on it").session_id,
        message.session_id
    );
}

#[test]
fn contact_calls_refuse_a_non_canonical_identity_key() {
    let relay = Relay::new();
    let alice = Device::new(&relay, 0xa1);
    let invalid = ContactIdentityKey {
        x25519_public_key: [0; 32],
        ed25519_verifying_key: alice.identity_key().ed25519_verifying_key,
    };

    assert!(matches!(
        alice.store.protocol_engine().unblock_contact(invalid, None),
        Err(ProtocolStateError::InvalidStateBinding { .. })
    ));
}
