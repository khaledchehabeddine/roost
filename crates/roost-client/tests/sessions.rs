//! Two hosts establish a Session through the exported API and address it by its SessionID.

mod support;

use roost_client::{
    ContactIdentity, DomainSigningKey, DomainSigningKeyStatus, IdentityContext, IdentityKey,
    InboundMessageOutcome, Message, OperationId, PreKeySelection, ProtocolStateCommitCheck,
    ProtocolStateEntry, ProtocolStateUpdate, RevocationState, RoostError,
    SenderCertificateValidation, SessionAcceptanceOutcome, SessionId, TransportBinding,
};
use roost_crypto::SigningKeyPair;
use std::collections::HashSet;
use std::sync::Arc;
use support::MemoryStorage;

const CERTIFICATE_DOMAIN_TAG: &[u8] = b"AetherSenderCertificate-v2:";
const CERTIFICATE_VERSION: u8 = 2;
const DOMAIN_SIGNING_KEY_ID: &[u8] = b"relay-signing-key";
const RELAY_DOMAIN: &[u8] = b"relay.example";
const NOW_MILLIS: u64 = 1_700_000_000_000;

fn domain_signing_key() -> SigningKeyPair {
    SigningKeyPair::from_signing_bytes([0x41; 32])
}

fn binding() -> TransportBinding {
    TransportBinding {
        bytes: b"route".to_vec(),
    }
}

fn validation() -> SenderCertificateValidation {
    SenderCertificateValidation {
        domain_signing_keys: vec![DomainSigningKey {
            id: DOMAIN_SIGNING_KEY_ID.to_vec(),
            verifying_key: domain_signing_key().verifying.to_bytes().to_vec(),
            status: DomainSigningKeyStatus::Trusted,
        }],
        expected_relay_domain: RELAY_DOMAIN.to_vec(),
        revocation_state: RevocationState {
            available: true,
            revoked_identity_keys: Vec::new(),
        },
        reference_time_millis: NOW_MILLIS,
    }
}

/// One app's IdentityContext, its host store, and the certificate its relay issued.
struct Host {
    context: Arc<IdentityContext>,
    entries: Vec<ProtocolStateEntry>,
    certificate: Vec<u8>,
    certificate_signature: Vec<u8>,
}

impl Host {
    fn new() -> Self {
        let context = IdentityContext::new(Arc::new(MemoryStorage::default()));
        let identity = context.prepare_identity_creation().unwrap();
        complete(&context, identity.operation_id);
        let signed_prekey = context.prepare_signed_prekey_rotation().unwrap();
        complete(&context, signed_prekey.operation_id);
        // Encoded as a relay's domain authority does before signing.
        let certificate = [
            CERTIFICATE_DOMAIN_TAG,
            &[CERTIFICATE_VERSION],
            &[u8::try_from(DOMAIN_SIGNING_KEY_ID.len()).unwrap()],
            DOMAIN_SIGNING_KEY_ID,
            &[u8::try_from(RELAY_DOMAIN.len()).unwrap()],
            RELAY_DOMAIN,
            &identity.identity.key.agreement_key,
            &identity.identity.key.signing_key,
            &(NOW_MILLIS / 1_000 + 3_600).to_be_bytes(),
        ]
        .concat();
        let mut host = Self {
            certificate_signature: domain_signing_key().sign(&certificate).to_bytes().to_vec(),
            certificate,
            entries: Vec::new(),
            context,
        };
        let deduplication_set = host
            .context
            .messaging()
            .initialize_deduplication_set(b"dedup".to_vec())
            .unwrap();
        host.commit(vec![deduplication_set]);
        host
    }

    fn identity_key(&self) -> IdentityKey {
        self.context.identity().unwrap().unwrap().key
    }

    fn contact(&self) -> ContactIdentity {
        let publication = self.context.current_publication().unwrap();
        ContactIdentity {
            identity_key: self.identity_key(),
            discovery_key: roost_client::ContactDiscoveryKey {
                x25519_public_key: publication.discovery_key.public_key,
                ed25519_verifying_key: publication.discovery_key.verifying_key,
                epoch: publication.discovery_key.epoch,
                created_at_millis: publication.discovery_key.created_at_millis,
                identity_signature: publication.discovery_key.signature,
            },
        }
    }

    fn accept_contact(&mut self, peer: &Host) {
        let contacts = self.context.contacts();
        let recorded = contacts
            .record_contact(self.snapshot(), peer.contact())
            .unwrap();
        self.commit(recorded.state_updates);
        let accepted = contacts
            .accept_contact(self.snapshot(), peer.identity_key())
            .unwrap();
        self.commit(accepted.state_updates);
    }

    fn snapshot(&self) -> Vec<ProtocolStateEntry> {
        self.entries
            .iter()
            .map(|entry| ProtocolStateEntry {
                kind: entry.kind,
                key: entry.key.clone(),
                blob: entry.blob.clone(),
            })
            .collect()
    }

    // Applies updates after checking each one's condition, as a host transaction does.
    fn commit(&mut self, updates: Vec<ProtocolStateUpdate>) {
        for update in updates {
            let position = self
                .entries
                .iter()
                .position(|entry| entry.kind == update.kind && entry.key == update.key);
            match (&update.commit_check, position) {
                (ProtocolStateCommitCheck::Absent, None) => {}
                (
                    ProtocolStateCommitCheck::Digest {
                        expected_blob_digest,
                    },
                    Some(index),
                ) => {
                    assert_eq!(
                        &roost_client::protocol_state_blob_digest(self.entries[index].blob.clone()),
                        expected_blob_digest
                    );
                }
                _ => panic!("stale commit condition"),
            }
            if let Some(index) = position {
                self.entries.remove(index);
            }
            if let Some(blob) = update.blob {
                self.entries.push(ProtocolStateEntry {
                    kind: update.kind,
                    key: update.key,
                    blob,
                });
            }
        }
    }

    fn receive(
        &self,
        message: Message,
        validation: Option<SenderCertificateValidation>,
    ) -> Result<InboundMessageOutcome, RoostError> {
        self.context.messaging().decrypt_message(
            self.snapshot(),
            b"dedup".to_vec(),
            message,
            vec![0x99; 16],
            vec![0x09; 32],
            NOW_MILLIS,
            self.certificate.clone(),
            self.certificate_signature.clone(),
            validation,
            binding(),
            binding(),
        )
    }
}

fn complete(context: &IdentityContext, id: OperationId) {
    context.reserve_operation(id.clone()).unwrap();
    context.finalize_operation(id).unwrap();
}

// Starts a Session from `alice` to `bob`, has Bob accept it, and returns its SessionIDs as each
// host saw them.
fn establish(alice: &mut Host, bob: &mut Host) -> (SessionId, SessionId) {
    let one_time_prekeys = bob.context.prepare_one_time_prekeys(1).unwrap();
    complete(&bob.context, one_time_prekeys.operation_id);
    let one_time_prekey = one_time_prekeys.one_time_prekeys[0].clone();
    let publication = bob.context.current_publication().unwrap();
    let selection = PreKeySelection {
        signed_prekey_id: publication.signed_prekey.id,
        one_time_prekey_id: Some(one_time_prekey.id),
    };
    let initiation = alice
        .context
        .messaging()
        .initiate_session(
            alice.snapshot(),
            bob.context.identity().unwrap().unwrap(),
            publication,
            Some(one_time_prekey),
            vec![0x01; 16],
            NOW_MILLIS,
            alice.certificate.clone(),
            alice.certificate_signature.clone(),
            b"hello bob".to_vec(),
            binding(),
        )
        .unwrap();
    alice.commit(initiation.state_updates);
    assert!(matches!(
        bob.receive(initiation.message.clone(), Some(validation())),
        Ok(InboundMessageOutcome::UnknownSession)
    ));
    let prepared = bob
        .context
        .messaging()
        .prepare_accept_session(
            bob.snapshot(),
            b"dedup".to_vec(),
            initiation.message,
            validation(),
            binding(),
            selection,
        )
        .unwrap();
    bob.context
        .reserve_operation(prepared.operation_id.clone())
        .unwrap();
    let SessionAcceptanceOutcome::Accepted { result } = prepared.acceptance else {
        panic!("expected an accepted Session");
    };
    assert_eq!(result.plaintext, b"hello bob");
    bob.commit(result.state_updates);
    bob.context
        .finalize_operation(prepared.operation_id)
        .unwrap();
    (initiation.session_id, result.session_id)
}

#[test]
fn both_hosts_see_one_canonical_session_id() {
    let mut alice = Host::new();
    let mut bob = Host::new();
    alice.accept_contact(&bob);
    bob.accept_contact(&alice);

    let (alice_view, bob_view) = establish(&mut alice, &mut bob);

    assert_eq!(alice_view, bob_view);
    assert_eq!(
        HashSet::from([alice_view.clone(), bob_view.clone()]).len(),
        1
    );
    assert_eq!(alice_view.value.len(), 32);
    assert!(
        alice_view
            .value
            .bytes()
            .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'))
    );
    let reply = bob
        .context
        .messaging()
        .encrypt_message(
            bob.snapshot(),
            vec![0x02; 16],
            alice.identity_key(),
            NOW_MILLIS,
            bob.certificate.clone(),
            bob.certificate_signature.clone(),
            b"hello alice".to_vec(),
            binding(),
        )
        .unwrap();
    assert_eq!(reply.session_id, bob_view);
    bob.commit(reply.state_updates);
    let Ok(InboundMessageOutcome::Accepted { result }) =
        alice.receive(reply.message, Some(validation()))
    else {
        panic!("expected an accepted reply");
    };
    assert_eq!(result.session_id, alice_view);
    assert_eq!(result.plaintext, b"hello alice");
    let pending = bob
        .context
        .messaging()
        .pending_acknowledgments(bob.snapshot(), bob_view)
        .unwrap();
    assert_eq!(pending.len(), 1);
}

#[test]
fn session_ids_must_be_canonical() {
    let mut alice = Host::new();
    let mut bob = Host::new();
    let (session_id, _) = establish(&mut alice, &mut bob);

    for value in [
        session_id.value.to_uppercase(),
        session_id.value[..30].to_string(),
        format!("{}0", session_id.value),
    ] {
        assert!(matches!(
            alice
                .context
                .messaging()
                .pending_acknowledgments(alice.snapshot(), SessionId { value }),
            Err(RoostError::InvalidData { .. })
        ));
    }
}

#[test]
fn decrypt_message_requires_certificate_validation_for_a_unique_message() {
    let mut alice = Host::new();
    let mut bob = Host::new();
    alice.accept_contact(&bob);
    bob.accept_contact(&alice);
    establish(&mut alice, &mut bob);
    let outbound = alice
        .context
        .messaging()
        .encrypt_message(
            alice.snapshot(),
            vec![0x03; 16],
            bob.identity_key(),
            NOW_MILLIS,
            alice.certificate.clone(),
            alice.certificate_signature.clone(),
            b"follow-up".to_vec(),
            binding(),
        )
        .unwrap();

    assert!(matches!(
        bob.receive(outbound.message, None),
        Err(RoostError::InvalidData { .. })
    ));
}
