//! Devices that run real handshakes through KeyStore and commit through a host store.

use super::host_identity::DeviceStorage;
use super::{CREATED_AT_SECS, HostStore, sender_certificate_bytes, validation};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    AcknowledgmentOutcome, AcknowledgmentProcessing, ContactDiscoveryKey, ContactIdentity,
    ContactIdentityKey, InboundMessageOutcome, KeyStore, Message, MessageDecryption,
    MessageEncryption, OutboundMessageResult, PreKeyBundle, PreKeySelection,
    PreparedKeyStoreOperation, ProtocolStateKey, PublicIdentityKey, SessionAcceptance,
    SessionAcceptanceOutcome, SessionEstablishmentError, SessionInitiation,
    SessionInitiationResult, TransportBinding,
};
use roost_crypto::SigningKeyPair;
use roost_protocol::{DomainSigningKey, DomainSigningKeyStatus, MessageId};

/// The relay that certifies every test Device's Identity Key.
pub struct Relay {
    domain_id: Vec<u8>,
    signing_key: SigningKeyPair,
}

impl Relay {
    pub fn new() -> Self {
        Self {
            domain_id: super::TEST_DOMAIN_ID.to_vec(),
            signing_key: super::test_domain_key(),
        }
    }

    fn certify(&self, identity: &PublicIdentityKey) -> Credential {
        let certificate = sender_certificate_bytes(
            &self.domain_id,
            identity_key(identity),
            CREATED_AT_SECS + 100_000,
        );
        let signature = self.signing_key.sign(&certificate).to_bytes().to_vec();
        Credential {
            certificate,
            signature,
        }
    }

    fn domain_signing_key(&self) -> DomainSigningKey<'_> {
        DomainSigningKey {
            id: &self.domain_id,
            verifying_key: self.signing_key.verifying.as_bytes(),
            status: DomainSigningKeyStatus::Trusted,
        }
    }
}

struct Credential {
    certificate: Vec<u8>,
    signature: Vec<u8>,
}

/// One app install: its KeyStore, its host database, and the Relay that certifies it.
pub struct Device<'relay> {
    pub store: KeyStore,
    pub host: HostStore,
    storage: DeviceStorage,
    pub identity: PublicIdentityKey,
    relay: &'relay Relay,
    credential: Credential,
    deduplication_key: ProtocolStateKey,
    /// Where acknowledgments go: the Discovery Key of the contact this Device last accepted.
    acknowledgment_recipient: [u8; 32],
    next_message: u16,
    tag: u8,
}

pub fn binding() -> TransportBinding {
    TransportBinding::new(b"test-route".to_vec()).unwrap()
}

impl<'relay> Device<'relay> {
    pub fn new(relay: &'relay Relay, tag: u8) -> Self {
        let storage = DeviceStorage::default();
        let store = storage.open();
        let created = store.prepare_identity_creation().unwrap();
        finalize(&store, &created);
        let identity = created.output.public().unwrap();
        let rotated = store.prepare_signed_prekey_rotation().unwrap();
        finalize(&store, &rotated);
        let deduplication_key = ProtocolStateKey::from_bytes(vec![tag; 16]).unwrap();
        let mut host = HostStore::default();
        host.commit(vec![
            store
                .protocol_engine()
                .initialize_deduplication_set(
                    &mut ChaCha20Rng::from_seed([tag; 32]),
                    deduplication_key.clone(),
                )
                .unwrap(),
        ])
        .unwrap();
        Self {
            store,
            host,
            storage,
            credential: relay.certify(&identity),
            identity,
            relay,
            deduplication_key,
            acknowledgment_recipient: [0x09; 32],
            next_message: 0,
            tag,
        }
    }

    pub fn identity_key(&self) -> ContactIdentityKey {
        identity_key(&self.identity)
    }

    /// Replaces the KeyStore with a new one over the same SecureStorage, as an app restart does.
    pub fn restart(&mut self) {
        self.store = self.storage.open();
    }

    pub fn contact_identity(&self) -> ContactIdentity {
        ContactIdentity {
            identity_key: self.identity_key(),
            discovery_key: ContactDiscoveryKey::from(
                &self.store.current_publication().unwrap().discovery_key,
            ),
        }
    }

    /// Records `peer` as an accepted contact, as the app does after the user accepts them.
    pub fn accept_contact(&mut self, peer: &Device<'_>) {
        let engine = *self.store.protocol_engine();
        let recorded = engine
            .record_contact(&self.host.snapshot(), peer.contact_identity())
            .unwrap();
        self.host.commit(recorded.state_updates).unwrap();
        let accepted = engine
            .accept_contact(&self.host.snapshot(), peer.identity_key())
            .unwrap();
        self.host.commit(accepted.state_updates).unwrap();
        self.acknowledgment_recipient = peer.contact_identity().discovery_key.x25519_public_key;
    }

    /// Publishes a bundle with a fresh one-time prekey, as the relay would serve it.
    pub fn bundle(&self) -> PublishedBundle {
        let one_time_prekeys = self.store.prepare_one_time_prekeys(1).unwrap();
        finalize(&self.store, &one_time_prekeys);
        self.published(Some(one_time_prekeys.output[0].clone()))
    }

    /// Publishes a bundle after one-time prekeys run out, so only the signed prekey is used.
    pub fn bundle_without_one_time_prekey(&self) -> PublishedBundle {
        self.published(None)
    }

    fn published(
        &self,
        one_time_prekey: Option<roost_core::PublicOneTimePreKey>,
    ) -> PublishedBundle {
        let publication = self.store.current_publication().unwrap();
        PublishedBundle {
            identity: self.identity.clone(),
            selection: PreKeySelection {
                signed_prekey_id: publication.signed_prekey.id,
                one_time_prekey_id: one_time_prekey.as_ref().map(|prekey| prekey.id),
            },
            discovery_to_identity: publication.discovery_to_identity,
            bundle: PreKeyBundle {
                version: publication.version,
                discovery_key: publication.discovery_key,
                signed_prekey: publication.signed_prekey,
                one_time_prekey,
            },
        }
    }

    pub fn initiate(
        &mut self,
        peer: &PublishedBundle,
        plaintext: &[u8],
    ) -> SessionInitiationResult {
        let mut initiation = self.initiate_session(peer, plaintext).unwrap();
        self.host
            .commit(std::mem::take(&mut initiation.state_updates))
            .unwrap();
        initiation
    }

    /// Starts a Session with `peer` without committing the result.
    pub fn initiate_session(
        &mut self,
        peer: &PublishedBundle,
        plaintext: &[u8],
    ) -> Result<SessionInitiationResult, SessionEstablishmentError> {
        let message_id = self.next_message_id();
        self.store.initiate_session_with_transport_binding(
            SessionInitiation {
                snapshot: &self.host.snapshot(),
                responder_identity_key: peer.identity.clone(),
                responder_discovery_to_identity: peer.discovery_to_identity,
                responder_prekey_bundle: peer.bundle.clone(),
                message_id,
                sent_at_millis: sent_at_millis(message_id),
                sender_certificate: &self.credential.certificate,
                sender_signature: &self.credential.signature,
                plaintext,
            },
            &binding(),
        )
    }

    /// Replaces the Deduplication Set with an empty one, as if every recorded digest had aged out.
    pub fn forget_received_digests(&mut self) {
        let fresh = self
            .store
            .protocol_engine()
            .initialize_deduplication_set(
                &mut ChaCha20Rng::from_seed([self.tag ^ 0x5a; 32]),
                self.deduplication_key.clone(),
            )
            .unwrap();
        self.host.set_raw(
            fresh.address().clone(),
            fresh.blob().unwrap().as_bytes().to_vec(),
        );
    }

    /// Sends to `peer` on whichever Session Roost selects.
    pub fn send(&mut self, peer: &Device<'_>, plaintext: &[u8]) -> OutboundMessageResult {
        let mut sent = self.encrypt(peer, plaintext).unwrap();
        self.host
            .commit(std::mem::take(&mut sent.state_updates))
            .unwrap();
        sent
    }

    /// Encrypts for `peer` without committing the result.
    pub fn encrypt(
        &mut self,
        peer: &Device<'_>,
        plaintext: &[u8],
    ) -> Result<OutboundMessageResult, roost_core::MessageOperationError> {
        let message_id = self.next_message_id();
        self.store.encrypt_message_with_transport_binding(
            MessageEncryption {
                snapshot: &self.host.snapshot(),
                message_id,
                contact_identity_key: peer.identity_key(),
                sent_at_millis: sent_at_millis(message_id),
                sender_certificate: &self.credential.certificate,
                sender_signature: &self.credential.signature,
                plaintext,
            },
            &binding(),
        )
    }

    /// Receives `message` and commits whatever state it returns.
    pub fn receive(&mut self, message: &Message) -> InboundMessageOutcome {
        let mut outcome = self.decrypt(message).unwrap();
        let updates = match &mut outcome {
            InboundMessageOutcome::Accepted(result) => std::mem::take(&mut result.state_updates),
            InboundMessageOutcome::Blocked(result) => std::mem::take(&mut result.state_updates),
            InboundMessageOutcome::SessionUnrecoverable(result) => {
                std::mem::take(&mut result.state_updates)
            }
            InboundMessageOutcome::Duplicate | InboundMessageOutcome::UnknownSession => Vec::new(),
        };
        self.host.commit(updates).unwrap();
        outcome
    }

    /// Decrypts `message` without committing the result.
    pub fn decrypt(
        &self,
        message: &Message,
    ) -> Result<InboundMessageOutcome, roost_core::MessageOperationError> {
        let domain_keys = [self.relay.domain_signing_key()];
        self.store.decrypt_message_with_transport_bindings(
            MessageDecryption {
                snapshot: &self.host.snapshot(),
                deduplication_key: self.deduplication_key.clone(),
                message,
                acknowledgment_id: MessageId::from_bytes([self.tag ^ 0xff; 16]),
                acknowledgment_recipient_public_key: self.acknowledgment_recipient,
                acknowledgment_sent_at_millis: CREATED_AT_SECS * 1000,
                acknowledgment_sender_certificate: &self.credential.certificate,
                acknowledgment_sender_signature: &self.credential.signature,
                sender_certificate_validation: Some(validation(&domain_keys, &[])),
            },
            &binding(),
            &binding(),
        )
    }

    /// Accepts a Session from a first Message and commits it through the prepared operation.
    pub fn accept(
        &mut self,
        message: &Message,
        selection: PreKeySelection,
    ) -> SessionAcceptanceOutcome {
        let mut prepared = self.prepare_accept(message, selection).unwrap();
        self.store.reserve_operation(prepared.operation.id).unwrap();
        if let SessionAcceptanceOutcome::Accepted(result) = &mut prepared.output {
            self.host
                .commit(std::mem::take(&mut result.state_updates))
                .unwrap();
        }
        self.store
            .finalize_operation(prepared.operation.id)
            .unwrap();
        prepared.output
    }

    /// Prepares acceptance of the Session `message` starts, without reserving or committing it.
    pub fn prepare_accept(
        &self,
        message: &Message,
        selection: PreKeySelection,
    ) -> Result<PreparedKeyStoreOperation<SessionAcceptanceOutcome>, SessionEstablishmentError>
    {
        self.prepare_accept_with_binding(message, &binding(), selection)
    }

    pub fn prepare_accept_with_binding(
        &self,
        message: &Message,
        transport_binding: &TransportBinding,
        selection: PreKeySelection,
    ) -> Result<PreparedKeyStoreOperation<SessionAcceptanceOutcome>, SessionEstablishmentError>
    {
        let domain_keys = [self.relay.domain_signing_key()];
        self.store.prepare_accept_session_with_transport_binding(
            SessionAcceptance {
                snapshot: &self.host.snapshot(),
                deduplication_key: self.deduplication_key.clone(),
                message,
                sender_certificate_validation: validation(&domain_keys, &[]),
            },
            transport_binding,
            selection,
        )
    }

    /// Processes an acknowledgment and commits whatever state it returns.
    pub fn process_acknowledgment(&mut self, message: &Message) -> AcknowledgmentOutcome {
        let mut outcome = self
            .store
            .process_acknowledgment_with_transport_binding(
                AcknowledgmentProcessing {
                    snapshot: &self.host.snapshot(),
                    message,
                },
                &binding(),
            )
            .unwrap();
        let updates = match &mut outcome {
            AcknowledgmentOutcome::Cleared(result) => std::mem::take(&mut result.state_updates),
            AcknowledgmentOutcome::Missed { state_updates, .. } => std::mem::take(state_updates),
            AcknowledgmentOutcome::SessionUnrecoverable(result) => {
                std::mem::take(&mut result.state_updates)
            }
            AcknowledgmentOutcome::Duplicate | AcknowledgmentOutcome::UnknownSession => Vec::new(),
        };
        self.host.commit(updates).unwrap();
        outcome
    }

    fn next_message_id(&mut self) -> MessageId {
        self.next_message += 1;
        let mut id = [self.tag; 16];
        id[..2].copy_from_slice(&self.next_message.to_be_bytes());
        MessageId::from_bytes(id)
    }
}

/// A peer's published keys as the relay serves them, with the prekey IDs a transport carries.
pub struct PublishedBundle {
    pub identity: PublicIdentityKey,
    pub discovery_to_identity: roost_core::Signature,
    pub bundle: PreKeyBundle,
    pub selection: PreKeySelection,
}

fn identity_key(identity: &PublicIdentityKey) -> ContactIdentityKey {
    ContactIdentityKey {
        x25519_public_key: *identity.public_key.as_bytes(),
        ed25519_verifying_key: identity.verifying_key.to_bytes(),
    }
}

fn sent_at_millis(message_id: MessageId) -> u64 {
    CREATED_AT_SECS * 1000 + u64::from(message_id.as_bytes()[1])
}

fn finalize<T>(store: &KeyStore, prepared: &PreparedKeyStoreOperation<T>) {
    store.reserve_operation(prepared.operation.id).unwrap();
    store.finalize_operation(prepared.operation.id).unwrap();
}
