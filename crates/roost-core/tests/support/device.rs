//! Devices that run real handshakes through KeyStore and commit through a host store.

use super::host_identity::DeviceStorage;
use super::{
    CREATED_AT_SECS, HostStore, deduplication_address, run_decryption, run_encryption,
    sender_certificate_bytes, validation,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    ContactDiscoveryKey, ContactIdentity, ContactIdentityKey, InboundMessageOutcome,
    InboundSenderCertificateValidation, IncomingMessage, KeyStore, KnownDomainSigningKey, Message,
    MessageOperationError, MessageStartError, OutboundMessageResult, OutgoingMessage, PreKeyBundle,
    PreKeySelection, PreparedKeyStoreOperation, PublicIdentityKey, ReceiveSettings,
    SessionAcceptance, SessionAcceptanceOutcome, SessionEstablishmentError, SessionId,
    SessionInitiation, SessionInitiationResult, SignedSenderCertificate, TransportBinding,
};
use roost_crypto::SigningKeyPair;
use roost_protocol::{DomainSigningKeyStatus, MessageId};
use zeroize::Zeroizing;

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

    fn domain_signing_key(&self) -> KnownDomainSigningKey {
        KnownDomainSigningKey {
            id: self.domain_id.clone(),
            verifying_key: self.signing_key.verifying.to_bytes(),
            status: DomainSigningKeyStatus::Trusted,
        }
    }

    /// Returns the validation inputs that trust this relay and revoke nothing.
    pub fn validation(&self) -> InboundSenderCertificateValidation {
        validation(vec![self.domain_signing_key()], Vec::new())
    }
}

struct Credential {
    certificate: Vec<u8>,
    signature: Vec<u8>,
}

impl Credential {
    fn signed(&self) -> SignedSenderCertificate {
        SignedSenderCertificate {
            certificate: self.certificate.clone(),
            signature: self.signature.clone(),
        }
    }
}

/// One app install: its KeyStore, its host database, and the Relay that certifies it.
pub struct Device<'relay> {
    pub store: KeyStore,
    pub host: HostStore,
    storage: DeviceStorage,
    pub identity: PublicIdentityKey,
    relay: &'relay Relay,
    credential: Credential,
    /// The settings the app passes with each receive.
    pub settings: ReceiveSettings,
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
        Self {
            store,
            host: HostStore::default(),
            storage,
            credential: relay.certify(&identity),
            identity,
            relay,
            settings: ReceiveSettings::default(),
            next_message: 0,
            tag,
        }
    }

    pub fn identity_key(&self) -> ContactIdentityKey {
        identity_key(&self.identity)
    }

    /// Returns another KeyStore over the same SecureStorage, as an app extension runs.
    pub fn second_instance(&self) -> KeyStore {
        self.storage.open()
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

    /// Deletes the Deduplication Set, as if every recorded digest had aged out.
    pub fn forget_received_digests(&mut self) {
        self.host.remove(&deduplication_address());
    }

    /// Sends to `peer` on whichever Session Roost selects, and commits it.
    pub fn send(&mut self, peer: &Device<'_>, plaintext: &[u8]) -> SentMessage {
        let sent = self.encrypt(peer, plaintext).unwrap();
        let message = SentMessage {
            session_id: sent.session_id,
            message_id: sent.message_id,
            message: super::copy(&sent.message),
        };
        self.host.commit_changes(sent.changes).unwrap();
        message
    }

    /// Returns what the app passes to send `plaintext` to `peer` under a new draft MessageID.
    pub fn outgoing(&mut self, peer: &Device<'_>, plaintext: &[u8]) -> OutgoingMessage {
        let message_id = self.next_message_id();
        OutgoingMessage {
            recipient: peer.identity_key(),
            message_id,
            sent_at_millis: sent_at_millis(message_id),
            sender_certificate: self.credential.signed(),
            plaintext: Zeroizing::new(plaintext.to_vec()),
        }
    }

    /// Encrypts for `peer` without committing the result.
    pub fn encrypt(
        &mut self,
        peer: &Device<'_>,
        plaintext: &[u8],
    ) -> Result<OutboundMessageResult, DeviceError> {
        let outgoing = self.outgoing(peer, plaintext);
        let seed = self.tag ^ outgoing.message_id.as_bytes()[1];
        let encryption = self.store.start_encryption(outgoing)?;
        Ok(run_encryption(
            encryption,
            &self.host,
            &mut ChaCha20Rng::from_seed([seed; 32]),
            &binding(),
        )?)
    }

    /// Returns what the app passes to receive `message` with this Device's settings.
    pub fn incoming(&self, message: &Message) -> IncomingMessage {
        IncomingMessage {
            message: super::copy(message),
            transport_binding: binding(),
            settings: self.settings,
            sender_certificate_validation: self.relay.validation(),
            acknowledgment_sent_at_millis: CREATED_AT_SECS * 1000,
            acknowledgment_sender_certificate: self.credential.signed(),
        }
    }

    /// Receives `message` and commits whatever state it returns.
    pub fn receive(&mut self, message: &Message) -> InboundMessageOutcome {
        let outcome = self.decrypt(message).unwrap();
        let (outcome, changes) = super::split_changes(outcome);
        if let Some(changes) = changes {
            self.host.commit_changes(changes).unwrap();
        }
        outcome
    }

    /// Decrypts `message` without committing the result.
    pub fn decrypt(&self, message: &Message) -> Result<InboundMessageOutcome, DeviceError> {
        let decryption = self.store.start_decryption(self.incoming(message))?;
        Ok(run_decryption(
            decryption,
            &self.host,
            &mut ChaCha20Rng::from_seed([self.tag ^ 0xff; 32]),
            &binding(),
        )?)
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
        self.store.prepare_accept_session_with_transport_binding(
            SessionAcceptance {
                snapshot: &self.host.snapshot(),
                message,
                settings: self.settings,
                sender_certificate_validation: &self.relay.validation(),
            },
            transport_binding,
            selection,
        )
    }

    fn next_message_id(&mut self) -> MessageId {
        self.next_message += 1;
        let mut id = [self.tag; 16];
        id[..2].copy_from_slice(&self.next_message.to_be_bytes());
        MessageId::from_bytes(id)
    }
}

/// A Message the host committed and queued for sending.
pub struct SentMessage {
    pub session_id: SessionId,
    pub message_id: MessageId,
    pub message: Message,
}

/// Why a Device's Message Operation failed.
#[derive(Debug)]
pub enum DeviceError {
    Start(MessageStartError),
    Operation(MessageOperationError),
}

impl From<MessageStartError> for DeviceError {
    fn from(error: MessageStartError) -> Self {
        Self::Start(error)
    }
}

impl From<MessageOperationError> for DeviceError {
    fn from(error: MessageOperationError) -> Self {
        Self::Operation(error)
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
