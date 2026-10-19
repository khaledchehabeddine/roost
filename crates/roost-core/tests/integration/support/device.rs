//! Devices that send and receive through KeyStore and commit through a host store.

use super::host_identity::DeviceStorage;
use super::{CREATED_AT_SECS, HostCommitError, HostStore, sender_certificate_bytes, validation};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    AdmissionRequest, ContactIdentityKey, ContactState, DeliveryCheckResult, DeliveryCheckStep,
    InboundMessageOutcome, InboundSenderCertificateValidation, IncomingMessage, KeyStore,
    KeyStoreError, KeyStoreOperationError, KnownDomainSigningKey, MessageDecryptionStep,
    MessageDestination, MessageEncryption, MessageEncryptionStep, MessageOperationError,
    MessageRecoveryStep, MessageStartError, OutboundMessageResult, OutgoingGrantUpdate,
    OutgoingMessage, OutgoingRecovery, PeerPreKeyBundle, PreKeyBundle, PreparedKeyStoreOperation,
    ProtocolStateAddress, ProtocolStateBlob, ProtocolStateKind, ProtocolStateUpdate,
    PublicIdentityKey, PublicationBundle, ReceiveSettings, SealedFrame, SessionId,
    SignedSenderCertificate, StateChanges, TransportBinding,
};
use roost_crypto::SigningKeyPair;
use roost_protocol::{DomainSigningKeyStatus, MessageId, PayloadKind};
use std::collections::BTreeMap;
use std::time::Duration;
use zeroize::Zeroizing;

/// The relay that certifies every test Device's Identity Key.
pub(crate) struct Relay {
    domain_id: Vec<u8>,
    signing_key: SigningKeyPair,
}

impl Relay {
    pub(crate) fn new() -> Self {
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
            domain_id: self.domain_id.clone(),
            domain_verifying_key: self.signing_key.verifying.to_bytes(),
        }
    }
}

// A Device's certificate and the relay key that vouches for every Device's certificate.
#[derive(Clone)]
struct Credential {
    certificate: Vec<u8>,
    signature: Vec<u8>,
    domain_id: Vec<u8>,
    domain_verifying_key: [u8; 32],
}

impl Credential {
    fn signed(&self) -> SignedSenderCertificate {
        SignedSenderCertificate {
            certificate: self.certificate.clone(),
            signature: self.signature.clone(),
        }
    }

    fn validation(&self) -> InboundSenderCertificateValidation {
        validation(
            vec![KnownDomainSigningKey {
                id: self.domain_id.clone(),
                verifying_key: self.domain_verifying_key,
                status: DomainSigningKeyStatus::Trusted,
            }],
            Vec::new(),
        )
    }
}

/// What the app asks an encryption to do.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Intent {
    Message,
    Request,
    Acceptance,
    /// A Grant Update, which ignores the draft's plaintext.
    GrantUpdate,
}

/// A sealed Message, the changes to commit with it, and the destination Roost named for it.
pub(crate) struct Sealed {
    pub(crate) result: OutboundMessageResult,
    pub(crate) changes: StateChanges,
    pub(crate) destination: MessageDestination,
}

/// How an encryption ended.
pub(crate) enum Encrypted {
    Ready(Box<Sealed>),
    NeedsPreKeyBundle(ContactIdentityKey),
    NothingToSend,
}

impl Encrypted {
    pub(crate) fn ready(self) -> Sealed {
        match self {
            Self::Ready(sealed) => *sealed,
            Self::NeedsPreKeyBundle(_) | Self::NothingToSend => panic!("expected a sealed Message"),
        }
    }
}

/// A destination's public parts, with the capability reduced to its verifier, so tests can compare
/// destinations.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Route {
    FirstMessage {
        identity_key: ContactIdentityKey,
        discovery_key: [u8; 32],
        signed_prekey_id: u64,
        one_time_prekey_id: Option<u64>,
    },
    Established {
        identity_key: ContactIdentityKey,
        discovery_key: [u8; 32],
        verifier: [u8; 32],
    },
}

impl Route {
    pub(crate) fn of(destination: &MessageDestination) -> Self {
        match destination {
            MessageDestination::FirstMessage {
                identity_key,
                discovery_key,
                signed_prekey_id,
                one_time_prekey_id,
            } => Self::FirstMessage {
                identity_key: *identity_key,
                discovery_key: *discovery_key,
                signed_prekey_id: *signed_prekey_id,
                one_time_prekey_id: *one_time_prekey_id,
            },
            MessageDestination::Established {
                identity_key,
                discovery_key,
                delivery_capability,
            } => Self::Established {
                identity_key: *identity_key,
                discovery_key: *discovery_key,
                verifier: *delivery_capability.verifier().as_bytes(),
            },
        }
    }
}

/// How a decryption ended, the changes to commit with it, and what it asked for on the way.
pub(crate) struct Decrypted {
    pub(crate) outcome: InboundMessageOutcome,
    pub(crate) changes: StateChanges,
    pub(crate) admission: Option<AdmissionRequest>,
    pub(crate) acknowledgment_destination: Option<MessageDestination>,
}

/// One app install: its KeyStore, its host database, and the certificate its relay issued.
pub(crate) struct Device {
    pub(crate) store: KeyStore,
    pub(crate) host: HostStore,
    storage: DeviceStorage,
    pub(crate) identity: PublicIdentityKey,
    credential: Credential,
    /// The settings the app passes with each receive.
    pub(crate) settings: ReceiveSettings,
    /// Whether the Relay's proofs show it admitted the first Messages this Device receives.
    pub(crate) admits: bool,
    /// The app's copy of what each committed send carried, which a recovery encrypts again.
    contents: BTreeMap<[u8; 16], Vec<u8>>,
    next_message: u16,
    tag: u8,
}

pub(crate) fn binding() -> TransportBinding {
    TransportBinding::new(b"test-route".to_vec()).unwrap()
}

impl Device {
    pub(crate) fn new(relay: &Relay, tag: u8) -> Self {
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
            settings: ReceiveSettings::default(),
            admits: true,
            contents: BTreeMap::new(),
            next_message: 0,
            tag,
        }
    }

    pub(crate) fn identity_key(&self) -> ContactIdentityKey {
        identity_key(&self.identity)
    }

    /// Returns another KeyStore over the same SecureStorage, as an app extension runs.
    pub(crate) fn second_instance(&self) -> KeyStore {
        self.storage.open()
    }

    /// Returns this Device as an app extension sees it: another KeyStore over the same
    /// SecureStorage, reading a copy of the same host records.
    pub(crate) fn second_instance_device(&self) -> Device {
        Device {
            store: self.storage.open(),
            host: self.host.clone(),
            storage: self.storage.clone(),
            identity: self.identity.clone(),
            credential: self.credential.clone(),
            settings: self.settings,
            admits: self.admits,
            contents: self.contents.clone(),
            next_message: self.next_message,
            tag: self.tag,
        }
    }

    /// Replaces the KeyStore with a new one over the same SecureStorage, as an app restart does.
    pub(crate) fn restart(&mut self) {
        self.store = self.storage.open();
    }

    /// Forgets the Sessions kept with `peer`, as a host that lost that record does, so the next
    /// request starts a new Session.
    pub(crate) fn forget_sessions_with(&mut self, peer: &Device) {
        let address = self.sessions_address(peer.identity_key());
        self.host.remove(&address);
    }

    /// Returns the address of this Device's contact record for `peer`, as Roost names it.
    pub(crate) fn contact_address(&self, peer: ContactIdentityKey) -> ProtocolStateAddress {
        self.contact_record_address(peer, ProtocolStateKind::ContactState)
    }

    /// Returns the address of this Device's record of the Sessions kept with `peer`, as Roost
    /// names it.
    pub(crate) fn sessions_address(&self, peer: ContactIdentityKey) -> ProtocolStateAddress {
        self.contact_record_address(peer, ProtocolStateKind::PeerSessions)
    }

    // Returns the address of `peer`'s record of `kind`, which a delivery check asks for first.
    fn contact_record_address(
        &self,
        peer: ContactIdentityKey,
        kind: ProtocolStateKind,
    ) -> ProtocolStateAddress {
        let now = std::time::UNIX_EPOCH + Duration::from_secs(CREATED_AT_SECS);
        let mut check = self
            .store
            .protocol_engine()
            .start_delivery_check(peer, now)
            .unwrap();
        let DeliveryCheckStep::NeedsState(addresses) = check.step().unwrap() else {
            panic!("expected a delivery check to read the contact's records first");
        };
        addresses
            .into_iter()
            .find(|address| address.kind() == kind)
            .expect("a delivery check reads each of the contact's records")
    }

    /// Returns the record this Device's host holds for `peer`, if any.
    pub(crate) fn contact_record(&self, peer: ContactIdentityKey) -> Option<ProtocolStateBlob> {
        self.host
            .blob_bytes(&self.contact_address(peer))
            .map(ProtocolStateBlob::from_bytes)
    }

    /// Returns this Device's certificate as its relay issued it.
    pub(crate) fn certificate(&self) -> SignedSenderCertificate {
        self.credential.signed()
    }

    /// Returns a certificate for this Device's Identity Key that expires at `expires_at_secs`.
    pub(crate) fn certified_until(&self, expires_at_secs: u64) -> SignedSenderCertificate {
        super::certificate_until(self.identity_key(), expires_at_secs)
    }

    pub(crate) fn publication(&self) -> PublicationBundle {
        self.store.current_publication().unwrap()
    }

    /// Returns the contact this Device's host holds for `peer`, decoded after commit.
    pub(crate) fn contact(&self, peer: &Device) -> Option<ContactState> {
        let address = self.contact_address(peer.identity_key());
        self.host.blob_bytes(&address).map(|bytes| {
            self.store
                .protocol_engine()
                .decode_contact(&address, &ProtocolStateBlob::from_bytes(bytes))
                .unwrap()
        })
    }

    /// Publishes a bundle with a fresh one-time prekey, as the relay would serve it.
    pub(crate) fn bundle(&self) -> PeerPreKeyBundle {
        let one_time_prekeys = self.store.prepare_one_time_prekeys(1).unwrap();
        finalize(&self.store, &one_time_prekeys);
        self.published(Some(one_time_prekeys.output[0].clone()))
    }

    /// Publishes a bundle after one-time prekeys run out, so only the signed prekey is used.
    pub(crate) fn bundle_without_one_time_prekey(&self) -> PeerPreKeyBundle {
        self.published(None)
    }

    fn published(
        &self,
        one_time_prekey: Option<roost_core::PublicOneTimePreKey>,
    ) -> PeerPreKeyBundle {
        let publication = self.publication();
        PeerPreKeyBundle {
            identity_key: self.identity.clone(),
            discovery_to_identity: publication.discovery_to_identity,
            bundle: PreKeyBundle {
                version: publication.version,
                discovery_key: publication.discovery_key,
                signed_prekey: publication.signed_prekey,
                one_time_prekey,
            },
        }
    }

    /// Returns where `peer`'s established Messages go: its current Discovery Key and inbox.
    pub(crate) fn established_route(&self) -> Route {
        let publication = self.publication();
        Route::Established {
            identity_key: self.identity_key(),
            discovery_key: *publication.discovery_key.public_key.as_bytes(),
            verifier: *publication.recipient_delivery_verifier.as_bytes(),
        }
    }

    /// Encrypts an ordinary Message for `peer` under a new draft MessageID without committing it.
    pub(crate) fn encrypt_to(
        &mut self,
        peer: &Device,
        plaintext: &[u8],
    ) -> Result<Sealed, DeviceError> {
        let outgoing = self.outgoing(peer, plaintext);
        Ok(self.encrypt(outgoing, Intent::Message)?.ready())
    }

    /// Returns what the app passes to send `plaintext` to `peer` under a new draft MessageID.
    pub(crate) fn outgoing(&mut self, peer: &Device, plaintext: &[u8]) -> OutgoingMessage {
        let message_id = self.next_message_id();
        OutgoingMessage {
            recipient: peer.identity_key(),
            message_id,
            sent_at_millis: sent_at_millis(message_id),
            sender_certificate: self.credential.signed(),
            plaintext: Zeroizing::new(plaintext.to_vec()),
            prekey_bundle: None,
        }
    }

    /// Asks `peer` to become a contact with a freshly fetched bundle, and commits the request.
    pub(crate) fn request(&mut self, peer: &Device, plaintext: &[u8]) -> SentMessage {
        let mut outgoing = self.outgoing(peer, plaintext);
        outgoing.prekey_bundle = Some(peer.bundle());
        self.send_with(outgoing, Intent::Request)
    }

    /// Accepts `peer`'s Contact Request and commits the acceptance.
    pub(crate) fn accept_request(&mut self, peer: &Device, plaintext: &[u8]) -> SentMessage {
        let outgoing = self.outgoing(peer, plaintext);
        self.send_with(outgoing, Intent::Acceptance)
    }

    /// Sends to `peer` on whichever Session Roost selects, and commits it.
    pub(crate) fn send(&mut self, peer: &Device, plaintext: &[u8]) -> SentMessage {
        let outgoing = self.outgoing(peer, plaintext);
        self.send_with(outgoing, Intent::Message)
    }

    /// Sends `peer` a Grant Update and commits it.
    pub(crate) fn send_grant_update(&mut self, peer: &Device) -> SentMessage {
        let outgoing = self.outgoing(peer, b"");
        self.send_with(outgoing, Intent::GrantUpdate)
    }

    /// Encrypts `outgoing` as `intent` and commits the sealed Message.
    pub(crate) fn send_with(&mut self, outgoing: OutgoingMessage, intent: Intent) -> SentMessage {
        self.contents
            .insert(*outgoing.message_id.as_bytes(), outgoing.plaintext.to_vec());
        let sealed = self.encrypt(outgoing, intent).unwrap().ready();
        self.commit_sent(sealed)
    }

    // Commits `sealed` and queues its Message.
    fn commit_sent(&mut self, sealed: Sealed) -> SentMessage {
        let Sealed {
            result,
            changes,
            destination,
        } = sealed;
        self.host.commit_sent(&result, changes).unwrap();
        SentMessage {
            session_id: result.session_id,
            message_id: result.message_id,
            payload_kind: result.payload_kind,
            message: result.message,
            destination,
        }
    }

    /// Encrypts `outgoing` as `intent` without committing the result.
    pub(crate) fn encrypt(
        &self,
        outgoing: OutgoingMessage,
        intent: Intent,
    ) -> Result<Encrypted, DeviceError> {
        let seed = self.tag ^ outgoing.message_id.as_bytes()[1];
        let encryption = match intent {
            Intent::Message => self.store.start_encryption(outgoing),
            Intent::Request => self.store.request_contact(outgoing),
            Intent::Acceptance => self.store.accept_contact(outgoing),
            Intent::GrantUpdate => self.store.start_grant_update(OutgoingGrantUpdate {
                recipient: outgoing.recipient,
                message_id: outgoing.message_id,
                sent_at_millis: outgoing.sent_at_millis,
                sender_certificate: outgoing.sender_certificate,
                prekey_bundle: outgoing.prekey_bundle,
            }),
        }?;
        Ok(run_encryption(
            encryption,
            &self.host,
            &mut ChaCha20Rng::from_seed([seed; 32]),
            &binding(),
        )?)
    }

    /// Checks the delivery of what this Device sent `peer` at `now_millis`, and commits the
    /// result.
    pub(crate) fn check_deliveries(
        &mut self,
        peer: &Device,
        now_millis: u64,
    ) -> DeliveryCheckResult {
        let now = std::time::UNIX_EPOCH + Duration::from_millis(now_millis);
        let mut check = self
            .store
            .protocol_engine()
            .start_delivery_check(peer.identity_key(), now)
            .unwrap();
        loop {
            match check.step().unwrap() {
                DeliveryCheckStep::NeedsState(addresses) => {
                    check.supply_state(self.host.read(&addresses)).unwrap();
                }
                DeliveryCheckStep::Ready { result, changes } => {
                    self.commit_changes(changes).unwrap();
                    return result;
                }
            }
        }
    }

    /// Runs one recovery of what this Device sent `peer`, supplying the app's copy of each
    /// Message's content and `prekey_bundle`, and commits a resent Message.
    pub(crate) fn recover(
        &mut self,
        peer: &Device,
        prekey_bundle: Option<PeerPreKeyBundle>,
    ) -> Recovered {
        match self.observe_recovery(peer, prekey_bundle).unwrap() {
            Recovered::Resent(sealed) => Recovered::Committed(Box::new(self.commit_sent(*sealed))),
            other @ (Recovered::Committed(_)
            | Recovered::NeedsPreKeyBundle
            | Recovered::AwaitingProbe(_)
            | Recovered::Finished) => other,
        }
    }

    /// Runs one recovery of what this Device sent `peer` without committing.
    pub(crate) fn observe_recovery(
        &self,
        peer: &Device,
        prekey_bundle: Option<PeerPreKeyBundle>,
    ) -> Result<Recovered, DeviceError> {
        let mut recovery = self.store.start_recovery(OutgoingRecovery {
            recipient: peer.identity_key(),
            sender_certificate: self.credential.signed(),
            prekey_bundle,
        })?;
        let mut rng = ChaCha20Rng::from_seed([self.tag ^ 0x7e; 32]);
        let mut destination = None;
        loop {
            match recovery.step(&mut rng)? {
                MessageRecoveryStep::NeedsState(addresses) => {
                    recovery.supply_state(self.host.read(&addresses))?;
                }
                MessageRecoveryStep::NeedsContent(message_id) => {
                    let content = self.contents[message_id.as_bytes()].clone();
                    recovery.supply_content(Zeroizing::new(content))?;
                }
                MessageRecoveryStep::NeedsTransport(asked) => {
                    destination = Some(asked);
                    recovery.supply_transport_binding(binding())?;
                }
                MessageRecoveryStep::NeedsPreKeyBundle(_) => {
                    return Ok(Recovered::NeedsPreKeyBundle);
                }
                MessageRecoveryStep::AwaitingProbe(message_id) => {
                    return Ok(Recovered::AwaitingProbe(message_id));
                }
                MessageRecoveryStep::Finished => return Ok(Recovered::Finished),
                MessageRecoveryStep::Ready { result, changes } => {
                    let destination = destination.expect("a resent Message names its destination");
                    return Ok(Recovered::Resent(Box::new(Sealed {
                        result: *result,
                        changes,
                        destination,
                    })));
                }
            }
        }
    }

    /// Returns what the app passes to receive `message` with this Device's settings.
    pub(crate) fn incoming(&self, message: &SealedFrame) -> IncomingMessage {
        IncomingMessage {
            message: message.clone(),
            transport_binding: binding(),
            settings: self.settings,
            sender_certificate_validation: self.credential.validation(),
            acknowledgment_sent_at_millis: CREATED_AT_SECS * 1000,
            acknowledgment_sender_certificate: self.credential.signed(),
        }
    }

    /// Receives `message` and commits the state it returns.
    pub(crate) fn receive(&mut self, message: &SealedFrame) -> InboundMessageOutcome {
        let decrypted = self.observe(message).unwrap();
        self.commit_changes(decrypted.changes).unwrap();
        decrypted.outcome
    }

    /// Decrypts `message` without committing the result.
    pub(crate) fn decrypt(
        &self,
        message: &SealedFrame,
    ) -> Result<InboundMessageOutcome, DeviceError> {
        Ok(self.observe(message)?.outcome)
    }

    /// Decrypts `message` without committing the result, and reports what the operation asked for.
    pub(crate) fn observe(&self, message: &SealedFrame) -> Result<Decrypted, DeviceError> {
        let mut decryption = self.store.start_decryption(self.incoming(message))?;
        // Each Message's ephemeral key varies the seed, so each ratchet step draws new keys.
        let mut seed = message.ephemeral_public_key;
        seed[0] ^= self.tag;
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut admission = None;
        let mut acknowledgment_destination = None;
        loop {
            match decryption.step(&mut rng)? {
                MessageDecryptionStep::NeedsState(addresses) => {
                    decryption.supply_state(self.host.read(&addresses))?;
                }
                MessageDecryptionStep::NeedsAdmission(request) => {
                    admission = Some(request);
                    if !self.admits {
                        return Err(DeviceError::NotAdmitted(request));
                    }
                    decryption.confirm_admission()?;
                }
                MessageDecryptionStep::NeedsAcknowledgmentTransport(destination) => {
                    acknowledgment_destination = Some(destination);
                    decryption.supply_acknowledgment_transport_binding(binding())?;
                }
                MessageDecryptionStep::Ready { outcome, changes } => {
                    return Ok(Decrypted {
                        outcome,
                        changes,
                        admission,
                        acknowledgment_destination,
                    });
                }
            }
        }
    }

    /// Commits `changes`, reserving and finalizing the operation they carry around the host
    /// transaction, and aborting it when a condition fails. Returns the updates it wrote.
    pub(crate) fn commit_changes(
        &mut self,
        changes: StateChanges,
    ) -> Result<Vec<ProtocolStateUpdate>, HostCommitError> {
        let Some(operation) = changes.operation() else {
            return self.host.commit(changes);
        };
        // SecureStorage changed since preparation, so the result is stale like a failed condition.
        if let Err(KeyStoreError::Operation(KeyStoreOperationError::PreconditionChanged {
            ..
        })) = self.store.reserve_operation(operation)
        {
            self.store.abort_operation(operation).unwrap();
            return Err(HostCommitError::StaleCondition);
        }
        match self.host.commit(changes) {
            Ok(updates) => {
                self.store.finalize_operation(operation).unwrap();
                Ok(updates)
            }
            Err(error) => {
                self.store.abort_operation(operation).unwrap();
                Err(error)
            }
        }
    }

    /// Blocks `peer`, given whatever record this Device holds for them, and commits the block.
    pub(crate) fn block(&mut self, peer: ContactIdentityKey) -> Option<PublicationBundle> {
        let record = self.contact_record(peer);
        let block = self
            .store
            .prepare_block_contact(peer, record.as_ref())
            .unwrap();
        self.commit_changes(block.changes).unwrap();
        block.publication
    }

    /// Unblocks `peer`, given whatever record this Device holds for them, and commits it.
    pub(crate) fn unblock(&mut self, peer: ContactIdentityKey) {
        let record = self.contact_record(peer);
        let changes = self
            .store
            .protocol_engine()
            .unblock_contact(peer, record.as_ref())
            .unwrap();
        self.commit_changes(changes).unwrap();
    }

    /// Deletes the Deduplication Set, as if every recorded digest had aged out.
    pub(crate) fn forget_received_digests(&mut self) {
        let address = self.host.only(ProtocolStateKind::DeduplicationSet);
        self.host.remove(&address);
    }

    /// Rotates the inbox outside any block, and returns the new publication.
    pub(crate) fn rotate_inbox(&self) -> PublicationBundle {
        let rotation = self.store.prepare_inbox_rotation().unwrap();
        finalize(&self.store, &rotation);
        rotation.output
    }

    fn next_message_id(&mut self) -> MessageId {
        self.next_message += 1;
        let mut id = [self.tag; 16];
        id[..2].copy_from_slice(&self.next_message.to_be_bytes());
        MessageId::from_bytes(id)
    }
}

/// Runs `encryption` over `host`'s records, supplying `binding` when it asks for a transport, and
/// returns the destination it named.
pub(crate) fn run_encryption(
    mut encryption: MessageEncryption,
    host: &HostStore,
    rng: &mut ChaCha20Rng,
    binding: &TransportBinding,
) -> Result<Encrypted, MessageOperationError> {
    let mut destination = None;
    loop {
        match encryption.step(rng)? {
            MessageEncryptionStep::NeedsState(addresses) => {
                encryption.supply_state(host.read(&addresses))?;
            }
            MessageEncryptionStep::NeedsTransport(asked) => {
                destination = Some(asked);
                encryption.supply_transport_binding(binding.clone())?;
            }
            MessageEncryptionStep::NeedsPreKeyBundle(identity_key) => {
                return Ok(Encrypted::NeedsPreKeyBundle(identity_key));
            }
            MessageEncryptionStep::NothingToSend => return Ok(Encrypted::NothingToSend),
            MessageEncryptionStep::Ready { result, changes } => {
                let destination = destination.expect("a sealed Message names its destination");
                return Ok(Encrypted::Ready(Box::new(Sealed {
                    result: *result,
                    changes,
                    destination,
                })));
            }
        }
    }
}

/// How one recovery ended.
pub(crate) enum Recovered {
    /// A Message encrypted again and not yet committed.
    Resent(Box<Sealed>),
    /// A Message encrypted again, committed, and queued for sending.
    Committed(Box<SentMessage>),
    NeedsPreKeyBundle,
    AwaitingProbe(MessageId),
    Finished,
}

impl Recovered {
    pub(crate) fn committed(self) -> SentMessage {
        match self {
            Self::Committed(sent) => *sent,
            Self::Resent(_) | Self::NeedsPreKeyBundle | Self::AwaitingProbe(_) | Self::Finished => {
                panic!("expected a committed resend")
            }
        }
    }
}

/// A Message the host committed and queued for sending.
pub(crate) struct SentMessage {
    pub(crate) session_id: SessionId,
    pub(crate) message_id: MessageId,
    pub(crate) payload_kind: PayloadKind,
    pub(crate) message: SealedFrame,
    pub(crate) destination: MessageDestination,
}

/// Why a Device's Message Operation failed.
#[derive(Debug)]
pub(crate) enum DeviceError {
    Operation(MessageOperationError),
    NotAdmitted(AdmissionRequest),
}

impl From<MessageStartError> for DeviceError {
    fn from(error: MessageStartError) -> Self {
        Self::Operation(super::start_failure(error))
    }
}

impl From<MessageOperationError> for DeviceError {
    fn from(error: MessageOperationError) -> Self {
        Self::Operation(error)
    }
}

/// Alice asks Bob, and Bob receives the request.
pub(crate) fn requested(relay: &Relay) -> (Device, Device) {
    let mut alice = Device::new(relay, 0xa1);
    let mut bob = Device::new(relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");
    assert!(matches!(
        bob.receive(&request.message),
        InboundMessageOutcome::ContactRequest(_)
    ));
    (alice, bob)
}

/// Alice asks Bob, Bob accepts, and Alice receives the acceptance and acknowledges it.
pub(crate) fn befriended(relay: &Relay) -> (Device, Device) {
    let (mut alice, mut bob) = requested(relay);
    let acceptance = bob.accept_request(&alice, b"welcome");
    let acknowledgment = super::accepted(alice.receive(&acceptance.message))
        .acknowledgment
        .unwrap();
    assert!(matches!(
        bob.receive(&acknowledgment),
        InboundMessageOutcome::AcknowledgmentMatched(_)
    ));
    (alice, bob)
}

/// Returns the verifier of the capability an established destination carries.
pub(crate) fn established_verifier(
    destination: &MessageDestination,
) -> roost_crypto::RecipientDeliveryVerifier {
    match destination {
        MessageDestination::Established {
            delivery_capability,
            ..
        } => delivery_capability.verifier(),
        MessageDestination::FirstMessage { .. } => panic!("expected an established Message"),
    }
}

/// Returns the same draft again, as an app restarts an attempt, without a bundle.
pub(crate) fn redraft(draft: &OutgoingMessage) -> OutgoingMessage {
    OutgoingMessage {
        recipient: draft.recipient,
        message_id: draft.message_id,
        sent_at_millis: draft.sent_at_millis,
        sender_certificate: SignedSenderCertificate {
            certificate: draft.sender_certificate.certificate.clone(),
            signature: draft.sender_certificate.signature.clone(),
        },
        plaintext: draft.plaintext.clone(),
        prekey_bundle: None,
    }
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
    store.reserve_operation(prepared.id).unwrap();
    store.finalize_operation(prepared.id).unwrap();
}
