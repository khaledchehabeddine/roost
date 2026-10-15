//! Devices that send and receive through KeyStore and commit through a host store.

use super::host_identity::DeviceStorage;
use super::{
    CREATED_AT_SECS, HostCommitError, HostStore, deduplication_address, sender_certificate_bytes,
    validation,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    AdmissionRequest, ContactIdentityKey, ContactState, DeliveryCheckResult, DeliveryCheckStep,
    InboundMessageOutcome, InboundSenderCertificateValidation, IncomingMessage, KeyStore,
    KeyStoreError, KeyStoreOperationError, KnownDomainSigningKey, Message, MessageDecryptionStep,
    MessageDestination, MessageEncryption, MessageEncryptionStep, MessageOperationError,
    MessageRecoveryStep, MessageStartError, OutboundMessageResult, OutgoingGrantUpdate,
    OutgoingMessage, OutgoingRecovery, PeerPreKeyBundle, PreKeyBundle, PreparedKeyStoreOperation,
    ProtocolStateAddress, ProtocolStateKey, ProtocolStateKind, PublicIdentityKey,
    PublicationBundle, ReceiveSettings, SessionId, SignedSenderCertificate, StateChanges,
    TransportBinding,
};
use roost_crypto::SigningKeyPair;
use roost_protocol::{DomainSigningKeyStatus, MessageId, PayloadKind};
use std::collections::BTreeMap;
use std::time::Duration;
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
pub enum Intent {
    Message,
    Request,
    Acceptance,
    /// A Grant Update, which ignores the draft's plaintext.
    GrantUpdate,
}

/// How an encryption ended.
pub enum Encrypted {
    Ready(Box<(OutboundMessageResult, MessageDestination)>),
    NeedsPreKeyBundle(ContactIdentityKey),
    NothingToSend,
}

impl Encrypted {
    pub fn ready(self) -> (OutboundMessageResult, MessageDestination) {
        match self {
            Self::Ready(sealed) => *sealed,
            Self::NeedsPreKeyBundle(_) | Self::NothingToSend => panic!("expected a sealed Message"),
        }
    }
}

/// A destination's public parts, with the capability reduced to its verifier, so tests can compare
/// destinations.
#[derive(Debug, Eq, PartialEq)]
pub enum Route {
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
    pub fn of(destination: &MessageDestination) -> Self {
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

/// How a decryption ended, with what it asked for on the way.
pub struct Decrypted {
    pub outcome: InboundMessageOutcome,
    pub admission: Option<AdmissionRequest>,
    pub acknowledgment_destination: Option<MessageDestination>,
}

/// One app install: its KeyStore, its host database, and the certificate its relay issued.
pub struct Device {
    pub store: KeyStore,
    pub host: HostStore,
    storage: DeviceStorage,
    pub identity: PublicIdentityKey,
    credential: Credential,
    /// The settings the app passes with each receive.
    pub settings: ReceiveSettings,
    /// Whether the Relay's proofs show it admitted the first Messages this Device receives.
    pub admits: bool,
    /// The app's copy of what each committed send carried, which a recovery encrypts again.
    contents: BTreeMap<[u8; 16], Vec<u8>>,
    next_message: u16,
    tag: u8,
}

pub fn binding() -> TransportBinding {
    TransportBinding::new(b"test-route".to_vec()).unwrap()
}

impl Device {
    pub fn new(relay: &Relay, tag: u8) -> Self {
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

    pub fn identity_key(&self) -> ContactIdentityKey {
        identity_key(&self.identity)
    }

    /// Returns another KeyStore over the same SecureStorage, as an app extension runs.
    pub fn second_instance(&self) -> KeyStore {
        self.storage.open()
    }

    /// Returns this Device as an app extension sees it: another KeyStore over the same
    /// SecureStorage, reading a copy of the same host records.
    pub fn second_instance_device(&self) -> Device {
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
    pub fn restart(&mut self) {
        self.store = self.storage.open();
    }

    /// Returns this Device's current Discovery Key, read from its SecureStorage as an attacker who
    /// stole it would hold it.
    pub fn discovery_key(&self) -> roost_crypto::DiscoveryKey {
        use roost_core::SecureStorage as _;
        let blob = self.storage.load("discovery/current").unwrap().unwrap();
        let field = |range: std::ops::Range<usize>| blob[range].to_vec();
        roost_crypto::DiscoveryKey::from_secret_bytes(
            field(5..37).try_into().unwrap(),
            field(37..69).try_into().unwrap(),
            u32::from_be_bytes(field(1..5).try_into().unwrap()),
            u64::from_be_bytes(field(133..141).try_into().unwrap()),
            field(69..133).try_into().unwrap(),
        )
    }

    /// Forgets the Sessions kept with `peer`, as a host that lost that record does, so the next
    /// request starts a new Session.
    pub fn forget_sessions_with(&mut self, peer: &Device) {
        self.host
            .remove(&peer_sessions_address(peer.identity_key()));
    }

    /// Returns this Device's certificate as its relay issued it.
    pub fn certificate(&self) -> SignedSenderCertificate {
        self.credential.signed()
    }

    /// Returns a certificate for this Device's Identity Key that expires at `expires_at_secs`.
    pub fn certified_until(&self, expires_at_secs: u64) -> SignedSenderCertificate {
        super::certificate_until(self.identity_key(), expires_at_secs)
    }

    pub fn publication(&self) -> PublicationBundle {
        self.store.current_publication().unwrap()
    }

    /// Returns the contact this Device's host holds for `peer`, decoded after commit.
    pub fn contact(&self, peer: &Device) -> Option<ContactState> {
        let address = contact_address(peer.identity_key());
        self.host.blob_bytes(&address).map(|bytes| {
            self.store
                .protocol_engine()
                .decode_contact(&address, &roost_core::ProtocolStateBlob::from_bytes(bytes))
                .unwrap()
        })
    }

    /// Publishes a bundle with a fresh one-time prekey, as the relay would serve it.
    pub fn bundle(&self) -> PeerPreKeyBundle {
        let one_time_prekeys = self.store.prepare_one_time_prekeys(1).unwrap();
        finalize(&self.store, &one_time_prekeys);
        self.published(Some(one_time_prekeys.output[0].clone()))
    }

    /// Publishes a bundle after one-time prekeys run out, so only the signed prekey is used.
    pub fn bundle_without_one_time_prekey(&self) -> PeerPreKeyBundle {
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
    pub fn established_route(&self) -> Route {
        let publication = self.publication();
        Route::Established {
            identity_key: self.identity_key(),
            discovery_key: *publication.discovery_key.public_key.as_bytes(),
            verifier: *publication.recipient_delivery_verifier.as_bytes(),
        }
    }

    /// Encrypts an ordinary Message for `peer` under a new draft MessageID without committing it.
    pub fn encrypt_to(
        &mut self,
        peer: &Device,
        plaintext: &[u8],
    ) -> Result<OutboundMessageResult, DeviceError> {
        let outgoing = self.outgoing(peer, plaintext);
        Ok(self.encrypt(outgoing, Intent::Message)?.ready().0)
    }

    /// Returns what the app passes to send `plaintext` to `peer` under a new draft MessageID.
    pub fn outgoing(&mut self, peer: &Device, plaintext: &[u8]) -> OutgoingMessage {
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
    pub fn request(&mut self, peer: &Device, plaintext: &[u8]) -> SentMessage {
        let mut outgoing = self.outgoing(peer, plaintext);
        outgoing.prekey_bundle = Some(peer.bundle());
        self.send_with(outgoing, Intent::Request)
    }

    /// Accepts `peer`'s Contact Request and commits the acceptance.
    pub fn accept_request(&mut self, peer: &Device, plaintext: &[u8]) -> SentMessage {
        let outgoing = self.outgoing(peer, plaintext);
        self.send_with(outgoing, Intent::Acceptance)
    }

    /// Sends to `peer` on whichever Session Roost selects, and commits it.
    pub fn send(&mut self, peer: &Device, plaintext: &[u8]) -> SentMessage {
        let outgoing = self.outgoing(peer, plaintext);
        self.send_with(outgoing, Intent::Message)
    }

    /// Sends `peer` a Grant Update and commits it.
    pub fn send_grant_update(&mut self, peer: &Device) -> SentMessage {
        let outgoing = self.outgoing(peer, b"");
        self.send_with(outgoing, Intent::GrantUpdate)
    }

    /// Encrypts `outgoing` as `intent` and commits the sealed Message.
    pub fn send_with(&mut self, outgoing: OutgoingMessage, intent: Intent) -> SentMessage {
        self.contents
            .insert(*outgoing.message_id.as_bytes(), outgoing.plaintext.to_vec());
        let (result, destination) = self.encrypt(outgoing, intent).unwrap().ready();
        let sent = SentMessage {
            session_id: result.session_id,
            message_id: result.message_id,
            payload_kind: result.payload_kind,
            message: super::copy(&result.message),
            destination,
        };
        self.host.commit_sent(result).unwrap();
        sent
    }

    /// Encrypts `outgoing` as `intent` without committing the result.
    pub fn encrypt(
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
        )?)
    }

    /// Checks the delivery of what this Device sent `peer` at `now_millis`, and commits the
    /// result.
    pub fn check_deliveries(&mut self, peer: &Device, now_millis: u64) -> DeliveryCheckResult {
        let mut result = self.observe_deliveries(peer, now_millis).unwrap();
        let changes = std::mem::replace(&mut result.changes, StateChanges::from(Vec::new()));
        self.commit_changes(changes).unwrap();
        result
    }

    /// Checks the delivery of what this Device sent `peer` at `now_millis` without committing.
    pub fn observe_deliveries(
        &self,
        peer: &Device,
        now_millis: u64,
    ) -> Result<DeliveryCheckResult, MessageOperationError> {
        let now = std::time::UNIX_EPOCH + Duration::from_millis(now_millis);
        let mut check = self
            .store
            .protocol_engine()
            .start_delivery_check(peer.identity_key(), now)?;
        loop {
            match check.step()? {
                DeliveryCheckStep::NeedsState(addresses) => {
                    check.supply_state(self.host.read(&addresses))?;
                }
                DeliveryCheckStep::Ready(result) => return Ok(*result),
            }
        }
    }

    /// Runs one recovery of what this Device sent `peer`, supplying the app's copy of each
    /// Message's content and `prekey_bundle`, and commits a resent Message.
    pub fn recover(&mut self, peer: &Device, prekey_bundle: Option<PeerPreKeyBundle>) -> Recovered {
        match self.observe_recovery(peer, prekey_bundle).unwrap() {
            Recovered::Resent(sent) => {
                let (result, destination) = *sent;
                let resent = SentMessage {
                    session_id: result.session_id,
                    message_id: result.message_id,
                    payload_kind: result.payload_kind,
                    message: super::copy(&result.message),
                    destination,
                };
                self.host.commit_sent(result).unwrap();
                Recovered::Committed(Box::new(resent))
            }
            other @ (Recovered::Committed(_)
            | Recovered::NeedsPreKeyBundle
            | Recovered::AwaitingProbe(_)
            | Recovered::Finished) => other,
        }
    }

    /// Runs one recovery of what this Device sent `peer` without committing.
    pub fn observe_recovery(
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
                MessageRecoveryStep::Ready(result) => {
                    let destination = destination.expect("a resent Message names its destination");
                    return Ok(Recovered::Resent(Box::new((*result, destination))));
                }
            }
        }
    }

    /// Returns what the app passes to receive `message` with this Device's settings.
    pub fn incoming(&self, message: &Message) -> IncomingMessage {
        IncomingMessage {
            message: super::copy(message),
            transport_binding: binding(),
            settings: self.settings,
            sender_certificate_validation: self.credential.validation(),
            acknowledgment_sent_at_millis: CREATED_AT_SECS * 1000,
            acknowledgment_sender_certificate: self.credential.signed(),
        }
    }

    /// Receives `message` and commits whatever state it returns.
    pub fn receive(&mut self, message: &Message) -> InboundMessageOutcome {
        let outcome = self.decrypt(message).unwrap();
        let (outcome, changes) = super::split_changes(outcome);
        if let Some(changes) = changes {
            self.commit_changes(changes).unwrap();
        }
        outcome
    }

    /// Decrypts `message` without committing the result.
    pub fn decrypt(&self, message: &Message) -> Result<InboundMessageOutcome, DeviceError> {
        Ok(self.observe(message)?.outcome)
    }

    /// Decrypts `message` without committing the result, and reports what the operation asked for.
    pub fn observe(&self, message: &Message) -> Result<Decrypted, DeviceError> {
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
                MessageDecryptionStep::Ready(outcome) => {
                    return Ok(Decrypted {
                        outcome: *outcome,
                        admission,
                        acknowledgment_destination,
                    });
                }
            }
        }
    }

    /// Commits `changes`, reserving and finalizing the operation they carry around the host
    /// transaction, and aborting it when a condition fails.
    pub fn commit_changes(&mut self, changes: StateChanges) -> Result<(), HostCommitError> {
        let Some(operation) = changes.operation() else {
            return self.host.commit_changes(changes);
        };
        // SecureStorage changed since preparation, so the result is stale like a failed condition.
        if let Err(KeyStoreError::Operation(KeyStoreOperationError::PreconditionChanged {
            ..
        })) = self.store.reserve_operation(operation)
        {
            self.store.abort_operation(operation).unwrap();
            return Err(HostCommitError::StaleCondition);
        }
        match self.host.commit_changes(changes) {
            Ok(()) => {
                self.store.finalize_operation(operation).unwrap();
                Ok(())
            }
            Err(error) => {
                self.store.abort_operation(operation).unwrap();
                Err(error)
            }
        }
    }

    /// Blocks `peer`, given whatever record this Device holds for them, and commits the block.
    pub fn block(&mut self, peer: ContactIdentityKey) -> Option<PublicationBundle> {
        let address = contact_address(peer);
        let record = self
            .host
            .blob_bytes(&address)
            .map(roost_core::ProtocolStateBlob::from_bytes);
        let block = self
            .store
            .prepare_block_contact(peer, record.as_ref())
            .unwrap();
        self.commit_changes(block.changes).unwrap();
        block.publication
    }

    /// Unblocks `peer`, given whatever record this Device holds for them, and commits it.
    pub fn unblock(&mut self, peer: ContactIdentityKey) {
        let record = self
            .host
            .blob_bytes(&contact_address(peer))
            .map(roost_core::ProtocolStateBlob::from_bytes);
        let changes = self
            .store
            .protocol_engine()
            .unblock_contact(peer, record.as_ref())
            .unwrap();
        self.commit_changes(changes).unwrap();
    }

    /// Deletes the Deduplication Set, as if every recorded digest had aged out.
    pub fn forget_received_digests(&mut self) {
        self.host.remove(&deduplication_address());
    }

    /// Rotates the inbox outside any block, and returns the new publication.
    pub fn rotate_inbox(&self) -> PublicationBundle {
        let rotation = self.store.prepare_inbox_rotation().unwrap();
        finalize(&self.store, &rotation);
        rotation.output
    }

    /// Returns whether this Device's record for `peer` holds a Delivery Capability, read from the
    /// stored record as a modified client could read it.
    pub fn holds_capability_for(&self, peer: &Device) -> bool {
        let blob = self
            .host
            .blob_bytes(&contact_address(peer.identity_key()))
            .unwrap();
        let (record, _): (ContactRecordPrefixWire, _) =
            postcard::take_from_bytes(&blob[1..]).unwrap();
        record.delivery_capability.is_some()
    }

    fn next_message_id(&mut self) -> MessageId {
        self.next_message += 1;
        let mut id = [self.tag; 16];
        id[..2].copy_from_slice(&self.next_message.to_be_bytes());
        MessageId::from_bytes(id)
    }
}

/// Runs `encryption` over `host`'s records, supplying the test binding when it asks for a
/// transport, and returns the destination it named.
pub fn run_encryption(
    mut encryption: MessageEncryption,
    host: &HostStore,
    rng: &mut ChaCha20Rng,
) -> Result<Encrypted, MessageOperationError> {
    let mut destination = None;
    loop {
        match encryption.step(rng)? {
            MessageEncryptionStep::NeedsState(addresses) => {
                encryption.supply_state(host.read(&addresses))?;
            }
            MessageEncryptionStep::NeedsTransport(asked) => {
                destination = Some(asked);
                encryption.supply_transport_binding(binding())?;
            }
            MessageEncryptionStep::NeedsPreKeyBundle(identity_key) => {
                return Ok(Encrypted::NeedsPreKeyBundle(identity_key));
            }
            MessageEncryptionStep::NothingToSend => return Ok(Encrypted::NothingToSend),
            MessageEncryptionStep::Ready(result) => {
                let destination = destination.expect("a sealed Message names its destination");
                return Ok(Encrypted::Ready(Box::new((*result, destination))));
            }
        }
    }
}

/// How one recovery ended.
pub enum Recovered {
    /// A Message encrypted again and not yet committed.
    Resent(Box<(OutboundMessageResult, MessageDestination)>),
    /// A Message encrypted again, committed, and queued for sending.
    Committed(Box<SentMessage>),
    NeedsPreKeyBundle,
    AwaitingProbe(MessageId),
    Finished,
}

impl Recovered {
    pub fn committed(self) -> SentMessage {
        match self {
            Self::Committed(sent) => *sent,
            Self::Resent(_) | Self::NeedsPreKeyBundle | Self::AwaitingProbe(_) | Self::Finished => {
                panic!("expected a committed resend")
            }
        }
    }
}

/// A Message the host committed and queued for sending.
pub struct SentMessage {
    pub session_id: SessionId,
    pub message_id: MessageId,
    pub payload_kind: PayloadKind,
    pub message: Message,
    pub destination: MessageDestination,
}

/// Why a Device's Message Operation failed.
#[derive(Debug)]
pub enum DeviceError {
    Start(MessageStartError),
    Operation(MessageOperationError),
    NotAdmitted(AdmissionRequest),
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

// The start of a contact record, up to the peer's Delivery Capability.
#[derive(serde::Deserialize)]
struct ContactRecordPrefixWire {
    _identity_x25519_public_key: [u8; 32],
    _identity_ed25519_verifying_key: [u8; 32],
    _discovery_key: Option<DiscoveryKeyWire>,
    delivery_capability: Option<[u8; 32]>,
}

// A Discovery Key's public keys, epoch, creation time, and identity signature.
type DiscoveryKeyWire = ([u8; 32], [u8; 32], u32, u64, Vec<u8>);

/// Alice asks Bob, and Bob receives the request.
pub fn requested(relay: &Relay) -> (Device, Device) {
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
pub fn befriended(relay: &Relay) -> (Device, Device) {
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
pub fn established_verifier(
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
pub fn redraft(draft: &OutgoingMessage) -> OutgoingMessage {
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

/// The address of the record of the Sessions kept with `identity_key`.
pub fn peer_sessions_address(identity_key: ContactIdentityKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(
        ProtocolStateKind::PeerSessions,
        ProtocolStateKey::from(identity_key),
    )
}

/// The address of the contact record for `identity_key`.
pub fn contact_address(identity_key: ContactIdentityKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(
        ProtocolStateKind::ContactState,
        ProtocolStateKey::from(identity_key),
    )
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
