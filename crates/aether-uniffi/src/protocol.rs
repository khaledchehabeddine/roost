//! UniFFI protocol-state objects, records, and host persistence boundary.

use crate::error::AetherError;
use crate::message::{Message, PayloadKind, SenderIdentityMaterial};
use crate::records::{fixed_32, fixed_64};
use aether_core::{
    ContactSafetyNumberConfirmation as CoreSafetyNumberConfirmation,
    ContactStateChange as CoreContactStateChange, EventStreamError,
    ProtocolStateAddress as CoreProtocolStateAddress, ProtocolStateBlob as CoreProtocolStateBlob,
    ProtocolStateEngine as CoreProtocolStateEngine, ProtocolStateKey as CoreProtocolStateKey,
    ProtocolStateSnapshot as CoreProtocolStateSnapshot,
    ProtocolStateUpdate as CoreProtocolStateUpdate,
};
use aether_crypto::RecipientDeliveryCapability as CoreRecipientDeliveryCapability;
use rand::rngs::OsRng;
use std::sync::Arc;
use zeroize::Zeroizing;

const PROTOCOL_STATE_COMMIT_DIGEST_CONTEXT: &[u8] = b"AetherProtocolStateCommit-v1:";

/// Host-provided protocol-state storage boundary.
#[uniffi::export(with_foreign)]
pub trait ProtocolStateStore: Send + Sync {
    /// Loads an opaque blob by state kind and key.
    fn load(&self, kind: ProtocolStateKind, key: Vec<u8>) -> Result<Option<Vec<u8>>, AetherError>;

    /// Commits updates atomically after enforcing each update's commit check.
    fn commit(&self, updates: Vec<ProtocolStateUpdate>) -> Result<(), AetherError>;
}

/// Stable category for an opaque protocol-state blob.
#[derive(Clone, Copy, Eq, PartialEq, uniffi::Enum)]
pub enum ProtocolStateKind {
    /// Double Ratchet session state.
    RatchetSession,
    /// Deduplication-set state.
    DeduplicationSet,
    /// Pending-acknowledgment state.
    PendingAcknowledgments,
    /// Identity-key-addressed contact state.
    ContactState,
    /// Identity-key-addressed peer inbox-authorization state.
    ///
    /// Separate from [`Self::ContactState`] because it holds the peer's delivery capability, a
    /// bearer secret that must not ride along with the public contact snapshot.
    PeerInboxAuthorization,
    /// Identity-key-addressed record of which local inbox generation a contact has been given.
    LocalInboxAuthorization,
}

/// Host-side compare-and-set precondition for one protocol-state update.
#[derive(Clone, Copy, Eq, PartialEq, uniffi::Enum)]
pub enum ProtocolStateCommitCheck {
    /// The host may apply the update without checking the previous blob.
    Unchecked,
    /// The host must apply the update only when no blob exists at the address.
    Absent,
    /// The host must apply the update only when the current blob digest matches.
    Digest,
}

/// Opaque protocol-state address and blob loaded by a host.
///
/// Loaded blob bytes are wrapped and zeroized when converted into a Rust snapshot.
#[derive(uniffi::Record)]
pub struct ProtocolStateEntry {
    /// State kind.
    pub kind: ProtocolStateKind,
    /// State key bytes.
    pub key: Vec<u8>,
    /// Opaque blob bytes.
    pub blob: Vec<u8>,
}

/// Opaque protocol-state update returned by Rust for host commit.
///
/// Returned blob bytes are host-owned FFI values; hosts must commit or discard them promptly.
#[derive(uniffi::Record)]
pub struct ProtocolStateUpdate {
    /// State kind.
    pub kind: ProtocolStateKind,
    /// State key bytes.
    pub key: Vec<u8>,
    /// Previous-blob check the host must enforce before applying this update.
    pub commit_check: ProtocolStateCommitCheck,
    /// Expected digest when `commit_check` is `Digest`. Always 32 bytes when present.
    pub expected_blob_digest: Option<Vec<u8>>,
    /// Replacement blob, or `None` to delete the address.
    pub blob: Option<Vec<u8>>,
}

/// Protocol hardening limits exposed to bindings.
#[derive(uniffi::Record)]
pub struct ProtocolHardeningLimits {
    /// Maximum encoded Message bytes accepted before parsing.
    pub max_encoded_message_len: u64,
    /// Maximum Message ciphertext bytes accepted after frame decode.
    pub max_message_payload_len: u64,
    /// Maximum general Protocol State Blob bytes accepted before body decode.
    pub max_protocol_state_blob_len: u64,
    /// Maximum sender certificate bytes accepted after sealed-sender decrypt.
    pub max_sender_certificate_len: u64,
    /// Maximum sender signature bytes accepted after sealed-sender decrypt.
    pub max_sender_signature_len: u64,
    /// Received-message digest window capacity.
    pub deduplication_capacity: u64,
    /// Maximum pending outbound Messages retained for acknowledgment processing.
    pub max_pending_acknowledgments: u64,
    /// Maximum processed acknowledgment digests retained for duplicate detection.
    pub max_acknowledgment_digests: u64,
}

/// Permanent Identity Key bytes used for trust, certificates, and contacts.
#[derive(Clone, uniffi::Record)]
pub struct IdentityKey {
    /// Canonical X25519 public key bytes. Always 32 bytes.
    pub x25519_public_key: Vec<u8>,
    /// Canonical Ed25519 verifying-key bytes. Always 32 bytes.
    pub ed25519_verifying_key: Vec<u8>,
}

/// Current Discovery Key material for a Contact Identity.
#[derive(Clone, uniffi::Record)]
pub struct ContactDiscoveryKey {
    /// X25519 public key used to fetch the contact prekey bundle.
    pub x25519_public_key: Vec<u8>,
    /// Ed25519 verifying key used to validate signed prekeys.
    pub ed25519_verifying_key: Vec<u8>,
    /// Discovery Key epoch.
    pub epoch: u32,
    /// Signed creation timestamp in Unix seconds.
    pub created_at: u64,
    /// Identity-key signature over the Discovery Key bundle. Always 64 bytes.
    pub identity_signature: Vec<u8>,
}

/// Known peer identity and current Discovery Key.
#[derive(Clone, uniffi::Record)]
pub struct ContactIdentity {
    /// Permanent peer Identity Key.
    pub identity_key: IdentityKey,
    /// Current peer Discovery Key.
    pub discovery_key: ContactDiscoveryKey,
}

/// Consumer-recorded trust state for a contact.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum ContactTrustState {
    /// Contact exists but has not been accepted.
    Pending,
    /// Contact was accepted but not verified out of band.
    Unverified,
    /// Contact Safety Number was verified out of band.
    Verified,
}

/// Public contact state snapshot.
#[derive(Clone, uniffi::Record)]
pub struct ContactState {
    /// Contact identity material.
    pub identity: ContactIdentity,
    /// Trust state.
    pub trust_state: ContactTrustState,
    /// Local block flag.
    pub blocked: bool,
}

/// Contact event kind.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum ContactEventKind {
    /// Contact state changed.
    Changed,
}

/// Immutable contact event snapshot.
#[derive(Clone, uniffi::Record)]
pub struct ContactEvent {
    /// Event kind.
    pub kind: ContactEventKind,
    /// Complete changed contact snapshot.
    pub contact: ContactState,
}

/// A peer's recipient delivery capability for one of its inbox generations.
///
/// Deliberately not [`Clone`]: [`Self::capability`] is a bearer secret, and every clone is another
/// heap copy nothing scrubs. Hand it straight to the relay submission that needs it.
#[derive(uniffi::Record)]
pub struct PeerInboxAuthorization {
    /// The peer inbox generation this authorization belongs to.
    pub generation: u32,
    /// The peer's recipient delivery capability for that generation. Always 32 bytes, and secret.
    pub capability: Vec<u8>,
}

/// Contact mutation result.
#[derive(uniffi::Record)]
pub struct ContactStateChange {
    /// Complete contact snapshot after the operation.
    pub contact: ContactState,
    /// Opaque state updates to commit.
    pub state_updates: Vec<ProtocolStateUpdate>,
    /// Event to emit after durable commit, when state changed.
    pub event: Option<ContactEvent>,
}

/// Safety-number confirmation outcome kind.
#[derive(uniffi::Enum)]
pub enum ContactSafetyNumberConfirmationKind {
    /// Presented Safety Number matched.
    Matched,
    /// Presented Safety Number did not match.
    Mismatched,
}

/// Safety-number confirmation outcome.
#[derive(uniffi::Record)]
pub struct ContactSafetyNumberConfirmation {
    /// Match result.
    pub kind: ContactSafetyNumberConfirmationKind,
    /// Contact state change.
    pub change: ContactStateChange,
}

/// Derived Safety Number.
#[derive(uniffi::Record)]
pub struct SafetyNumber {
    /// Raw derivation bytes.
    pub raw_bytes: Vec<u8>,
    /// Grouped decimal display string.
    pub grouped_decimal: String,
}

/// Pending acknowledgment visible to hosts without plaintext.
#[derive(uniffi::Record)]
pub struct PendingAcknowledgment {
    /// Original outbound Message ID. Always 16 bytes.
    pub message_id: Vec<u8>,
    /// Original outbound Message waiting for acknowledgment.
    pub message: Message,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_millis: u64,
    /// Last retry-instruction timestamp in milliseconds.
    pub last_retry_millis: Option<u64>,
}

/// Retry instruction for an unacknowledged Message.
#[derive(uniffi::Record)]
pub struct RetryInstruction {
    /// Original outbound Message ID. Always 16 bytes.
    pub message_id: Vec<u8>,
    /// Message the host may retransmit.
    pub message: Message,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_millis: u64,
    /// Previous retry-instruction timestamp in milliseconds.
    pub last_retry_millis: Option<u64>,
}

/// Retry instructions plus pending-state updates.
#[derive(uniffi::Record)]
pub struct RetryInstructionResult {
    /// Messages whose retry window elapsed.
    pub instructions: Vec<RetryInstruction>,
    /// Opaque state updates to commit.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Outbound Message plus state updates from one encrypt operation.
#[derive(uniffi::Record)]
pub struct OutboundMessageResult {
    /// Stable outbound Message ID. Always 16 bytes.
    pub message_id: Vec<u8>,
    /// Sender-observed Unix timestamp in milliseconds.
    pub timestamp_millis: u64,
    /// Payload kind sealed in the Message.
    pub payload_kind: PayloadKind,
    /// Message to send after durable commit.
    pub message: Message,
    /// Opaque state updates to commit atomically with the Message.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Receive outcome kind.
#[derive(uniffi::Enum)]
pub enum InboundMessageOutcomeKind {
    /// A unique Message decrypted and produced plaintext.
    Accepted,
    /// A unique blocked Message advanced state without plaintext.
    Blocked,
    /// The Message was a duplicate.
    Duplicate,
    /// The Session is terminal and must be replaced.
    SessionUnrecoverable,
}

/// Terminal Session reason.
#[derive(uniffi::Enum)]
pub enum SessionUnrecoverableReason {
    /// The skipped-message-key retention cap was exceeded.
    SkippedKeyLimitExceeded,
}

/// Session event emitted after committing returned updates.
#[derive(uniffi::Record)]
pub struct SessionEvent {
    /// Session-scoped protocol-state key.
    pub session_key: Vec<u8>,
    /// Terminal reason.
    pub reason: SessionUnrecoverableReason,
}

/// Receive result for one encrypted Message.
#[derive(uniffi::Record)]
pub struct InboundMessageOutcome {
    /// Outcome kind.
    pub kind: InboundMessageOutcomeKind,
    /// Message ID when decrypt succeeded. Always 16 bytes when present.
    pub message_id: Option<Vec<u8>>,
    /// Sender-observed Unix timestamp when decrypt succeeded.
    pub timestamp_millis: Option<u64>,
    /// Payload kind when decrypt succeeded.
    pub payload_kind: Option<PayloadKind>,
    /// Plaintext for accepted Messages.
    pub plaintext: Option<Vec<u8>>,
    /// Sender identity material for accepted Messages.
    pub sender_identity: Option<SenderIdentityMaterial>,
    /// Opaque authenticity evidence for an accepted Message, when present.
    ///
    /// Persisting or transmitting these bytes creates a durable, non-repudiable record containing
    /// the accepted plaintext. Callers should retain it only when their reporting policy requires.
    pub evidence_bundle: Option<Vec<u8>>,
    /// Acknowledgment Message to durably queue, when produced.
    pub acknowledgment: Option<Message>,
    /// Opaque state updates to commit.
    pub state_updates: Vec<ProtocolStateUpdate>,
    /// Session event to emit after durable commit, if any.
    pub session_event: Option<SessionEvent>,
    /// Terminal reason, if the Session is unrecoverable.
    pub unrecoverable_reason: Option<SessionUnrecoverableReason>,
}

/// Acknowledgment processing outcome kind.
#[derive(uniffi::Enum)]
pub enum AcknowledgmentOutcomeKind {
    /// A pending outbound Message was cleared.
    Cleared,
    /// The acknowledgment decrypted but did not match pending state.
    Missed,
    /// The acknowledgment was a duplicate.
    Duplicate,
    /// The Session is terminal and must be replaced.
    SessionUnrecoverable,
}

/// Result of processing an encrypted acknowledgment Message.
#[derive(uniffi::Record)]
pub struct AcknowledgmentOutcome {
    /// Outcome kind.
    pub kind: AcknowledgmentOutcomeKind,
    /// Acknowledgment Message ID. Always 16 bytes when present.
    pub message_id: Option<Vec<u8>>,
    /// Acknowledgment timestamp in milliseconds.
    pub timestamp_millis: Option<u64>,
    /// Outbound Message ID named by the acknowledgment.
    pub acknowledged_message_id: Option<Vec<u8>>,
    /// Sender identity material decoded from the acknowledgment.
    pub sender_identity: Option<SenderIdentityMaterial>,
    /// Opaque state updates to commit.
    pub state_updates: Vec<ProtocolStateUpdate>,
    /// Session event to emit after durable commit, if any.
    pub session_event: Option<SessionEvent>,
    /// Terminal reason, if the Session is unrecoverable.
    pub unrecoverable_reason: Option<SessionUnrecoverableReason>,
}

/// Blocked-contact acknowledgment policy.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum BlockedContactAcknowledgmentPolicy {
    /// Suppress acknowledgments so blocks look like unreachable recipients.
    Unreachable,
    /// Return normal acknowledgments while hiding plaintext.
    SilentReceipt,
}

/// Stateless protocol-state engine exposed through generated bindings.
#[derive(uniffi::Object)]
pub struct ProtocolStateEngine {
    inner: CoreProtocolStateEngine,
}

#[uniffi::export]
impl ProtocolStateEngine {
    /// Creates a protocol-state engine with default hardening limits.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: CoreProtocolStateEngine::new(),
        })
    }

    /// Creates a protocol-state engine with a deduplication capacity.
    #[uniffi::constructor]
    pub fn with_deduplication_capacity(capacity: u64) -> Result<Arc<Self>, AetherError> {
        Ok(Arc::new(Self {
            inner: CoreProtocolStateEngine::with_deduplication_capacity(usize_from_u64(
                capacity,
                "deduplication capacity",
            )?)?,
        }))
    }

    /// Returns the engine hardening limits.
    pub fn hardening_limits(&self) -> ProtocolHardeningLimits {
        self.inner.hardening_limits().into()
    }

    /// Returns a copy with blocked-contact acknowledgment policy changed.
    pub fn with_blocked_contact_acknowledgment_policy(
        &self,
        policy: BlockedContactAcknowledgmentPolicy,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: self
                .inner
                .with_blocked_contact_acknowledgment_policy(policy.into()),
        })
    }

    /// Loads the requested addresses from a host store into snapshot entries.
    ///
    /// Updates produced from a snapshot include commit checks derived from these blob bytes. Hosts
    /// must reject stale commits instead of overwriting state unconditionally.
    pub fn load_snapshot(
        &self,
        store: Arc<dyn ProtocolStateStore>,
        addresses: Vec<ProtocolStateAddress>,
    ) -> Result<Vec<ProtocolStateEntry>, AetherError> {
        let mut entries = Vec::new();
        for address in addresses {
            if let Some(blob) = store.load(address.kind, address.key.clone())? {
                entries.push(ProtocolStateEntry {
                    kind: address.kind,
                    key: address.key,
                    blob,
                });
            }
        }
        Ok(entries)
    }

    /// Returns an update that initializes a deduplication set.
    pub fn initialize_deduplication_set(
        &self,
        key: Vec<u8>,
    ) -> Result<ProtocolStateUpdate, AetherError> {
        ProtocolStateUpdate::from_core_absent(
            self.inner
                .initialize_deduplication_set(&mut OsRng, protocol_key(key)?)?,
        )
    }

    /// Returns an update that initializes pending-acknowledgment state.
    pub fn initialize_pending_acknowledgments(
        &self,
        key: Vec<u8>,
    ) -> Result<ProtocolStateUpdate, AetherError> {
        ProtocolStateUpdate::from_core_absent(
            self.inner
                .initialize_pending_acknowledgments(protocol_key(key)?)?,
        )
    }

    /// Returns deletion updates for all protocol-state kinds at the key.
    pub fn wipe(&self, key: Vec<u8>) -> Result<Vec<ProtocolStateUpdate>, AetherError> {
        self.inner
            .wipe(protocol_key(key)?)
            .into_iter()
            .map(ProtocolStateUpdate::from_core_unchecked)
            .collect()
    }

    /// Creates or updates a Contact State blob.
    pub fn record_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        contact_identity: ContactIdentity,
    ) -> Result<ContactStateChange, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        ContactStateChange::from_core(
            &snapshot,
            self.inner
                .record_contact(&snapshot.snapshot, contact_identity.to_core()?)?,
        )
    }

    /// Returns one Contact State, if present.
    pub fn contact_state(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<Option<ContactState>, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(self
            .inner
            .contact_state(&snapshot.snapshot, identity_key.to_core()?)?
            .map(ContactState::from_core))
    }

    /// Returns all Contact State snapshots.
    pub fn contact_states(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
    ) -> Result<Vec<ContactState>, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(self
            .inner
            .contact_states(&snapshot.snapshot)?
            .into_iter()
            .map(ContactState::from_core)
            .collect())
    }

    /// Accepts a pending contact.
    pub fn accept_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<ContactStateChange, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        ContactStateChange::from_core(
            &snapshot,
            self.inner
                .accept_contact(&snapshot.snapshot, identity_key.to_core()?)?,
        )
    }

    /// Records a peer's inbox authorization for a generation (AE-CON-05).
    ///
    /// Returns no updates when `generation` is not newer than what is stored. That refusal is
    /// load-bearing: an old authorization replayed at a contact would restore a capability the
    /// peer has already rotated away from, which is exactly the state a blocked sender wants to
    /// reach (AE-BLK-08).
    ///
    /// # Errors
    /// - [`AetherError::InvalidData`] if `identity_key` or `capability` has the wrong length.
    /// - [`AetherError::ProtocolStateFault`] if the stored or new authorization cannot be coded.
    pub fn record_peer_inbox_authorization(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
        generation: u32,
        capability: Vec<u8>,
    ) -> Result<Vec<ProtocolStateUpdate>, AetherError> {
        let capability = Zeroizing::new(capability);
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let capability = CoreRecipientDeliveryCapability::from_bytes(fixed_32(
            &capability,
            "recipient delivery capability",
        )?);
        updates_from_core_with_snapshot(
            &snapshot,
            self.inner.record_peer_inbox_authorization(
                &snapshot.snapshot,
                identity_key.to_core()?,
                generation,
                &capability,
            )?,
        )
    }

    /// Returns the stored inbox authorization for a peer, if one has been recorded.
    ///
    /// # Errors
    /// - [`AetherError::InvalidData`] if `identity_key` has the wrong length.
    /// - [`AetherError::ProtocolStateFault`] if the stored authorization cannot be decoded.
    pub fn peer_inbox_authorization(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<Option<PeerInboxAuthorization>, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(self
            .inner
            .peer_inbox_authorization(&snapshot.snapshot, identity_key.to_core()?)?
            .map(|stored| PeerInboxAuthorization {
                generation: stored.generation,
                capability: stored.capability.to_bytes().to_vec(),
            }))
    }

    /// Records that a contact has been given local inbox generation `generation`.
    ///
    /// Call this only once the authorization update has actually reached transport. Recording it
    /// earlier would let an app killed mid-re-key resume past a contact that never received
    /// anything, leaving that contact unable to deliver until the next rotation.
    ///
    /// # Errors
    /// - [`AetherError::InvalidData`] if `identity_key` has the wrong length.
    /// - [`AetherError::ProtocolStateFault`] if the stored or new record cannot be coded.
    pub fn record_inbox_authorization_delivered(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
        generation: u32,
    ) -> Result<Vec<ProtocolStateUpdate>, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        updates_from_core_with_snapshot(
            &snapshot,
            self.inner.record_inbox_authorization_delivered(
                &snapshot.snapshot,
                identity_key.to_core()?,
                generation,
            )?,
        )
    }

    /// Returns which of `candidates` still need the current inbox generation.
    ///
    /// A contact qualifies when it has never been given an authorization or was last given an
    /// older one. Blocked contacts are always excluded — re-supplying one would hand back the very
    /// capability the rotation revoked and silently undo the block (AE-BLK-08). Contacts with no
    /// stored contact record are skipped.
    ///
    /// # Errors
    /// - [`AetherError::InvalidData`] if a candidate key has the wrong length.
    /// - [`AetherError::ProtocolStateFault`] if a stored record cannot be decoded.
    pub fn contacts_needing_inbox_authorization(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        current_generation: u32,
        candidates: Vec<IdentityKey>,
    ) -> Result<Vec<IdentityKey>, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let candidates = candidates
            .iter()
            .map(IdentityKey::to_core)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .inner
            .contacts_needing_inbox_authorization(
                &snapshot.snapshot,
                current_generation,
                &candidates,
            )?
            .into_iter()
            .map(IdentityKey::from_core)
            .collect())
    }

    /// Confirms a Safety Number out of band.
    pub fn confirm_contact_safety_number(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        local_identity_key: IdentityKey,
        contact_identity_key: IdentityKey,
        presented_grouped_decimal: String,
    ) -> Result<ContactSafetyNumberConfirmation, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        ContactSafetyNumberConfirmation::from_core(
            &snapshot,
            self.inner.confirm_contact_safety_number(
                &snapshot.snapshot,
                local_identity_key.to_core()?,
                contact_identity_key.to_core()?,
                &presented_grouped_decimal,
            )?,
        )
    }

    /// Blocks a contact locally.
    pub fn block_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<ContactStateChange, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        ContactStateChange::from_core(
            &snapshot,
            self.inner
                .block_contact(&snapshot.snapshot, identity_key.to_core()?)?,
        )
    }

    /// Unblocks a contact locally.
    pub fn unblock_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<ContactStateChange, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        ContactStateChange::from_core(
            &snapshot,
            self.inner
                .unblock_contact(&snapshot.snapshot, identity_key.to_core()?)?,
        )
    }

    /// Returns all pending acknowledgments for a Session.
    pub fn pending_acknowledgments(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        key: Vec<u8>,
    ) -> Result<Vec<PendingAcknowledgment>, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(self
            .inner
            .pending_acknowledgments(&snapshot.snapshot, protocol_key(key)?)?
            .into_iter()
            .map(PendingAcknowledgment::from_core)
            .collect())
    }

    /// Returns retry instructions whose retry window elapsed.
    pub fn retry_instructions(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        key: Vec<u8>,
        now_millis: u64,
        retry_window_millis: u64,
    ) -> Result<RetryInstructionResult, AetherError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        RetryInstructionResult::from_core(
            &snapshot,
            self.inner.retry_instructions(
                &snapshot.snapshot,
                protocol_key(key)?,
                now_millis,
                retry_window_millis,
            )?,
        )
    }
}

/// Protocol-state address requested from a host store.
#[derive(uniffi::Record)]
pub struct ProtocolStateAddress {
    /// State kind.
    pub kind: ProtocolStateKind,
    /// State key bytes.
    pub key: Vec<u8>,
}

pub(crate) struct ProtocolStateSnapshotInput {
    pub(crate) snapshot: CoreProtocolStateSnapshot,
    preconditions: Vec<ProtocolStatePrecondition>,
}

struct ProtocolStatePrecondition {
    kind: ProtocolStateKind,
    key: Vec<u8>,
    digest: Vec<u8>,
}

/// Derives a Safety Number for two permanent Identity Keys.
#[uniffi::export]
pub fn derive_safety_number(
    first: IdentityKey,
    second: IdentityKey,
) -> Result<SafetyNumber, AetherError> {
    let safety_number = aether_core::derive_safety_number(first.to_core()?, second.to_core()?)?;
    Ok(SafetyNumber {
        raw_bytes: safety_number.raw_bytes.to_vec(),
        grouped_decimal: safety_number.grouped_decimal,
    })
}

/// Computes the binding-level digest used by `ProtocolStateUpdate` commit checks.
#[uniffi::export]
pub fn protocol_state_blob_digest(blob: Vec<u8>) -> Vec<u8> {
    let blob = Zeroizing::new(blob);
    state_blob_digest(&blob)
}

pub(crate) fn protocol_key(key: Vec<u8>) -> Result<CoreProtocolStateKey, AetherError> {
    CoreProtocolStateKey::from_bytes(key).map_err(AetherError::from)
}

pub(crate) fn snapshot_input_from_entries(
    entries: Vec<ProtocolStateEntry>,
) -> Result<ProtocolStateSnapshotInput, AetherError> {
    let mut snapshot = CoreProtocolStateSnapshot::new();
    let mut preconditions = Vec::with_capacity(entries.len());
    for entry in entries {
        let blob = Zeroizing::new(entry.blob);
        let digest = state_blob_digest(&blob);
        let key = entry.key;
        let address = CoreProtocolStateAddress::new(entry.kind.into(), protocol_key(key.clone())?);
        snapshot.set(address, CoreProtocolStateBlob::from_bytes(blob.to_vec()));
        preconditions.push(ProtocolStatePrecondition {
            kind: entry.kind,
            key,
            digest,
        });
    }
    Ok(ProtocolStateSnapshotInput {
        snapshot,
        preconditions,
    })
}

fn usize_from_u64(value: u64, label: &str) -> Result<usize, AetherError> {
    usize::try_from(value).map_err(|_| AetherError::InvalidData {
        reason: format!("{label} exceeds usize"),
    })
}

impl ProtocolStateUpdate {
    pub(crate) fn from_core_absent(update: CoreProtocolStateUpdate) -> Result<Self, AetherError> {
        Self::from_core_with_precondition(update, ProtocolStateCommitCheck::Absent, None)
    }

    pub(crate) fn from_core_unchecked(
        update: CoreProtocolStateUpdate,
    ) -> Result<Self, AetherError> {
        Self::from_core_with_precondition(update, ProtocolStateCommitCheck::Unchecked, None)
    }

    pub(crate) fn from_core_with_snapshot(
        snapshot: &ProtocolStateSnapshotInput,
        update: CoreProtocolStateUpdate,
    ) -> Result<Self, AetherError> {
        let kind = ProtocolStateKind::from_core(update.address().kind())?;
        let key = update.address().key().as_bytes();
        let digest = snapshot
            .preconditions
            .iter()
            .find(|entry| entry.kind == kind && entry.key.as_slice() == key)
            .map(|entry| entry.digest.clone());
        let check = if digest.is_some() {
            ProtocolStateCommitCheck::Digest
        } else {
            ProtocolStateCommitCheck::Absent
        };
        Self::from_core_with_precondition(update, check, digest)
    }

    fn from_core_with_precondition(
        update: CoreProtocolStateUpdate,
        commit_check: ProtocolStateCommitCheck,
        expected_blob_digest: Option<Vec<u8>>,
    ) -> Result<Self, AetherError> {
        Self {
            kind: ProtocolStateKind::from_core(update.address().kind())?,
            key: update.address().key().as_bytes().to_vec(),
            commit_check,
            expected_blob_digest,
            blob: update.blob().map(|blob| blob.as_bytes().to_vec()),
        }
        .validate_commit_check()
    }

    fn validate_commit_check(self) -> Result<Self, AetherError> {
        match (self.commit_check, self.expected_blob_digest.as_deref()) {
            (ProtocolStateCommitCheck::Digest, Some(digest)) if digest.len() == 32 => Ok(self),
            (ProtocolStateCommitCheck::Absent | ProtocolStateCommitCheck::Unchecked, None) => {
                Ok(self)
            }
            _ => Err(AetherError::InternalError {
                reason: "invalid protocol-state update commit check".into(),
            }),
        }
    }
}

pub(crate) fn updates_from_core_absent(
    updates: Vec<CoreProtocolStateUpdate>,
) -> Result<Vec<ProtocolStateUpdate>, AetherError> {
    updates
        .into_iter()
        .map(ProtocolStateUpdate::from_core_absent)
        .collect()
}

pub(crate) fn updates_from_core_with_snapshot(
    snapshot: &ProtocolStateSnapshotInput,
    updates: Vec<CoreProtocolStateUpdate>,
) -> Result<Vec<ProtocolStateUpdate>, AetherError> {
    updates
        .into_iter()
        .map(|update| ProtocolStateUpdate::from_core_with_snapshot(snapshot, update))
        .collect()
}

fn state_blob_digest(blob: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROTOCOL_STATE_COMMIT_DIGEST_CONTEXT);
    hasher.update(blob);
    hasher.finalize().as_bytes().to_vec()
}

impl ProtocolStateKind {
    fn from_core(value: aether_core::ProtocolStateKind) -> Result<Self, AetherError> {
        match value {
            aether_core::ProtocolStateKind::RatchetSession => Ok(Self::RatchetSession),
            aether_core::ProtocolStateKind::DeduplicationSet => Ok(Self::DeduplicationSet),
            aether_core::ProtocolStateKind::PendingAcknowledgments => {
                Ok(Self::PendingAcknowledgments)
            }
            aether_core::ProtocolStateKind::ContactState => Ok(Self::ContactState),
            aether_core::ProtocolStateKind::PeerInboxAuthorization => {
                Ok(Self::PeerInboxAuthorization)
            }
            aether_core::ProtocolStateKind::LocalInboxAuthorization => {
                Ok(Self::LocalInboxAuthorization)
            }
            _ => Err(AetherError::UnsupportedVersion {
                reason: "unknown protocol-state kind".into(),
            }),
        }
    }
}

impl From<ProtocolStateKind> for aether_core::ProtocolStateKind {
    fn from(value: ProtocolStateKind) -> Self {
        match value {
            ProtocolStateKind::RatchetSession => Self::RatchetSession,
            ProtocolStateKind::DeduplicationSet => Self::DeduplicationSet,
            ProtocolStateKind::PendingAcknowledgments => Self::PendingAcknowledgments,
            ProtocolStateKind::ContactState => Self::ContactState,
            ProtocolStateKind::PeerInboxAuthorization => Self::PeerInboxAuthorization,
            ProtocolStateKind::LocalInboxAuthorization => Self::LocalInboxAuthorization,
        }
    }
}

impl From<aether_core::ProtocolHardeningLimits> for ProtocolHardeningLimits {
    fn from(value: aether_core::ProtocolHardeningLimits) -> Self {
        Self {
            max_encoded_message_len: value.max_encoded_message_len as u64,
            max_message_payload_len: value.max_message_payload_len as u64,
            max_protocol_state_blob_len: value.max_protocol_state_blob_len as u64,
            max_sender_certificate_len: value.max_sender_certificate_len as u64,
            max_sender_signature_len: value.max_sender_signature_len as u64,
            deduplication_capacity: value.deduplication_capacity as u64,
            max_pending_acknowledgments: value.max_pending_acknowledgments as u64,
            max_acknowledgment_digests: value.max_acknowledgment_digests as u64,
        }
    }
}

impl From<BlockedContactAcknowledgmentPolicy> for aether_core::BlockedContactAcknowledgmentPolicy {
    fn from(value: BlockedContactAcknowledgmentPolicy) -> Self {
        match value {
            BlockedContactAcknowledgmentPolicy::Unreachable => Self::Unreachable,
            BlockedContactAcknowledgmentPolicy::SilentReceipt => Self::SilentReceipt,
        }
    }
}

impl IdentityKey {
    pub(crate) fn from_core(value: aether_core::IdentityKey) -> Self {
        Self {
            x25519_public_key: value.x25519_public_key.to_vec(),
            ed25519_verifying_key: value.ed25519_verifying_key.to_vec(),
        }
    }

    pub(crate) fn to_core(&self) -> Result<aether_core::IdentityKey, AetherError> {
        Ok(aether_core::IdentityKey {
            x25519_public_key: fixed_32(&self.x25519_public_key, "identity x25519 public key")?,
            ed25519_verifying_key: fixed_32(
                &self.ed25519_verifying_key,
                "identity ed25519 verifying key",
            )?,
        })
    }
}

impl ContactDiscoveryKey {
    fn from_core(value: aether_core::ContactDiscoveryKey) -> Self {
        Self {
            x25519_public_key: value.x25519_public_key.to_vec(),
            ed25519_verifying_key: value.ed25519_verifying_key.to_vec(),
            epoch: value.epoch,
            created_at: value.created_at,
            identity_signature: value.identity_signature.to_vec(),
        }
    }

    fn to_core(&self) -> Result<aether_core::ContactDiscoveryKey, AetherError> {
        Ok(aether_core::ContactDiscoveryKey {
            x25519_public_key: fixed_32(
                &self.x25519_public_key,
                "contact discovery x25519 public key",
            )?,
            ed25519_verifying_key: fixed_32(
                &self.ed25519_verifying_key,
                "contact discovery ed25519 verifying key",
            )?,
            epoch: self.epoch,
            created_at: self.created_at,
            identity_signature: fixed_64(
                &self.identity_signature,
                "contact discovery identity signature",
            )?,
        })
    }
}

impl ContactIdentity {
    fn from_core(value: aether_core::ContactIdentity) -> Self {
        Self {
            identity_key: IdentityKey::from_core(value.identity_key),
            discovery_key: ContactDiscoveryKey::from_core(value.discovery_key),
        }
    }

    fn to_core(&self) -> Result<aether_core::ContactIdentity, AetherError> {
        Ok(aether_core::ContactIdentity {
            identity_key: self.identity_key.to_core()?,
            discovery_key: self.discovery_key.to_core()?,
        })
    }
}

impl From<aether_core::ContactTrustState> for ContactTrustState {
    fn from(value: aether_core::ContactTrustState) -> Self {
        match value {
            aether_core::ContactTrustState::Pending => Self::Pending,
            aether_core::ContactTrustState::Unverified => Self::Unverified,
            aether_core::ContactTrustState::Verified => Self::Verified,
        }
    }
}

impl From<ContactTrustState> for aether_core::ContactTrustState {
    fn from(value: ContactTrustState) -> Self {
        match value {
            ContactTrustState::Pending => Self::Pending,
            ContactTrustState::Unverified => Self::Unverified,
            ContactTrustState::Verified => Self::Verified,
        }
    }
}

impl ContactState {
    pub(crate) fn from_core(value: aether_core::ContactState) -> Self {
        Self {
            identity: ContactIdentity::from_core(value.identity),
            trust_state: value.trust_state.into(),
            blocked: value.blocked,
        }
    }

    pub(crate) fn to_core(&self) -> Result<aether_core::ContactState, AetherError> {
        Ok(aether_core::ContactState {
            identity: self.identity.to_core()?,
            trust_state: self.trust_state.into(),
            blocked: self.blocked,
        })
    }
}

impl ContactEvent {
    pub(crate) fn from_core(value: aether_core::ContactEvent) -> Self {
        match value {
            aether_core::ContactEvent::Changed { contact } => Self {
                kind: ContactEventKind::Changed,
                contact: ContactState::from_core(contact),
            },
        }
    }

    pub(crate) fn to_core(&self) -> Result<aether_core::ContactEvent, AetherError> {
        match self.kind {
            ContactEventKind::Changed => Ok(aether_core::ContactEvent::Changed {
                contact: self.contact.to_core()?,
            }),
        }
    }
}

impl ContactStateChange {
    pub(crate) fn from_core(
        snapshot: &ProtocolStateSnapshotInput,
        value: CoreContactStateChange,
    ) -> Result<Self, AetherError> {
        Ok(Self {
            contact: ContactState::from_core(value.contact),
            state_updates: updates_from_core_with_snapshot(snapshot, value.state_updates)?,
            event: value.event.map(ContactEvent::from_core),
        })
    }
}

impl ContactSafetyNumberConfirmation {
    fn from_core(
        snapshot: &ProtocolStateSnapshotInput,
        value: CoreSafetyNumberConfirmation,
    ) -> Result<Self, AetherError> {
        match value {
            CoreSafetyNumberConfirmation::Matched(change) => Ok(Self {
                kind: ContactSafetyNumberConfirmationKind::Matched,
                change: ContactStateChange::from_core(snapshot, change)?,
            }),
            CoreSafetyNumberConfirmation::Mismatched(change) => Ok(Self {
                kind: ContactSafetyNumberConfirmationKind::Mismatched,
                change: ContactStateChange::from_core(snapshot, change)?,
            }),
        }
    }
}

impl PendingAcknowledgment {
    fn from_core(value: aether_core::PendingAcknowledgment) -> Self {
        Self {
            message_id: value.message_id.as_bytes().to_vec(),
            message: Message::from_core(value.message),
            first_sent_millis: value.first_sent_millis,
            last_retry_millis: value.last_retry_millis,
        }
    }
}

impl RetryInstruction {
    fn from_core(value: aether_core::RetryInstruction) -> Self {
        Self {
            message_id: value.message_id.as_bytes().to_vec(),
            message: Message::from_core(value.message),
            first_sent_millis: value.first_sent_millis,
            last_retry_millis: value.last_retry_millis,
        }
    }
}

impl RetryInstructionResult {
    fn from_core(
        snapshot: &ProtocolStateSnapshotInput,
        value: aether_core::RetryInstructionResult,
    ) -> Result<Self, AetherError> {
        Ok(Self {
            instructions: value
                .instructions
                .into_iter()
                .map(RetryInstruction::from_core)
                .collect(),
            state_updates: updates_from_core_with_snapshot(snapshot, value.state_updates)?,
        })
    }
}

impl OutboundMessageResult {
    pub(crate) fn from_core(
        snapshot: &ProtocolStateSnapshotInput,
        value: aether_core::OutboundMessageResult,
    ) -> Result<Self, AetherError> {
        Ok(Self {
            message_id: value.message_id.as_bytes().to_vec(),
            timestamp_millis: value.timestamp_millis,
            payload_kind: value.payload_kind.into(),
            message: Message::from_core(value.message),
            state_updates: updates_from_core_with_snapshot(snapshot, value.state_updates)?,
        })
    }
}

impl InboundMessageOutcome {
    pub(crate) fn from_core(
        snapshot: &ProtocolStateSnapshotInput,
        value: aether_core::InboundMessageOutcome,
    ) -> Result<Self, AetherError> {
        match value {
            aether_core::InboundMessageOutcome::Accepted(result) => {
                let state_updates =
                    updates_from_core_with_snapshot(snapshot, result.state_updates)?;
                let evidence_bundle = result.evidence_bundle.as_bytes().to_vec();
                Ok(Self {
                    kind: InboundMessageOutcomeKind::Accepted,
                    message_id: Some(result.message_id.as_bytes().to_vec()),
                    timestamp_millis: Some(result.timestamp_millis),
                    payload_kind: Some(result.payload_kind.into()),
                    plaintext: Some(result.plaintext.to_vec()),
                    sender_identity: Some(SenderIdentityMaterial::from_core(
                        result.sender_identity,
                    )),
                    evidence_bundle: Some(evidence_bundle),
                    acknowledgment: Some(Message::from_core(result.acknowledgment)),
                    state_updates,
                    session_event: None,
                    unrecoverable_reason: None,
                })
            }
            aether_core::InboundMessageOutcome::Blocked(result) => Ok(Self {
                kind: InboundMessageOutcomeKind::Blocked,
                message_id: None,
                timestamp_millis: None,
                payload_kind: None,
                plaintext: None,
                sender_identity: None,
                evidence_bundle: None,
                acknowledgment: result.acknowledgment.map(Message::from_core),
                state_updates: updates_from_core_with_snapshot(snapshot, result.state_updates)?,
                session_event: None,
                unrecoverable_reason: None,
            }),
            aether_core::InboundMessageOutcome::Duplicate => {
                Ok(Self::empty(InboundMessageOutcomeKind::Duplicate))
            }
            aether_core::InboundMessageOutcome::SessionUnrecoverable(result) => {
                Self::from_unrecoverable(
                    snapshot,
                    InboundMessageOutcomeKind::SessionUnrecoverable,
                    *result,
                )
            }
        }
    }

    fn empty(kind: InboundMessageOutcomeKind) -> Self {
        Self {
            kind,
            message_id: None,
            timestamp_millis: None,
            payload_kind: None,
            plaintext: None,
            sender_identity: None,
            evidence_bundle: None,
            acknowledgment: None,
            state_updates: Vec::new(),
            session_event: None,
            unrecoverable_reason: None,
        }
    }

    fn from_unrecoverable(
        snapshot: &ProtocolStateSnapshotInput,
        kind: InboundMessageOutcomeKind,
        result: aether_core::SessionUnrecoverableResult,
    ) -> Result<Self, AetherError> {
        let reason = SessionUnrecoverableReason::from_core(result.reason);
        Ok(Self {
            kind,
            message_id: None,
            timestamp_millis: None,
            payload_kind: None,
            plaintext: None,
            sender_identity: None,
            evidence_bundle: None,
            acknowledgment: None,
            state_updates: updates_from_core_with_snapshot(snapshot, result.state_updates)?,
            session_event: result.event.map(SessionEvent::from_core),
            unrecoverable_reason: Some(reason),
        })
    }
}

impl AcknowledgmentOutcome {
    pub(crate) fn from_core(
        snapshot: &ProtocolStateSnapshotInput,
        value: aether_core::AcknowledgmentOutcome,
    ) -> Result<Self, AetherError> {
        match value {
            aether_core::AcknowledgmentOutcome::Cleared(cleared) => Ok(Self {
                kind: AcknowledgmentOutcomeKind::Cleared,
                message_id: Some(cleared.message_id.as_bytes().to_vec()),
                timestamp_millis: Some(cleared.timestamp_millis),
                acknowledged_message_id: Some(cleared.acknowledged_message_id.as_bytes().to_vec()),
                sender_identity: Some(SenderIdentityMaterial::from_core(cleared.sender_identity)),
                state_updates: updates_from_core_with_snapshot(snapshot, cleared.state_updates)?,
                session_event: None,
                unrecoverable_reason: None,
            }),
            aether_core::AcknowledgmentOutcome::Missed {
                message_id,
                timestamp_millis,
                acknowledged_message_id,
                sender_identity,
                state_updates,
            } => Ok(Self {
                kind: AcknowledgmentOutcomeKind::Missed,
                message_id: Some(message_id.as_bytes().to_vec()),
                timestamp_millis: Some(timestamp_millis),
                acknowledged_message_id: Some(acknowledged_message_id.as_bytes().to_vec()),
                sender_identity: Some(SenderIdentityMaterial::from_core(sender_identity)),
                state_updates: updates_from_core_with_snapshot(snapshot, state_updates)?,
                session_event: None,
                unrecoverable_reason: None,
            }),
            aether_core::AcknowledgmentOutcome::Duplicate => {
                Ok(Self::empty(AcknowledgmentOutcomeKind::Duplicate))
            }
            aether_core::AcknowledgmentOutcome::SessionUnrecoverable(result) => {
                Self::from_unrecoverable(
                    snapshot,
                    AcknowledgmentOutcomeKind::SessionUnrecoverable,
                    *result,
                )
            }
        }
    }

    fn empty(kind: AcknowledgmentOutcomeKind) -> Self {
        Self {
            kind,
            message_id: None,
            timestamp_millis: None,
            acknowledged_message_id: None,
            sender_identity: None,
            state_updates: Vec::new(),
            session_event: None,
            unrecoverable_reason: None,
        }
    }

    fn from_unrecoverable(
        snapshot: &ProtocolStateSnapshotInput,
        kind: AcknowledgmentOutcomeKind,
        result: aether_core::SessionUnrecoverableResult,
    ) -> Result<Self, AetherError> {
        let reason = SessionUnrecoverableReason::from_core(result.reason);
        Ok(Self {
            kind,
            message_id: None,
            timestamp_millis: None,
            acknowledged_message_id: None,
            sender_identity: None,
            state_updates: updates_from_core_with_snapshot(snapshot, result.state_updates)?,
            session_event: result.event.map(SessionEvent::from_core),
            unrecoverable_reason: Some(reason),
        })
    }
}

impl SessionEvent {
    fn from_core(value: aether_core::SessionEvent) -> Self {
        match value {
            aether_core::SessionEvent::Unrecoverable {
                session_key,
                reason,
            } => Self {
                session_key: session_key.as_bytes().to_vec(),
                reason: SessionUnrecoverableReason::from_core(reason),
            },
        }
    }
}

impl SessionUnrecoverableReason {
    fn from_core(value: aether_core::SessionUnrecoverableReason) -> Self {
        match value {
            aether_core::SessionUnrecoverableReason::SkippedKeyLimitExceeded => {
                Self::SkippedKeyLimitExceeded
            }
        }
    }
}

impl From<EventStreamError> for AetherError {
    fn from(e: EventStreamError) -> Self {
        match e {
            EventStreamError::InvalidObserverCapacity { capacity, max } => {
                AetherError::InvalidData {
                    reason: format!("event observer capacity {capacity} exceeds {max}"),
                }
            }
            EventStreamError::ObserverClosed => AetherError::EventStreamClosed,
            EventStreamError::LockPoisoned => AetherError::InternalError {
                reason: "event stream lock poisoned".into(),
            },
            EventStreamError::EventIdOverflow | EventStreamError::ObserverIdOverflow => {
                AetherError::InternalError {
                    reason: e.to_string(),
                }
            }
            _ => AetherError::InternalError {
                reason: e.to_string(),
            },
        }
    }
}
