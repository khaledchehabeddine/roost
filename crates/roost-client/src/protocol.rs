//! UniFFI protocol-state objects, records, and host persistence boundary.

use crate::context::{Contacts, Messaging};
use crate::error::RoostError;
use crate::message::{Message, MessageId, PayloadKind, SenderIdentityMaterial};
use crate::operation::OperationId;
use crate::records::{SessionId, fixed_32, hex_bytes, hex_text};
use crate::time::millis_from_secs;
use roost_core::{
    ContactSafetyNumberConfirmation as CoreSafetyNumberConfirmation,
    ProtocolStateAddress as CoreProtocolStateAddress, ProtocolStateBlob as CoreProtocolStateBlob,
    ProtocolStateCommitCondition, ProtocolStateKey as CoreProtocolStateKey,
    ProtocolStateSnapshot as CoreProtocolStateSnapshot,
    ProtocolStateUpdate as CoreProtocolStateUpdate, StateChanges as CoreStateChanges,
};
use std::time::Duration;
use zeroize::Zeroize;

/// Stable category for an opaque protocol-state blob.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, uniffi::Enum)]
pub enum ProtocolStateKind {
    /// A Session's encryption state, stored under its SessionID.
    RatchetSession,
    /// Deduplication-set state.
    DeduplicationSet,
    /// SessionID-addressed pending-acknowledgment state.
    PendingAcknowledgments,
    /// A contact's record, stored under its Identity Key, which holds the peer's Delivery
    /// Capability. Read it through [`Contacts::contact_state`].
    ContactState,
    /// Identity-key-addressed record of the Sessions kept with one peer and the one Roost sends
    /// on.
    PeerSessions,
}

/// The name of one record the host stores: its kind and its ID.
///
/// The ID is lowercase hexadecimal. For a contact's records it encodes the contact's Identity
/// Key, so the host can find every record of one contact without decoding a blob.
#[derive(Clone, Debug, Eq, Hash, PartialEq, uniffi::Record)]
pub struct StateKey {
    /// The record's kind.
    pub kind: ProtocolStateKind,
    /// The record's ID within its kind, in lowercase hexadecimal.
    pub id: String,
}

/// One record as the host holds it, or its absence.
///
/// Roost wraps the bytes and erases its copy once it's done with them.
#[derive(uniffi::Record)]
pub struct StateEntry {
    /// The record's name.
    pub key: StateKey,
    /// The record's bytes, or `None` when the host holds no record under this key.
    pub blob: Option<Vec<u8>>,
}

/// One record to write when the host commits.
#[derive(uniffi::Record)]
pub struct StateUpdate {
    /// The record's name.
    pub key: StateKey,
    /// The record's new bytes, or `None` to delete it.
    pub blob: Option<Vec<u8>>,
}

/// What one record must still be when the host commits: unchanged since Roost read it, or still
/// absent.
#[derive(Clone, uniffi::Record)]
pub struct CommitCondition {
    /// The record's name.
    pub key: StateKey,
    /// Roost's fingerprint of the record it read, or `None` when the record must still be absent.
    /// Pass it back unchanged.
    pub digest: Option<Vec<u8>>,
}

/// The records an operation's result relies on, the records it writes, the operation that commits
/// with them, if any, and the sent Messages Roost stops waiting for.
///
/// Inside one transaction, read the record under each condition's key, call [`Self::matches`],
/// and only when it returns `true` write every update together with the result's effects, such as
/// a Message to send, and show each of [`Self::undelivered`] that has content as not delivered.
/// When it returns `false`, another operation changed a record first: roll back, then start the
/// operation again from fresh reads.
///
/// When [`Self::operation_id`] is present, the changes also change SecureStorage, such as using a
/// one-time prekey or rotating the inbox:
///
/// 1. Call [`IdentityContext::reserve_operation`](crate::IdentityContext::reserve_operation). If
///    it fails because SecureStorage changed, abort the operation and start again from fresh reads.
/// 2. Commit the updates and the operation ID in the one transaction. If a condition fails, abort
///    the operation and start again.
/// 3. Call [`IdentityContext::finalize_operation`](crate::IdentityContext::finalize_operation),
///    and only then show plaintext or send anything the result holds.
///
/// When the commit's outcome is unknown, neither finalize nor abort: resolve it at startup.
#[derive(uniffi::Record)]
pub struct StateChanges {
    /// Every record the result relies on, including ones it read but doesn't write.
    pub conditions: Vec<CommitCondition>,
    /// The records to write.
    pub updates: Vec<StateUpdate>,
    /// The operation to reserve before the commit and finalize after it, if any.
    pub operation_id: Option<OperationId>,
    /// Sent Messages Roost stops waiting for, oldest first, because the Relay would have dropped
    /// them by now or the Session they wait on is gone.
    pub undelivered: Vec<MessageId>,
}

/// Roost's fixed limits on what one Message or record may cost, and the Deduplication Set's range.
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
    /// Maximum pending outbound Messages retained for acknowledgment processing.
    pub max_pending_acknowledgments: u64,
    /// Maximum processed acknowledgment digests retained for duplicate detection.
    pub max_acknowledgment_digests: u64,
    /// Smallest Deduplication Set size a receive may pass.
    pub min_deduplication_capacity: u32,
    /// Deduplication Set size for apps without a reason to choose another.
    pub default_deduplication_capacity: u32,
    /// Largest Deduplication Set size a receive may pass.
    pub max_deduplication_capacity: u32,
    /// Distinct Messages each side may send a contact before the contact accepts.
    pub max_messages_before_acceptance: u32,
}

/// The settings the app passes with each receive.
///
/// Roost holds no settings, so the app and its extensions apply whatever each receive passes.
/// Read the value the app should use from one place, such as its own settings or its Relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct ReceiveSettings {
    /// How many received-Message digests the Deduplication Set keeps, within
    /// [`ProtocolHardeningLimits`]'s range. Roost resizes the set when this changes, dropping the
    /// oldest digests first.
    pub deduplication_capacity: u32,
    /// Whether a blocked contact's Messages get an acknowledgment.
    pub blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy,
    /// How long after expiry a sender certificate still validates, in milliseconds, at most
    /// 300,000.
    ///
    /// A grace covers clock differences between devices, at the cost of accepting a certificate
    /// the relay has stopped vouching for.
    pub certificate_grace_millis: u64,
}

/// An identity's permanent public key, used for trust, certificates, and contacts.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct IdentityKey {
    /// The X25519 key that peers agree on shared secrets with. Always 32 bytes.
    pub agreement_key: Vec<u8>,
    /// The Ed25519 key that verifies the identity's signatures. Always 32 bytes.
    pub signing_key: Vec<u8>,
}

/// A contact's current Discovery Key.
#[derive(Clone, uniffi::Record)]
pub struct ContactDiscoveryKey {
    /// X25519 public key used to fetch the contact prekey bundle.
    pub x25519_public_key: Vec<u8>,
    /// Ed25519 verifying key used to validate signed prekeys.
    pub ed25519_verifying_key: Vec<u8>,
    /// Discovery Key epoch.
    pub epoch: u32,
    /// Signed creation time in Unix milliseconds, always a whole number of seconds.
    pub created_at_millis: u64,
    /// Identity-key signature over the public Discovery Key. Always 64 bytes.
    pub identity_signature: Vec<u8>,
}

/// The trust level the app records for a contact.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum ContactTrustState {
    /// A Contact Request is open in either direction.
    Pending,
    /// Both sides consented, but the Safety Number wasn't verified out of band.
    Unverified,
    /// The contact's Safety Number was verified out of band.
    Verified,
}

/// A contact as its record holds it, decoded after the host commits.
///
/// The peer's Delivery Capability is not part of it: Roost hands it out only in an established
/// Message's destination.
#[derive(Clone, uniffi::Record)]
pub struct ContactState {
    /// The contact's permanent Identity Key.
    pub identity_key: IdentityKey,
    /// The contact's current Discovery Key, absent for a stranger blocked before they sent
    /// anything.
    pub discovery_key: Option<ContactDiscoveryKey>,
    /// Trust state.
    pub trust_state: ContactTrustState,
    /// Local block flag.
    pub blocked: bool,
}

/// The result of confirming a contact's Safety Number.
#[derive(uniffi::Enum)]
pub enum ContactSafetyNumberConfirmation {
    /// The Safety Number matched. Commit the changes before showing the contact as verified.
    Matched {
        /// The changes that verify the contact.
        changes: StateChanges,
    },
    /// The Safety Number didn't match, and nothing changed.
    Mismatched,
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
    /// Original outbound Message ID.
    pub message_id: MessageId,
    /// Original outbound Message waiting for acknowledgment.
    pub message: Message,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_at_millis: u64,
}

/// An outbound Message and the state changes from one Message Operation.
#[derive(uniffi::Record)]
pub struct OutboundMessageResult {
    /// The Session Roost selected for the Message.
    pub session_id: SessionId,
    /// The draft's MessageID, sealed inside the Message.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Payload kind sealed in the Message.
    pub payload_kind: PayloadKind,
    /// Message to send after durable commit.
    pub message: Message,
    /// State changes to commit atomically with the Message.
    pub changes: StateChanges,
}

/// A provisional receive result. Commit its changes and effects atomically before use.
///
/// Switch on the outcome to obtain only the fields that case permits. The host transaction must
/// check the changes with [`StateChanges::matches`] and persist effects before plaintext is
/// displayed or an acknowledgment is sent.
#[derive(uniffi::Enum)]
pub enum InboundMessageOutcome {
    /// Authenticated plaintext, and an acknowledgment when this side acknowledges, for a unique
    /// Message.
    Accepted {
        /// Payload for this outcome.
        result: InboundMessageResult,
    },
    /// A Contact Request: the first Message from an identity with no contact record, which the
    /// changes record as a Pending contact. Nothing is acknowledged until this side replies.
    ContactRequest {
        /// Payload for this outcome.
        result: InboundMessageResult,
    },
    /// A blocked Message with state changes and the acknowledgment its receive allows.
    Blocked {
        /// Payload for this outcome.
        result: BlockedInboundMessageResult,
    },
    /// A Message past the limit before acceptance, whose plaintext Roost withholds.
    Withheld {
        /// Payload for this outcome.
        result: WithheldInboundMessageResult,
    },
    /// A Grant Update: Roost kept the contact's new Inbox Grant, and there is nothing to show.
    GrantUpdate {
        /// Payload for this outcome.
        result: GrantUpdateResult,
    },
    /// An already accepted encrypted Message. No effects are produced.
    Duplicate,
    /// The Message names a Session this identity doesn't have and carries no handshake, such as
    /// one it lost. No effects are produced.
    UnknownSession,
    /// The first Message names a Session this identity deleted, so nothing was created. No
    /// effects are produced.
    DeletedSession,
    /// An acknowledgment cleared one of this identity's Pending Acknowledgments. Commit it before
    /// treating the acknowledged Message as delivered. Roost sends no reply to an acknowledgment.
    AcknowledgmentMatched {
        /// Payload for this outcome.
        result: AcknowledgmentResult,
    },
    /// An authenticated acknowledgment named no Pending Acknowledgment, such as one already
    /// cleared. Commit it anyway, so the advanced state recognizes a retry as a duplicate.
    AcknowledgmentUnmatched {
        /// Payload for this outcome.
        result: AcknowledgmentResult,
    },
}

/// Authenticated Message data that remains provisional until the host transaction commits.
///
/// The host commits the Message, acknowledgment, and state changes in one transaction. When the
/// changes carry an operation, the host finalizes it before showing the plaintext. Plaintext is
/// host-owned secret bytes; clear discarded copies promptly.
///
/// A sender's recovery resends a Message under its original MessageID with new bytes, so show one
/// Message per sender and MessageID, and check before notifying, including in a notification
/// extension. When one is already shown, still commit the changes and send the acknowledgment.
#[derive(uniffi::Record)]
pub struct InboundMessageResult {
    /// The Session the Message arrived on.
    pub session_id: SessionId,
    /// Authenticated MessageID.
    pub message_id: MessageId,
    /// Authenticated sender timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Authenticated payload kind.
    pub payload_kind: PayloadKind,
    /// Plaintext for the host to protect and clear after use.
    pub plaintext: Vec<u8>,
    /// Authenticated sender material.
    pub sender_identity: SenderIdentityMaterial,
    /// Encrypted acknowledgment to commit with the Transport Binding the host supplied for it,
    /// absent while the contact isn't accepted and this side doesn't acknowledge yet.
    pub acknowledgment: Option<Message>,
    /// State changes to commit with the accepted Message and acknowledgment.
    pub changes: StateChanges,
}

/// A Message from a contact who hasn't accepted, past the limit on Messages before acceptance.
///
/// Roost withholds its plaintext and sends no acknowledgment. Commit the changes so the Session
/// keeps up.
#[derive(uniffi::Record)]
pub struct WithheldInboundMessageResult {
    /// The Session the Message arrived on.
    pub session_id: SessionId,
    /// Authenticated MessageID.
    pub message_id: MessageId,
    /// State changes to commit before treating the Message as processed.
    pub changes: StateChanges,
}

/// A Grant Update whose Inbox Grant Roost kept, so later Messages reach the contact's current
/// inbox.
///
/// Commit the changes, and the acknowledgment when present, but show nothing.
#[derive(uniffi::Record)]
pub struct GrantUpdateResult {
    /// The Session the Grant Update arrived on.
    pub session_id: SessionId,
    /// Authenticated MessageID.
    pub message_id: MessageId,
    /// Encrypted acknowledgment to commit with the Transport Binding the host supplied for it,
    /// absent while this side doesn't acknowledge the contact yet.
    pub acknowledgment: Option<Message>,
    /// State changes to commit before treating the Grant Update as processed.
    pub changes: StateChanges,
}

/// A blocked receive with no plaintext available to the caller.
///
/// The acknowledgment is present only under the silent-receipt policy. Commit it with the changes
/// before sending; under the default policy the host persists only the processed state.
#[derive(uniffi::Record)]
pub struct BlockedInboundMessageResult {
    /// Acknowledgment when the receive's policy permits one.
    pub acknowledgment: Option<Message>,
    /// State changes to commit before treating the Message as processed.
    pub changes: StateChanges,
}

/// An authenticated acknowledgment and the state it advanced.
#[derive(uniffi::Record)]
pub struct AcknowledgmentResult {
    /// The Session the acknowledgment arrived on.
    pub session_id: SessionId,
    /// The acknowledgment's own MessageID.
    pub message_id: MessageId,
    /// Authenticated sender timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// The outbound MessageID the acknowledgment names.
    pub acknowledged_message_id: MessageId,
    /// Authenticated sender material.
    pub sender_identity: SenderIdentityMaterial,
    /// State changes to commit before clearing the host's own delivery state.
    pub changes: StateChanges,
}

/// Blocked-contact acknowledgment policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum BlockedContactAcknowledgmentPolicy {
    /// Suppress acknowledgments so blocks look like unreachable recipients.
    Unreachable,
    /// Return the acknowledgments an unblocked sender would get, while hiding plaintext.
    SilentReceipt,
}

/// Returns Roost's fixed limits and the Deduplication Set's range.
#[uniffi::export]
pub fn protocol_hardening_limits() -> ProtocolHardeningLimits {
    ProtocolHardeningLimits::from_core(roost_core::ProtocolHardeningLimits::default())
}

#[uniffi::export]
impl Messaging {
    /// Returns all pending acknowledgments for a Session.
    ///
    /// Load the Session's pending-acknowledgment blob from the committed host store.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the SessionID isn't canonical or the snapshot exceeds its
    ///   bounds or repeats an address.
    /// - [`RoostError::ProtocolStateFault`] if the pending-acknowledgment blob is missing or malformed.
    /// - [`RoostError::UnsupportedVersion`] if the stored blob has an unsupported version.
    pub fn pending_acknowledgments(
        &self,
        snapshot: Vec<StateEntry>,
        session_id: SessionId,
    ) -> Result<Vec<PendingAcknowledgment>, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(self
            .inner
            .protocol_engine()
            .pending_acknowledgments(&snapshot, session_id.to_core()?)?
            .into_iter()
            .map(PendingAcknowledgment::from_core)
            .collect())
    }
}

#[uniffi::export]
impl Contacts {
    /// Returns the contact a Contact State record holds, or no contact when the entry has no bytes.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the key is malformed.
    /// - [`RoostError::ProtocolStateFault`] if the entry isn't a contact record, or the record is
    ///   malformed or stored under another identity's key.
    /// - [`RoostError::UnsupportedVersion`] if the record has an unsupported version.
    pub fn contact_state(&self, record: StateEntry) -> Result<Option<ContactState>, RoostError> {
        let address = record.key.to_core()?;
        record
            .blob
            .map(|blob| {
                ContactState::from_core(
                    self.inner
                        .protocol_engine()
                        .decode_contact(&address, &CoreProtocolStateBlob::from_bytes(blob))?,
                )
            })
            .transpose()
    }

    /// Returns the contact each Contact State record holds, in the order given.
    ///
    /// Pass the host's committed records of kind [`ProtocolStateKind::ContactState`], so views can
    /// refresh after each commit without Roost keeping subscriptions or cursors.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key is malformed, an entry has no bytes, or there are
    ///   more entries than Roost's limit.
    /// - [`RoostError::ProtocolStateFault`] if an entry isn't a contact record, or a record is
    ///   malformed or stored under another identity's key.
    /// - [`RoostError::UnsupportedVersion`] if a record has an unsupported version.
    pub fn contact_states(
        &self,
        records: Vec<StateEntry>,
    ) -> Result<Vec<ContactState>, RoostError> {
        entries_to_core(records)?
            .into_iter()
            .map(|(address, blob)| {
                let blob = blob.ok_or_else(|| RoostError::InvalidData {
                    reason: "contact entry has no record".into(),
                })?;
                ContactState::from_core(
                    self.inner
                        .protocol_engine()
                        .decode_contact(&address, &blob)?,
                )
            })
            .collect()
    }

    /// Confirms a contact's Safety Number using this context's local Identity, given the record
    /// the host holds for the contact.
    ///
    /// The contact must already be accepted. A mismatch, including malformed presented text,
    /// changes nothing. The local Identity comes from this context's storage and cannot be supplied
    /// by the caller.
    ///
    /// # Errors
    /// - [`RoostError::InternalError`] if a storage lock is poisoned or a state update cannot encode.
    /// - [`RoostError::InvalidData`] if the stored local Identity or a key is malformed.
    /// - [`RoostError::NotFound`] if the context has no local Identity.
    /// - [`RoostError::OperationRecoveryRequired`] if a committed secure operation needs recovery.
    /// - [`RoostError::ProtocolStateFault`] if the record is absent, pending, or malformed.
    /// - [`RoostError::Storage`] if platform storage fails.
    /// - [`RoostError::UnsupportedVersion`] if stored Identity or contact state has an unsupported version.
    pub fn confirm_contact_safety_number(
        &self,
        contact_identity_key: IdentityKey,
        record: Option<Vec<u8>>,
        presented_grouped_decimal: String,
    ) -> Result<ContactSafetyNumberConfirmation, RoostError> {
        let record = record.map(CoreProtocolStateBlob::from_bytes);
        let local = self.inner.load_identity()?;
        ContactSafetyNumberConfirmation::from_core(
            self.inner.protocol_engine().confirm_contact_safety_number(
                roost_core::ContactIdentityKey {
                    x25519_public_key: *local.public_key().as_bytes(),
                    ed25519_verifying_key: *local.verifying_key().as_bytes(),
                },
                contact_identity_key.to_core()?,
                record.as_ref(),
                &presented_grouped_decimal,
            )?,
        )
    }

    /// Unblocks a contact locally, given the record the host holds for them or none.
    ///
    /// Commit the changes before resuming local delivery. Existing Sessions keep working, and the
    /// next Message carries this identity's current Inbox Grant over them. The contact may have
    /// rotated its own inbox during the block, so the first send after an unblock ends with
    /// `NeedsPreKeyBundle`: fetch the contact's bundle by its stored Discovery Key. When the Relay
    /// answers that it doesn't know that key, the contact rotated: keep the draft and ask for a
    /// fresh contact link, whose bundle starts a new Session. When the contact's own request is
    /// still open, that Session's first Message is a Contact Request, which accepts the contact
    /// on both sides. Unblocking a stranger blocked before they sent anything deletes their
    /// record, since nobody asked.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `identity_key` has the wrong length.
    /// - [`RoostError::InternalError`] if the updated contact cannot be encoded.
    /// - [`RoostError::ProtocolStateFault`] if the key is not canonical or the record is malformed.
    /// - [`RoostError::UnsupportedVersion`] if the record has an unsupported version.
    pub fn unblock_contact(
        &self,
        identity_key: IdentityKey,
        record: Option<Vec<u8>>,
    ) -> Result<StateChanges, RoostError> {
        let record = record.map(CoreProtocolStateBlob::from_bytes);
        Ok(StateChanges::from_core(
            self.inner
                .protocol_engine()
                .unblock_contact(identity_key.to_core()?, record.as_ref())?,
        ))
    }
}

/// Derives a Safety Number for two permanent Identity Keys.
#[uniffi::export]
pub fn derive_safety_number(
    first: IdentityKey,
    second: IdentityKey,
) -> Result<SafetyNumber, RoostError> {
    let safety_number = roost_core::derive_safety_number(first.to_core()?, second.to_core()?)?;
    Ok(SafetyNumber {
        raw_bytes: safety_number.raw_bytes.to_vec(),
        grouped_decimal: safety_number.grouped_decimal,
    })
}

#[uniffi::export]
impl StateChanges {
    /// Returns whether every condition still holds for `current`, the host's entry for each
    /// condition's key, read inside the commit's transaction.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `current` misses a condition's key, repeats one, names one
    ///   no condition has, or a key or digest is malformed.
    pub fn matches(&self, current: Vec<StateEntry>) -> Result<bool, RoostError> {
        let current = entries_to_core(current)?;
        let conditions = self
            .conditions
            .iter()
            .map(CommitCondition::to_core)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(roost_core::commit_conditions_match(&conditions, &current)?)
    }
}

impl StateChanges {
    pub(crate) fn from_core(changes: CoreStateChanges) -> Self {
        let conditions = changes
            .conditions()
            .iter()
            .map(|(address, condition)| CommitCondition::from_core(address, *condition))
            .collect();
        Self {
            conditions,
            operation_id: changes.operation().map(OperationId::from_core),
            undelivered: changes
                .undelivered()
                .iter()
                .copied()
                .map(MessageId::from_core)
                .collect(),
            updates: changes
                .into_updates()
                .into_iter()
                .map(StateUpdate::from_core)
                .collect(),
        }
    }
}

impl CommitCondition {
    fn from_core(
        address: &CoreProtocolStateAddress,
        condition: ProtocolStateCommitCondition,
    ) -> Self {
        Self {
            key: StateKey::from_core(address),
            digest: match condition {
                ProtocolStateCommitCondition::Absent => None,
                ProtocolStateCommitCondition::Digest(digest) => Some(digest.to_vec()),
            },
        }
    }

    fn to_core(
        &self,
    ) -> Result<(CoreProtocolStateAddress, ProtocolStateCommitCondition), RoostError> {
        let condition = match &self.digest {
            None => ProtocolStateCommitCondition::Absent,
            Some(digest) => {
                ProtocolStateCommitCondition::Digest(fixed_32(digest, "commit condition digest")?)
            }
        };
        Ok((self.key.to_core()?, condition))
    }
}

impl StateUpdate {
    fn from_core(update: CoreProtocolStateUpdate) -> Self {
        Self {
            key: StateKey::from_core(update.address()),
            blob: update.blob().map(|blob| blob.as_bytes().to_vec()),
        }
    }
}

impl StateKey {
    pub(crate) fn from_core(address: &CoreProtocolStateAddress) -> Self {
        Self {
            kind: ProtocolStateKind::from_core(address.kind()),
            id: hex_text(address.key().as_bytes()),
        }
    }

    pub(crate) fn to_core(&self) -> Result<CoreProtocolStateAddress, RoostError> {
        Ok(CoreProtocolStateAddress::new(
            self.kind.to_core(),
            protocol_key(&self.id)?,
        ))
    }
}

fn protocol_key(id: &str) -> Result<CoreProtocolStateKey, RoostError> {
    CoreProtocolStateKey::from_bytes(hex_bytes(id, "state id")?).map_err(RoostError::from)
}

// Wraps every entry's bytes before checking any key, so a malformed entry leaves no copy behind.
pub(crate) fn entries_to_core(
    mut entries: Vec<StateEntry>,
) -> Result<Vec<(CoreProtocolStateAddress, Option<CoreProtocolStateBlob>)>, RoostError> {
    if entries.len() > roost_core::MAX_PROTOCOL_STATE_ENTRIES {
        for entry in &mut entries {
            if let Some(blob) = &mut entry.blob {
                blob.zeroize();
            }
        }
        return Err(RoostError::InvalidData {
            reason: "too many protocol-state entries".into(),
        });
    }
    let wrapped: Vec<_> = entries
        .into_iter()
        .map(|entry| (entry.key, entry.blob.map(CoreProtocolStateBlob::from_bytes)))
        .collect();
    wrapped
        .into_iter()
        .map(|(key, blob)| Ok((key.to_core()?, blob)))
        .collect()
}

// Builds a snapshot from the host's present records; an entry without bytes adds nothing.
pub(crate) fn snapshot_input_from_entries(
    entries: Vec<StateEntry>,
) -> Result<CoreProtocolStateSnapshot, RoostError> {
    let mut snapshot = CoreProtocolStateSnapshot::new();
    for (address, blob) in entries_to_core(entries)? {
        if snapshot.get(&address).is_some() {
            return Err(RoostError::InvalidData {
                reason: "duplicate protocol-state address".into(),
            });
        }
        if let Some(blob) = blob {
            snapshot.set(address, blob)?;
        }
    }
    Ok(snapshot)
}

impl ProtocolHardeningLimits {
    fn from_core(value: roost_core::ProtocolHardeningLimits) -> Self {
        // Every limit is a fixed constant well inside both target types.
        Self {
            max_encoded_message_len: value.max_encoded_message_len as u64,
            max_message_payload_len: value.max_message_payload_len as u64,
            max_protocol_state_blob_len: value.max_protocol_state_blob_len as u64,
            max_sender_certificate_len: value.max_sender_certificate_len as u64,
            max_sender_signature_len: value.max_sender_signature_len as u64,
            max_pending_acknowledgments: value.max_pending_acknowledgments as u64,
            max_acknowledgment_digests: value.max_acknowledgment_digests as u64,
            min_deduplication_capacity: value.min_deduplication_capacity as u32,
            default_deduplication_capacity: value.default_deduplication_capacity as u32,
            max_deduplication_capacity: value.max_deduplication_capacity as u32,
            max_messages_before_acceptance: value.max_messages_before_acceptance as u32,
        }
    }
}

impl ReceiveSettings {
    pub(crate) fn to_core(self) -> Result<roost_core::ReceiveSettings, RoostError> {
        let deduplication_capacity =
            usize::try_from(self.deduplication_capacity).map_err(|_| RoostError::InvalidData {
                reason: "deduplication capacity exceeds platform range".into(),
            })?;
        Ok(roost_core::ReceiveSettings::new(
            deduplication_capacity,
            self.blocked_contact_acknowledgment_policy.to_core(),
            Duration::from_millis(self.certificate_grace_millis),
        )?)
    }
}

impl BlockedContactAcknowledgmentPolicy {
    fn to_core(self) -> roost_core::BlockedContactAcknowledgmentPolicy {
        match self {
            Self::Unreachable => roost_core::BlockedContactAcknowledgmentPolicy::Unreachable,
            Self::SilentReceipt => roost_core::BlockedContactAcknowledgmentPolicy::SilentReceipt,
        }
    }
}

impl IdentityKey {
    pub(crate) fn from_core(value: roost_core::IdentityKey) -> Self {
        Self {
            agreement_key: value.x25519_public_key.to_vec(),
            signing_key: value.ed25519_verifying_key.to_vec(),
        }
    }

    pub(crate) fn to_core(&self) -> Result<roost_core::IdentityKey, RoostError> {
        Ok(roost_core::IdentityKey {
            x25519_public_key: fixed_32(&self.agreement_key, "identity agreement key")?,
            ed25519_verifying_key: fixed_32(&self.signing_key, "identity signing key")?,
        })
    }
}

impl ContactDiscoveryKey {
    fn from_core(value: roost_core::ContactDiscoveryKey) -> Result<Self, RoostError> {
        Ok(Self {
            x25519_public_key: value.x25519_public_key.to_vec(),
            ed25519_verifying_key: value.ed25519_verifying_key.to_vec(),
            epoch: value.epoch,
            created_at_millis: millis_from_secs(
                value.created_at_secs,
                "contact discovery-key creation time",
            )?,
            identity_signature: value.identity_signature.to_vec(),
        })
    }
}

impl ContactTrustState {
    fn from_core(value: roost_core::ContactTrustState) -> Self {
        match value {
            roost_core::ContactTrustState::Pending => Self::Pending,
            roost_core::ContactTrustState::Unverified => Self::Unverified,
            roost_core::ContactTrustState::Verified => Self::Verified,
        }
    }
}

impl ContactState {
    pub(crate) fn from_core(value: roost_core::ContactState) -> Result<Self, RoostError> {
        Ok(Self {
            identity_key: IdentityKey::from_core(value.identity_key),
            discovery_key: value
                .discovery_key
                .map(ContactDiscoveryKey::from_core)
                .transpose()?,
            trust_state: ContactTrustState::from_core(value.trust_state),
            blocked: value.blocked,
        })
    }
}

impl ContactSafetyNumberConfirmation {
    fn from_core(value: CoreSafetyNumberConfirmation) -> Result<Self, RoostError> {
        Ok(match value {
            CoreSafetyNumberConfirmation::Matched(changes) => Self::Matched {
                changes: StateChanges::from_core(changes),
            },
            CoreSafetyNumberConfirmation::Mismatched => Self::Mismatched,
        })
    }
}

impl PendingAcknowledgment {
    fn from_core(value: roost_core::PendingAcknowledgment) -> Self {
        Self {
            message_id: MessageId::from_core(value.message_id),
            message: Message::from_core(value.message),
            first_sent_at_millis: value.first_sent_at_millis,
        }
    }
}

impl OutboundMessageResult {
    pub(crate) fn from_core(value: roost_core::OutboundMessageResult) -> Self {
        Self {
            session_id: SessionId::from_core(value.session_id),
            message_id: MessageId::from_core(value.message_id),
            sent_at_millis: value.sent_at_millis,
            payload_kind: PayloadKind::from_protocol(value.payload_kind),
            message: Message::from_core(value.message),
            changes: StateChanges::from_core(value.changes),
        }
    }
}

impl InboundMessageResult {
    fn from_core(value: roost_core::InboundMessageResult) -> Self {
        Self {
            session_id: SessionId::from_core(value.session_id),
            message_id: MessageId::from_core(value.message_id),
            sent_at_millis: value.sent_at_millis,
            payload_kind: PayloadKind::from_protocol(value.payload_kind),
            plaintext: value.plaintext.to_vec(),
            sender_identity: SenderIdentityMaterial::from_core(value.sender_identity),
            acknowledgment: value.acknowledgment.map(Message::from_core),
            changes: StateChanges::from_core(value.changes),
        }
    }
}

impl InboundMessageOutcome {
    pub(crate) fn from_core(value: roost_core::InboundMessageOutcome) -> Self {
        match value {
            roost_core::InboundMessageOutcome::Accepted(result) => Self::Accepted {
                result: InboundMessageResult::from_core(*result),
            },
            roost_core::InboundMessageOutcome::ContactRequest(result) => Self::ContactRequest {
                result: InboundMessageResult::from_core(*result),
            },
            roost_core::InboundMessageOutcome::Withheld(result) => Self::Withheld {
                result: WithheldInboundMessageResult {
                    session_id: SessionId::from_core(result.session_id),
                    message_id: MessageId::from_core(result.message_id),
                    changes: StateChanges::from_core(result.changes),
                },
            },
            roost_core::InboundMessageOutcome::GrantUpdate(result) => Self::GrantUpdate {
                result: GrantUpdateResult {
                    session_id: SessionId::from_core(result.session_id),
                    message_id: MessageId::from_core(result.message_id),
                    acknowledgment: result.acknowledgment.map(Message::from_core),
                    changes: StateChanges::from_core(result.changes),
                },
            },
            roost_core::InboundMessageOutcome::Blocked(result) => Self::Blocked {
                result: BlockedInboundMessageResult {
                    acknowledgment: result.acknowledgment.map(Message::from_core),
                    changes: StateChanges::from_core(result.changes),
                },
            },
            roost_core::InboundMessageOutcome::Duplicate => Self::Duplicate,
            roost_core::InboundMessageOutcome::UnknownSession => Self::UnknownSession,
            roost_core::InboundMessageOutcome::DeletedSession => Self::DeletedSession,
            roost_core::InboundMessageOutcome::AcknowledgmentMatched(result) => {
                Self::AcknowledgmentMatched {
                    result: AcknowledgmentResult::from_core(*result),
                }
            }
            roost_core::InboundMessageOutcome::AcknowledgmentUnmatched(result) => {
                Self::AcknowledgmentUnmatched {
                    result: AcknowledgmentResult::from_core(*result),
                }
            }
        }
    }
}

impl AcknowledgmentResult {
    fn from_core(result: roost_core::AcknowledgmentResult) -> Self {
        Self {
            session_id: SessionId::from_core(result.session_id),
            message_id: MessageId::from_core(result.message_id),
            sent_at_millis: result.sent_at_millis,
            acknowledged_message_id: MessageId::from_core(result.acknowledged_message_id),
            sender_identity: SenderIdentityMaterial::from_core(result.sender_identity),
            changes: StateChanges::from_core(result.changes),
        }
    }
}

impl ProtocolStateKind {
    fn from_core(value: roost_core::ProtocolStateKind) -> Self {
        match value {
            roost_core::ProtocolStateKind::RatchetSession => Self::RatchetSession,
            roost_core::ProtocolStateKind::DeduplicationSet => Self::DeduplicationSet,
            roost_core::ProtocolStateKind::PendingAcknowledgments => Self::PendingAcknowledgments,
            roost_core::ProtocolStateKind::ContactState => Self::ContactState,
            roost_core::ProtocolStateKind::PeerSessions => Self::PeerSessions,
        }
    }

    fn to_core(self) -> roost_core::ProtocolStateKind {
        match self {
            Self::RatchetSession => roost_core::ProtocolStateKind::RatchetSession,
            Self::DeduplicationSet => roost_core::ProtocolStateKind::DeduplicationSet,
            Self::PendingAcknowledgments => roost_core::ProtocolStateKind::PendingAcknowledgments,
            Self::ContactState => roost_core::ProtocolStateKind::ContactState,
            Self::PeerSessions => roost_core::ProtocolStateKind::PeerSessions,
        }
    }
}
