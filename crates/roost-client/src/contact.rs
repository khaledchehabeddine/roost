use crate::context::Contacts;
use crate::error::RoostError;
use crate::identity::IdentityKey;
use crate::publication::{PublicDiscoveryKey, PublicationBundle};
use crate::state::{StateChanges, StateEntry, StateKey, entries_to_core};
use rand::rngs::OsRng;
use roost_core::{
    ContactSafetyNumberConfirmation as CoreSafetyNumberConfirmation,
    ProtocolStateAddress as CoreProtocolStateAddress, ProtocolStateBlob as CoreProtocolStateBlob,
    ProtocolStateKind as CoreProtocolStateKind,
};

/// Result of blocking a contact.
#[derive(uniffi::Record)]
pub struct ContactBlock {
    /// The contact change to commit, carrying the inbox rotation's operation when the block
    /// rotated the inbox.
    pub changes: StateChanges,
    /// The rotated inbox's publication, absent when the contact was already blocked.
    ///
    /// Register it with the relay after finalizing and before sending anything. Every remaining
    /// contact then holds a stale delivery capability until a message, acknowledgment, or grant
    /// update carries them the new inbox grant, which Roost attaches by itself from finalization
    /// on. The blocked contact never gets one, so the block takes effect at the relay.
    pub publication: Option<PublicationBundle>,
}

/// The trust level Roost records for a contact.
#[derive(uniffi::Enum)]
pub enum ContactTrustState {
    /// A contact request is open in either direction.
    Pending,
    /// Both sides consented, but the safety number wasn't verified out of band.
    Unverified,
    /// The contact's safety number was verified out of band.
    Verified,
}

/// A contact as its record holds it, decoded after the app commits.
///
/// The peer's delivery capability isn't part of it, since Roost hands it out only in an established
/// message's destination.
#[derive(uniffi::Record)]
pub struct ContactState {
    /// The contact's permanent identity key.
    pub identity_key: IdentityKey,
    /// The contact's current discovery key, absent for a stranger blocked before they sent
    /// anything.
    pub discovery_key: Option<PublicDiscoveryKey>,
    /// The trust level Roost records for the contact.
    pub trust_state: ContactTrustState,
    /// Whether this device blocked the contact.
    pub blocked: bool,
}

/// The contacts [`Contacts::contact_states`] read, and the records it couldn't.
#[derive(uniffi::Record)]
pub struct ContactStates {
    /// The contact each readable record holds, in the order given.
    pub contacts: Vec<ContactState>,
    /// Each record Roost couldn't read, in the order given.
    pub failures: Vec<ContactStateFailure>,
}

/// A contact state record Roost couldn't read.
#[derive(uniffi::Record)]
pub struct ContactStateFailure {
    /// The record's name.
    pub key: StateKey,
    /// Why Roost couldn't read the record.
    pub kind: ContactStateFailureKind,
    /// Diagnostic context for logging only.
    pub reason: String,
}

/// Why Roost couldn't read a contact state record.
#[derive(Debug, PartialEq, uniffi::Enum)]
pub enum ContactStateFailureKind {
    /// The record is damaged or stored under another identity's key.
    Damaged,
    /// The record uses a format this version of Roost doesn't read, such as one from a newer app.
    NewerFormat,
    /// The entry has no record, or the record holds a value the app can't represent.
    Invalid,
}

/// The result of confirming a contact's safety number.
#[derive(uniffi::Enum)]
pub enum ContactSafetyNumberConfirmation {
    /// The safety number matched. Commit the changes before showing the contact as verified.
    Matched {
        /// The changes that verify the contact.
        changes: StateChanges,
    },
    /// The safety number didn't match, and nothing changed.
    Mismatched,
}

/// Derived safety number.
#[derive(uniffi::Record)]
pub struct SafetyNumber {
    /// Raw derivation bytes.
    pub raw_bytes: Vec<u8>,
    /// Grouped decimal display string.
    pub grouped_decimal: String,
}

/// Derives a safety number for two permanent identity keys.
///
/// # Errors
/// - [`RoostError::InvalidData`] if a key has the wrong length or isn't a valid public key.
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
impl Contacts {
    /// Prepares blocking a contact, given the record the app holds for them or none, and rotates
    /// the inbox so the block takes effect at the relay.
    ///
    /// Blocking stops this device sending to the contact and surfacing their messages, even a
    /// stranger's. A stranger with no record gets a record that holds only the block. Rotation
    /// replaces the inbox's prekeys and delivery capability, so a blocked person can't come back
    /// with a new identity at the same address. Blocking an already-blocked contact rotates nothing
    /// and carries no operation.
    ///
    /// When [`ContactBlock::changes`] carries an operation, reserve it, commit the changes with
    /// its ID, then finalize it before registering [`ContactBlock::publication`] as
    /// [`IdentityContext::prepare_inbox_rotation`](crate::IdentityContext::prepare_inbox_rotation)
    /// describes. Abort only after proving the app's transaction did not commit. Each block
    /// rotates the inbox once, even for blocks close together.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `identity_key` has the wrong length.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::ProtocolStateFault`] if the record is malformed or belongs to someone
    ///   else.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_block_contact(
        &self,
        identity_key: IdentityKey,
        record: Option<Vec<u8>>,
    ) -> Result<ContactBlock, RoostError> {
        let record = record.map(CoreProtocolStateBlob::from_bytes);
        let block = self.inner.prepare_block_contact(
            &mut OsRng,
            identity_key.to_core()?,
            record.as_ref(),
        )?;
        Ok(ContactBlock {
            changes: StateChanges::from_core(block.changes),
            publication: block
                .publication
                .map(PublicationBundle::from_core)
                .transpose()?,
        })
    }

    /// Returns the contact each contact state record holds, and each record Roost couldn't read.
    ///
    /// Pass the app's committed records of kind
    /// [`ProtocolStateKind::ContactState`](crate::ProtocolStateKind::ContactState), so views can
    /// refresh after each commit without Roost keeping subscriptions or cursors. A record Roost
    /// can't read doesn't stop the others from loading. Roost changes nothing for it, so the app
    /// decides whether to keep it, hide it, or ask the user to update. A malformed key, or one
    /// that names another kind of record, fails the whole call instead.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key is malformed or names another kind of record, or
    ///   there are more entries than Roost's limit.
    pub fn contact_states(&self, records: Vec<StateEntry>) -> Result<ContactStates, RoostError> {
        let entries = entries_to_core(records)?;
        if let Some((address, _)) = entries
            .iter()
            .find(|(address, _)| address.kind() != CoreProtocolStateKind::ContactState)
        {
            return Err(RoostError::InvalidData {
                reason: format!("{} entry isn't a contact record", address.kind()),
            });
        }
        let mut states = ContactStates {
            contacts: Vec::new(),
            failures: Vec::new(),
        };
        for (address, blob) in entries {
            match self.contact_state(&address, blob) {
                Ok(contact) => states.contacts.push(contact),
                Err(error) => states.failures.push(ContactStateFailure::from_error(
                    StateKey::from_core(&address),
                    error,
                )?),
            }
        }
        Ok(states)
    }

    /// Confirms a contact's safety number using this context's local identity, given the record
    /// the app holds for the contact.
    ///
    /// The contact must already be accepted. A mismatch, including malformed presented text,
    /// changes nothing.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the stored local identity or a key is malformed.
    /// - [`RoostError::NotFound`] if the context has no local identity.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::ProtocolStateFault`] if the record is absent, pending, or malformed.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    /// - [`RoostError::UnsupportedVersion`] if the stored identity or the record has an unsupported
    ///   version.
    pub fn confirm_contact_safety_number(
        &self,
        contact_identity_key: IdentityKey,
        record: Option<Vec<u8>>,
        presented_grouped_decimal: String,
    ) -> Result<ContactSafetyNumberConfirmation, RoostError> {
        let record = record.map(CoreProtocolStateBlob::from_bytes);
        let local = self.inner.load_identity()?;
        Ok(ContactSafetyNumberConfirmation::from_core(
            self.inner.protocol_engine().confirm_contact_safety_number(
                roost_core::IdentityKey {
                    x25519_public_key: *local.public_key().as_bytes(),
                    ed25519_verifying_key: *local.verifying_key().as_bytes(),
                },
                contact_identity_key.to_core()?,
                record.as_ref(),
                &presented_grouped_decimal,
            )?,
        ))
    }

    /// Unblocks a contact locally, given the record the app holds for them or none.
    ///
    /// Commit the changes before resuming local delivery. Existing sessions keep working, and the
    /// next message carries this identity's current inbox grant over them. The contact may have
    /// rotated its own inbox during the block, so the first send after an unblock ends with
    /// [`NeedsPreKeyBundle`](crate::MessageEncryptionStep::NeedsPreKeyBundle). Fetch the contact's
    /// bundle by its stored discovery key. When the relay answers that it doesn't know that key,
    /// the contact rotated, so keep the draft and ask for a fresh contact link. If
    /// [`is_newer_discovery_key`](crate::is_newer_discovery_key) says its discovery key is newer,
    /// fetch its bundle, which starts a new session. When the contact's own request is still open,
    /// that session's first message is a contact request, which accepts the contact on both sides.
    /// Unblocking a stranger blocked before they sent anything deletes their record, since nobody
    /// asked.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `identity_key` has the wrong length.
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

impl Contacts {
    fn contact_state(
        &self,
        address: &CoreProtocolStateAddress,
        blob: Option<CoreProtocolStateBlob>,
    ) -> Result<ContactState, RoostError> {
        let blob = blob.ok_or_else(|| RoostError::InvalidData {
            reason: "contact entry has no record".into(),
        })?;
        ContactState::from_core(
            self.inner
                .protocol_engine()
                .decode_contact(address, &blob)?,
        )
    }
}

impl ContactStateFailure {
    // Returns the failure for a record that didn't decode, or `error` itself when it isn't about
    // the record.
    fn from_error(key: StateKey, error: RoostError) -> Result<Self, RoostError> {
        let (kind, reason) = match error {
            RoostError::ProtocolStateFault { reason } => (ContactStateFailureKind::Damaged, reason),
            RoostError::UnsupportedVersion { reason } => {
                (ContactStateFailureKind::NewerFormat, reason)
            }
            RoostError::InvalidData { reason } => (ContactStateFailureKind::Invalid, reason),
            other @ (RoostError::AlreadyExists
            | RoostError::AuthenticationFailed { .. }
            | RoostError::BackupFailed { .. }
            | RoostError::BlockedContact { .. }
            | RoostError::CertificateRejected { .. }
            | RoostError::ContactNotAccepted { .. }
            | RoostError::Corrupt
            | RoostError::DecryptionFailed
            | RoostError::InternalError { .. }
            | RoostError::InboxRotationRequired
            | RoostError::NoDeliveryCapability
            | RoostError::NotFound
            | RoostError::OneTimePreKeyUsed { .. }
            | RoostError::OperationFinished
            | RoostError::OperationConflict { .. }
            | RoostError::UnfinishedReservation { .. }
            | RoostError::Storage { .. }
            | RoostError::SecureStoragePreconditionChanged { .. }
            | RoostError::TooManyUnfinishedOperations
            | RoostError::TooManyPendingAcknowledgments { .. }) => return Err(other),
        };
        Ok(Self { key, kind, reason })
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
    fn from_core(value: roost_core::ContactState) -> Result<Self, RoostError> {
        Ok(Self {
            identity_key: IdentityKey::from_core(value.identity_key),
            discovery_key: value
                .discovery_key
                .map(PublicDiscoveryKey::from_contact)
                .transpose()?,
            trust_state: ContactTrustState::from_core(value.trust_state),
            blocked: value.blocked,
        })
    }
}

impl ContactSafetyNumberConfirmation {
    fn from_core(value: CoreSafetyNumberConfirmation) -> Self {
        match value {
            CoreSafetyNumberConfirmation::Matched(changes) => Self::Matched {
                changes: StateChanges::from_core(changes),
            },
            CoreSafetyNumberConfirmation::Mismatched => Self::Mismatched,
        }
    }
}
