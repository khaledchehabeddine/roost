use crate::context::{Contacts, abort_unconverted};
use crate::error::RoostError;
use crate::identity::IdentityKey;
use crate::publication::{PublicDiscoveryKey, PublicationBundle};
use crate::state::{StateChanges, StateEntry, entries_to_core};
use rand::rngs::OsRng;
use roost_core::{
    ContactSafetyNumberConfirmation as CoreSafetyNumberConfirmation,
    ProtocolStateBlob as CoreProtocolStateBlob,
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

/// The trust level Roost records for a contact, which an acceptance and a safety number
/// confirmation raise.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum ContactTrustState {
    /// A contact request is open in either direction.
    Pending,
    /// Both sides consented, but the safety number wasn't verified out of band.
    Unverified,
    /// The contact's safety number was verified out of band.
    Verified,
}

/// A contact as its record holds it, decoded after the host commits.
///
/// The peer's delivery capability is not part of it: Roost hands it out only in an established
/// message's destination.
#[derive(Clone, uniffi::Record)]
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
    /// Prepares blocking a contact, given the record the host holds for them or none, and rotates
    /// the inbox so the block takes effect at the relay.
    ///
    /// Blocking stops this device sending to the contact and surfacing their messages, even a
    /// stranger's: one with no record gets a record that holds only the block. Rotation replaces
    /// the inbox's prekeys and delivery capability, so a blocked person can't come back with a new
    /// identity at the same address. Blocking an already-blocked contact rotates nothing and
    /// carries no operation.
    ///
    /// When [`ContactBlock::changes`] carries an operation, reserve it, commit the changes with
    /// its ID, then finalize it before registering [`ContactBlock::publication`] as
    /// [`IdentityContext::prepare_inbox_rotation`](crate::IdentityContext::prepare_inbox_rotation)
    /// describes. Abort only after proving the host transaction did not commit. Each block
    /// rotates the inbox once, even for blocks close together.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `identity_key` has the wrong length.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
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
        let operation = block.changes.operation();
        let publication = match block
            .publication
            .map(PublicationBundle::from_core)
            .transpose()
        {
            Ok(publication) => publication,
            Err(error) => return Err(abort_unconverted(&self.inner, operation, error)),
        };
        Ok(ContactBlock {
            changes: StateChanges::from_core(block.changes),
            publication,
        })
    }

    /// Returns the contact a contact state record holds, or no contact when the entry has no bytes.
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

    /// Returns the contact each contact state record holds, in the order given.
    ///
    /// Pass the host's committed records of kind
    /// [`ProtocolStateKind::ContactState`](crate::ProtocolStateKind::ContactState), so views can
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

    /// Confirms a contact's safety number using this context's local identity, given the record
    /// the host holds for the contact.
    ///
    /// The contact must already be accepted. A mismatch, including malformed presented text,
    /// changes nothing. The local identity comes from this context's storage and cannot be supplied
    /// by the caller.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the stored local identity or a key is malformed.
    /// - [`RoostError::NotFound`] if the context has no local identity.
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

    /// Unblocks a contact locally, given the record the host holds for them or none.
    ///
    /// Commit the changes before resuming local delivery. Existing sessions keep working, and the
    /// next message carries this identity's current inbox grant over them. The contact may have
    /// rotated its own inbox during the block, so the first send after an unblock ends with
    /// [`NeedsPreKeyBundle`](crate::MessageEncryptionStep::NeedsPreKeyBundle): fetch the contact's
    /// bundle by its stored discovery key. When the relay answers that it doesn't know that key,
    /// the contact rotated: keep the draft and ask for a fresh contact link. If
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
