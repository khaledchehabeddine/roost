//! The records the app stores for Roost, and the changes it commits to them.

use crate::encoding::{fixed_32, hex_bytes, hex_text};
use crate::error::RoostError;
use crate::message::MessageId;
use crate::operation::OperationId;
use roost_core::{
    ProtocolStateAddress as CoreProtocolStateAddress, ProtocolStateBlob as CoreProtocolStateBlob,
    ProtocolStateCommitCondition, ProtocolStateKey as CoreProtocolStateKey,
    ProtocolStateUpdate as CoreProtocolStateUpdate, StateChanges as CoreStateChanges,
};
use zeroize::Zeroize;

/// Stable category for an opaque protocol-state blob.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, uniffi::Enum)]
pub enum ProtocolStateKind {
    /// A session's encryption state, stored under its session ID.
    RatchetSession,
    /// The deduplication set.
    DeduplicationSet,
    /// A session's pending acknowledgments, stored under its session ID.
    PendingAcknowledgments,
    /// A contact's record, stored under its identity key, which holds the peer's delivery
    /// capability. Read it through [`Contacts::contact_states`](crate::Contacts::contact_states).
    ContactState,
    /// Identity-key-addressed record of the sessions kept with one peer and the one Roost sends
    /// on.
    PeerSessions,
}

/// The name of one record the app stores: its kind and its ID.
///
/// The ID is lowercase hexadecimal. For a contact's records it encodes the contact's identity
/// key, so the app can find every record of one contact without decoding a blob.
#[derive(Clone, Debug, Eq, Hash, PartialEq, uniffi::Record)]
pub struct StateKey {
    /// The record's kind.
    pub kind: ProtocolStateKind,
    /// The record's ID within its kind, in lowercase hexadecimal.
    pub id: String,
}

/// One record as the app holds it, or its absence.
///
/// Roost wraps the bytes and erases its copy once it's done with them.
#[derive(uniffi::Record)]
pub struct StateEntry {
    /// The record's name.
    pub key: StateKey,
    /// The record's bytes, absent when the app holds no record under this key.
    pub blob: Option<Vec<u8>>,
}

/// One record to write when the app commits.
#[derive(uniffi::Record)]
pub struct StateUpdate {
    /// The record's name.
    pub key: StateKey,
    /// The record's new bytes, absent to delete it.
    pub blob: Option<Vec<u8>>,
}

/// What one record must still be when the app commits: unchanged since Roost read it, or still
/// absent.
#[derive(uniffi::Record)]
pub struct CommitCondition {
    /// The record's name.
    pub key: StateKey,
    /// Roost's fingerprint of the record it read, absent when the record must still be absent.
    /// Pass it back unchanged.
    pub digest: Option<Vec<u8>>,
}

/// The records an operation's result relies on, the records it writes, the operation that commits
/// with them, if any, and the sent messages Roost stops waiting for.
///
/// Message operations and delivery checks return these beside their result. They're empty when
/// the result changes nothing, such as a duplicate.
///
/// Inside one transaction, read the record under each condition's key, call [`Self::matches`],
/// and only when it returns `true` write every update together with the result's effects, such as
/// a message to send, and show each of [`Self::undelivered`] that has content as not delivered.
/// When it returns `false`, another operation changed a record first, so roll back and start the
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
/// When the commit's outcome is unknown, neither finalize nor abort, and resolve it at startup
/// instead.
#[derive(uniffi::Record)]
pub struct StateChanges {
    /// Every record the result relies on, including ones it read but doesn't write.
    pub conditions: Vec<CommitCondition>,
    /// The records to write.
    pub updates: Vec<StateUpdate>,
    /// The operation to reserve before the commit and finalize after it, if any.
    pub operation_id: Option<OperationId>,
    /// Sent messages Roost stops waiting for, oldest first, because the relay would have dropped
    /// their first copies by now or the session they wait on is gone.
    pub undelivered: Vec<MessageId>,
}

#[uniffi::export]
impl StateChanges {
    /// Returns whether every condition still holds for `current`, the app's entry for each
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
        let key = CoreProtocolStateKey::from_bytes(hex_bytes(&self.id, "state id")?)?;
        Ok(CoreProtocolStateAddress::new(self.kind.to_core(), key))
    }
}

pub(crate) fn state_keys(addresses: &[CoreProtocolStateAddress]) -> Vec<StateKey> {
    addresses.iter().map(StateKey::from_core).collect()
}

const MAX_STATE_ENTRIES: usize = 4096;

// Wraps every entry's bytes before checking any key, so a malformed entry leaves no copy behind.
pub(crate) fn entries_to_core(
    mut entries: Vec<StateEntry>,
) -> Result<Vec<(CoreProtocolStateAddress, Option<CoreProtocolStateBlob>)>, RoostError> {
    if entries.len() > MAX_STATE_ENTRIES {
        for entry in &mut entries {
            if let Some(blob) = &mut entry.blob {
                blob.zeroize();
            }
        }
        return Err(RoostError::InvalidData {
            reason: format!(
                "{} protocol-state entries exceed the limit of {}",
                entries.len(),
                MAX_STATE_ENTRIES
            ),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(count: usize) -> Vec<StateEntry> {
        (0..count)
            .map(|_| StateEntry {
                key: StateKey {
                    kind: ProtocolStateKind::DeduplicationSet,
                    id: "00".into(),
                },
                blob: None,
            })
            .collect()
    }

    #[test]
    fn entries_to_core_refuses_more_entries_than_the_limit() {
        assert_eq!(
            entries_to_core(entries(MAX_STATE_ENTRIES)).unwrap().len(),
            MAX_STATE_ENTRIES
        );
        assert!(matches!(
            entries_to_core(entries(MAX_STATE_ENTRIES + 1)),
            Err(RoostError::InvalidData { reason })
                if reason == "4097 protocol-state entries exceed the limit of 4096"
        ));
    }
}
