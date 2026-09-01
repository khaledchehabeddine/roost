//! Contact event-stream bindings.

use crate::error::AetherError;
use crate::protocol::{ContactEvent, ContactState};
use aether_core::{
    ContactEventStream as CoreContactEventStream, EventObserver as CoreEventObserver,
    EventStreamItem as CoreEventStreamItem, EventStreamSnapshot as CoreEventStreamSnapshot,
};
use std::sync::Arc;

const MAX_IMPORTED_CONTACT_STATES: usize = 4096;

/// Contact event with its stream identifier.
#[derive(uniffi::Record)]
pub struct ContactEventEnvelope {
    /// Monotonic event ID.
    pub id: u64,
    /// Event value.
    pub event: ContactEvent,
}

/// A stream-bound current contact state snapshot.
///
/// The snapshot carries the last local Event ID, the current local State Revision, and the complete
/// public contact view. It also retains private stream provenance, so only an observer created by
/// the same [`ContactEventStream`] can resume from it.
///
/// # Examples
/// ```
/// use aether::ContactEventStream;
///
/// let stream = ContactEventStream::new(Vec::new())?;
/// let snapshot = stream.current_state()?;
/// assert_eq!(snapshot.event_id(), 0);
/// # Ok::<(), aether::AetherError>(())
/// ```
#[derive(uniffi::Object)]
pub struct ContactEventSnapshot {
    inner: CoreEventStreamSnapshot<Vec<aether_core::ContactState>>,
}

impl ContactEventSnapshot {
    fn from_core(inner: CoreEventStreamSnapshot<Vec<aether_core::ContactState>>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

#[uniffi::export]
impl ContactEventSnapshot {
    /// Returns the last local Event ID reflected by this snapshot.
    ///
    /// Event IDs start at zero for each library instance. State imports do not advance them.
    ///
    /// # Examples
    /// ```
    /// use aether::ContactEventStream;
    ///
    /// let stream = ContactEventStream::new(Vec::new())?;
    /// assert_eq!(stream.current_state()?.event_id(), 0);
    /// # Ok::<(), aether::AetherError>(())
    /// ```
    pub fn event_id(&self) -> u64 {
        self.inner.event_id().as_u64()
    }

    /// Returns the local State Revision reflected by this snapshot.
    ///
    /// The revision advances when the stream imports rebuilt state without emitting an Event. It
    /// starts at zero for each library instance and is not a durable blob version.
    ///
    /// # Examples
    /// ```
    /// use aether::ContactEventStream;
    ///
    /// let stream = ContactEventStream::new(Vec::new())?;
    /// let snapshot = stream.import_current_state(Vec::new())?;
    /// assert_eq!(snapshot.state_revision(), 1);
    /// # Ok::<(), aether::AetherError>(())
    /// ```
    pub fn state_revision(&self) -> u64 {
        self.inner.state_revision()
    }

    /// Returns a copy of the complete public contact view.
    ///
    /// Lagged and stale observers replace their cached view with this value before resuming from
    /// the snapshot.
    ///
    /// # Examples
    /// ```
    /// use aether::ContactEventStream;
    ///
    /// let stream = ContactEventStream::new(Vec::new())?;
    /// assert!(stream.current_state()?.state().is_empty());
    /// # Ok::<(), aether::AetherError>(())
    /// ```
    pub fn state(&self) -> Vec<ContactState> {
        self.inner
            .state()
            .iter()
            .cloned()
            .map(ContactState::from_core)
            .collect()
    }
}

/// A category of item returned by a contact observer.
///
/// `Event` carries a committed local change. `Lagged` reports bounded-buffer loss. `Stale` reports
/// that the host imported rebuilt state without creating a cross-instance Event.
///
/// # Examples
/// ```
/// use aether::{ContactEventStream, ContactEventStreamItemKind};
///
/// let stream = ContactEventStream::new(Vec::new())?;
/// let observer = stream.subscribe()?;
/// let _ = stream.import_current_state(Vec::new())?;
/// assert!(matches!(
///     observer.poll_next()?.map(|item| item.kind),
///     Some(ContactEventStreamItemKind::Stale)
/// ));
/// # Ok::<(), aether::AetherError>(())
/// ```
#[derive(uniffi::Enum)]
pub enum ContactEventStreamItemKind {
    /// A committed event is present.
    Event,
    /// The observer lagged and must recover from a snapshot.
    Lagged,
    /// Imported current state made the observer's view stale.
    Stale,
}

/// Next item returned to a contact observer.
#[derive(uniffi::Record)]
pub struct ContactEventStreamItem {
    /// Item kind.
    pub kind: ContactEventStreamItemKind,
    /// Event envelope when `kind` is `Event`.
    pub event: Option<ContactEventEnvelope>,
    /// Missed event count when `kind` is `Lagged`.
    pub missed: Option<u64>,
}

/// A per-instance contact event stream.
///
/// Local commits emit ordered Events. Cross-instance changes arrive through host-owned Protocol
/// State Blobs; the host rebuilds the contact view and imports it without importing foreign Event
/// IDs.
///
/// # Examples
/// ```
/// use aether::ContactEventStream;
///
/// let stream = ContactEventStream::new(Vec::new())?;
/// let observer = stream.subscribe()?;
/// assert_eq!(observer.cursor()?, 0);
/// # Ok::<(), aether::AetherError>(())
/// ```
#[derive(uniffi::Object)]
pub struct ContactEventStream {
    inner: CoreContactEventStream,
}

#[uniffi::export]
impl ContactEventStream {
    /// Creates a stream with default observer capacity.
    #[uniffi::constructor]
    pub fn new(initial_state: Vec<ContactState>) -> Result<Arc<Self>, AetherError> {
        Ok(Arc::new(Self {
            inner: CoreContactEventStream::new(core_contact_states(initial_state)?),
        }))
    }

    /// Creates a stream with explicit observer capacity.
    #[uniffi::constructor]
    pub fn with_observer_capacity(
        initial_state: Vec<ContactState>,
        observer_capacity: u64,
    ) -> Result<Arc<Self>, AetherError> {
        Ok(Arc::new(Self {
            inner: CoreContactEventStream::with_observer_capacity(
                core_contact_states(initial_state)?,
                usize::try_from(observer_capacity).map_err(|_| AetherError::InvalidData {
                    reason: "observer capacity exceeds usize".into(),
                })?,
            )?,
        }))
    }

    /// Subscribes an independent observer.
    pub fn subscribe(&self) -> Result<Arc<ContactEventObserver>, AetherError> {
        Ok(Arc::new(ContactEventObserver {
            inner: self.inner.subscribe()?,
        }))
    }

    /// Emits a contact event after the host commits its corresponding state update.
    pub fn emit(
        &self,
        event: ContactEvent,
        next_state: Vec<ContactState>,
    ) -> Result<ContactEventEnvelope, AetherError> {
        let envelope = self
            .inner
            .emit(event.to_core()?, core_contact_states(next_state)?)?;
        Ok(ContactEventEnvelope {
            id: envelope.id().as_u64(),
            event: ContactEvent::from_core(envelope.into_event()),
        })
    }

    /// Returns the current contact state for lag or stale-state recovery.
    ///
    /// The snapshot carries stream provenance and both local ordering tags. Apply its state, then
    /// pass the same snapshot object to [`ContactEventObserver::resume_after`].
    ///
    /// # Errors
    /// - [`AetherError::InternalError`] if the stream lock is poisoned.
    ///
    /// # Examples
    /// ```
    /// use aether::ContactEventStream;
    ///
    /// let stream = ContactEventStream::new(Vec::new())?;
    /// let snapshot = stream.current_state()?;
    /// assert_eq!(snapshot.event_id(), 0);
    /// # Ok::<(), aether::AetherError>(())
    /// ```
    pub fn current_state(&self) -> Result<Arc<ContactEventSnapshot>, AetherError> {
        Ok(ContactEventSnapshot::from_core(self.inner.current_state()?))
    }

    /// Imports current contact state rebuilt from committed Protocol State Blobs.
    ///
    /// The host must reconstruct `state` through [`crate::ProtocolStateEngine::contact_states`]
    /// while holding its protocol-state serializer. The import does not emit a contact event or
    /// accept another Library Instance's Event ID. Existing observers receive a stale-state item
    /// and must resume from a fresh snapshot.
    ///
    /// # Errors
    /// - [`AetherError::InvalidData`] if the snapshot exceeds 4096 contacts or any contact key or
    ///   signature has the wrong length.
    /// - [`AetherError::InternalError`] if the stream lock is poisoned or the local State Revision
    ///   overflows.
    ///
    /// # Examples
    /// ```
    /// use aether::{ContactEventStream, ContactEventStreamItemKind, ProtocolStateEngine};
    ///
    /// let engine = ProtocolStateEngine::new();
    /// let stream = ContactEventStream::new(Vec::new())?;
    /// let observer = stream.subscribe()?;
    /// let rebuilt = engine.contact_states(Vec::new())?;
    /// let snapshot = stream.import_current_state(rebuilt)?;
    ///
    /// assert!(matches!(
    ///     observer.poll_next()?.map(|item| item.kind),
    ///     Some(ContactEventStreamItemKind::Stale)
    /// ));
    /// observer.resume_after(snapshot)?;
    /// # Ok::<(), aether::AetherError>(())
    /// ```
    pub fn import_current_state(
        &self,
        state: Vec<ContactState>,
    ) -> Result<Arc<ContactEventSnapshot>, AetherError> {
        validate_imported_contact_state_count(state.len())?;
        Ok(ContactEventSnapshot::from_core(
            self.inner
                .import_current_state(core_contact_states(state)?)?,
        ))
    }
}

/// An independent observer over one contact event stream.
///
/// The observer owns a local cursor and bounded buffer. After a lag or stale-state item, it pauses
/// until the host applies a fresh snapshot from the same stream and resumes it.
///
/// # Examples
/// ```
/// use aether::ContactEventStream;
///
/// let stream = ContactEventStream::new(Vec::new())?;
/// let observer = stream.subscribe()?;
/// assert_eq!(observer.cursor()?, 0);
/// # Ok::<(), aether::AetherError>(())
/// ```
#[derive(uniffi::Object)]
pub struct ContactEventObserver {
    inner: CoreEventObserver<aether_core::ContactEvent, Vec<aether_core::ContactState>>,
}

#[uniffi::export]
impl ContactEventObserver {
    /// Returns the next event, lag signal, or stale-state signal.
    ///
    /// A lag or stale-state item pauses delivery. Fetch and apply
    /// [`ContactEventStream::current_state`], then call [`Self::resume_after`] before polling later
    /// Events.
    ///
    /// # Errors
    /// - [`AetherError::EventStreamClosed`] if this observer is no longer registered.
    /// - [`AetherError::InternalError`] if the stream lock is poisoned.
    ///
    /// # Examples
    /// ```
    /// use aether::{ContactEventStream, ContactEventStreamItemKind};
    ///
    /// let stream = ContactEventStream::new(Vec::new())?;
    /// let observer = stream.subscribe()?;
    /// let _ = stream.import_current_state(Vec::new())?;
    /// assert!(matches!(
    ///     observer.poll_next()?.map(|item| item.kind),
    ///     Some(ContactEventStreamItemKind::Stale)
    /// ));
    /// # Ok::<(), aether::AetherError>(())
    /// ```
    pub fn poll_next(&self) -> Result<Option<ContactEventStreamItem>, AetherError> {
        Ok(match self.inner.poll_next()? {
            Some(CoreEventStreamItem::Event(envelope)) => Some(ContactEventStreamItem {
                kind: ContactEventStreamItemKind::Event,
                event: Some(ContactEventEnvelope {
                    id: envelope.id().as_u64(),
                    event: ContactEvent::from_core(envelope.into_event()),
                }),
                missed: None,
            }),
            Some(CoreEventStreamItem::Lagged { missed }) => Some(ContactEventStreamItem {
                kind: ContactEventStreamItemKind::Lagged,
                event: None,
                missed: Some(missed),
            }),
            Some(CoreEventStreamItem::Stale) => Some(ContactEventStreamItem {
                kind: ContactEventStreamItemKind::Stale,
                event: None,
                missed: None,
            }),
            None => None,
        })
    }

    /// Returns the observer's last reflected local Event ID.
    ///
    /// The cursor advances when the observer consumes an Event or resumes from a snapshot. It does
    /// not advance when the stream imports rebuilt state.
    ///
    /// # Errors
    /// - [`AetherError::EventStreamClosed`] if this observer is no longer registered.
    /// - [`AetherError::InternalError`] if the stream lock is poisoned.
    ///
    /// # Examples
    /// ```
    /// use aether::ContactEventStream;
    ///
    /// let stream = ContactEventStream::new(Vec::new())?;
    /// let observer = stream.subscribe()?;
    /// assert_eq!(observer.cursor()?, 0);
    /// # Ok::<(), aether::AetherError>(())
    /// ```
    pub fn cursor(&self) -> Result<u64, AetherError> {
        Ok(self.inner.cursor()?.as_u64())
    }

    /// Resumes the observer after the host applies a current snapshot from its stream.
    ///
    /// The snapshot object preserves its stream provenance. A snapshot from another stream is
    /// rejected even when both numeric Event IDs and State Revisions match.
    ///
    /// # Errors
    /// - [`AetherError::EventStreamClosed`] if this observer is no longer registered.
    /// - [`AetherError::ForeignEventSnapshot`] if another stream created the snapshot.
    /// - [`AetherError::StaleEventSnapshot`] if the snapshot predates the latest current-state
    ///   import.
    /// - [`AetherError::InternalError`] if the stream lock is poisoned or the snapshot contains an
    ///   impossible future Event ID.
    ///
    /// # Examples
    /// ```
    /// use aether::{ContactEventStream, ContactEventStreamItemKind};
    ///
    /// let stream = ContactEventStream::new(Vec::new())?;
    /// let observer = stream.subscribe()?;
    /// let snapshot = stream.import_current_state(Vec::new())?;
    /// assert!(matches!(
    ///     observer.poll_next()?.map(|item| item.kind),
    ///     Some(ContactEventStreamItemKind::Stale)
    /// ));
    /// observer.resume_after(snapshot)?;
    /// # Ok::<(), aether::AetherError>(())
    /// ```
    pub fn resume_after(&self, snapshot: Arc<ContactEventSnapshot>) -> Result<(), AetherError> {
        self.inner.resume_after(&snapshot.inner)?;
        Ok(())
    }
}

fn core_contact_states(
    values: Vec<ContactState>,
) -> Result<Vec<aether_core::ContactState>, AetherError> {
    values.into_iter().map(|state| state.to_core()).collect()
}

fn validate_imported_contact_state_count(count: usize) -> Result<(), AetherError> {
    if count > MAX_IMPORTED_CONTACT_STATES {
        return Err(AetherError::InvalidData {
            reason: format!(
                "contact state snapshot contains {count} entries; maximum is {MAX_IMPORTED_CONTACT_STATES}"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imported_contact_state_count_is_bounded() {
        assert!(matches!(
            validate_imported_contact_state_count(MAX_IMPORTED_CONTACT_STATES + 1),
            Err(AetherError::InvalidData { .. })
        ));
    }
}
