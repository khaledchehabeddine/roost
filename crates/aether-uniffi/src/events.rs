//! Contact event-stream bindings.

use crate::error::AetherError;
use crate::protocol::{ContactEvent, ContactState};
use aether_core::{
    ContactEventStream as CoreContactEventStream, EventId, EventObserver as CoreEventObserver,
    EventStreamItem as CoreEventStreamItem, EventStreamSnapshot,
};
use std::sync::Arc;

/// Contact event with its stream identifier.
#[derive(uniffi::Record)]
pub struct ContactEventEnvelope {
    /// Monotonic event ID.
    pub id: u64,
    /// Event value.
    pub event: ContactEvent,
}

/// Current contact state snapshot tagged with the reflected event ID.
#[derive(uniffi::Record)]
pub struct ContactEventSnapshot {
    /// Last event ID reflected by `state`.
    pub event_id: u64,
    /// Complete contact state view.
    pub state: Vec<ContactState>,
}

/// Event observer item kind.
#[derive(uniffi::Enum)]
pub enum ContactEventStreamItemKind {
    /// A committed event is present.
    Event,
    /// The observer lagged and must recover from a snapshot.
    Lagged,
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

/// Per-instance contact event stream.
#[derive(uniffi::Object)]
pub struct ContactEventStream {
    inner: CoreContactEventStream,
}

/// Independent observer over a contact event stream.
#[derive(uniffi::Object)]
pub struct ContactEventObserver {
    inner: CoreEventObserver<aether_core::ContactEvent, Vec<aether_core::ContactState>>,
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

    /// Returns the current state snapshot for lag recovery.
    pub fn current_state(&self) -> Result<ContactEventSnapshot, AetherError> {
        let snapshot = self.inner.current_state()?;
        Ok(ContactEventSnapshot {
            event_id: snapshot.event_id().as_u64(),
            state: snapshot
                .into_state()
                .into_iter()
                .map(ContactState::from_core)
                .collect(),
        })
    }
}

#[uniffi::export]
impl ContactEventObserver {
    /// Returns the next event or lag signal.
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
            None => None,
        })
    }

    /// Returns the observer cursor.
    pub fn cursor(&self) -> Result<u64, AetherError> {
        Ok(self.inner.cursor()?.as_u64())
    }

    /// Resumes the observer after applying a snapshot.
    pub fn resume_after(&self, snapshot: ContactEventSnapshot) -> Result<(), AetherError> {
        let stream_snapshot = EventStreamSnapshot::from_parts(
            EventId::from_u64(snapshot.event_id),
            core_contact_states(snapshot.state)?,
        );
        self.inner.resume_after(&stream_snapshot)?;
        Ok(())
    }
}

fn core_contact_states(
    values: Vec<ContactState>,
) -> Result<Vec<aether_core::ContactState>, AetherError> {
    values.into_iter().map(|state| state.to_core()).collect()
}
