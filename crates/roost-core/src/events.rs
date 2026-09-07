//! Per-instance state-change event stream primitives.

use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Default number of events buffered per observer.
pub const DEFAULT_OBSERVER_CAPACITY: usize = 64;

/// Maximum supported event buffer size per observer.
pub const MAX_OBSERVER_CAPACITY: usize = 1024;

/// A monotonic identifier assigned when an event is committed to a stream.
///
/// Event ID 0 is reserved for the initial state snapshot. Emitted events start at 1 and form one
/// total order within one [`EventStream`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId(u64);

impl EventId {
    /// Returns the initial snapshot event ID.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Creates an event ID from its raw integer value.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw integer value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

/// An immutable event value with its assigned [`EventId`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventEnvelope<E> {
    id: EventId,
    event: E,
}

impl<E> EventEnvelope<E> {
    /// Returns this event's position in the stream's total order.
    #[must_use]
    pub fn id(&self) -> EventId {
        self.id
    }

    /// Returns the event value.
    #[must_use]
    pub fn event(&self) -> &E {
        &self.event
    }

    /// Consumes the envelope and returns the event value.
    #[must_use]
    pub fn into_event(self) -> E {
        self.event
    }
}

/// A stream-bound state snapshot tagged with the local [`EventId`] and state revision it reflects.
///
/// [`EventStream::current_state`] and [`EventStream::import_current_state`] create snapshots. A
/// snapshot can resume observers from that stream, but not observers from another stream whose
/// numeric Event ID happens to match.
///
/// # Examples
/// ```
/// use roost_core::EventStream;
///
/// let stream = EventStream::<&str, Vec<&str>>::new(Vec::new());
/// let snapshot = stream.current_state()?;
/// assert_eq!(snapshot.event_id().as_u64(), 0);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct EventStreamSnapshot<S> {
    origin: Arc<StreamOrigin>,
    event_id: EventId,
    state_revision: u64,
    state: S,
}

impl<S> EventStreamSnapshot<S> {
    /// Returns the last event ID reflected by this snapshot.
    #[must_use]
    pub fn event_id(&self) -> EventId {
        self.event_id
    }

    /// Returns the local state revision reflected by this snapshot.
    ///
    /// The revision advances when current state is imported without emitting an event. It is local
    /// to one [`EventStream`] and is not a durable Protocol State Blob version.
    #[must_use]
    pub fn state_revision(&self) -> u64 {
        self.state_revision
    }

    /// Returns the self-contained state value.
    #[must_use]
    pub fn state(&self) -> &S {
        &self.state
    }
}

impl<S> PartialEq for EventStreamSnapshot<S>
where
    S: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.origin, &other.origin)
            && self.event_id == other.event_id
            && self.state_revision == other.state_revision
            && self.state == other.state
    }
}

impl<S> Eq for EventStreamSnapshot<S> where S: Eq {}

/// The next item available to an event observer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventStreamItem<E> {
    /// A committed event in stream order.
    Event(EventEnvelope<E>),
    /// The observer missed `missed` events and must recover from a current-state snapshot.
    Lagged {
        /// Number of events missed since the last lag signal.
        missed: u64,
    },
    /// The observer's state is stale because current state was imported without a stream event.
    Stale,
}

/// Errors returned by event-stream operations.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventStreamError {
    /// The event ID counter reached its maximum value.
    EventIdOverflow,
    /// The observer capacity is outside supported bounds.
    InvalidObserverCapacity {
        /// Requested per-observer capacity.
        capacity: usize,
        /// Maximum supported per-observer capacity.
        max: usize,
    },
    /// The internal event-stream lock was poisoned by a panicked thread.
    LockPoisoned,
    /// The internal observer identifier counter reached its maximum value.
    ObserverIdOverflow,
    /// The observer is no longer registered with its stream.
    ObserverClosed,
    /// The snapshot belongs to another event stream.
    SnapshotFromDifferentStream,
    /// The snapshot names an event the stream has not emitted.
    SnapshotEventIdInFuture {
        /// Event ID carried by the rejected snapshot.
        snapshot_event_id: EventId,
        /// Latest Event ID emitted by the stream.
        current_event_id: EventId,
    },
    /// The local state revision counter reached its maximum value.
    StateRevisionOverflow,
    /// A snapshot predates the stream's latest current-state import.
    StaleSnapshot {
        /// State revision carried by the rejected snapshot.
        snapshot_revision: u64,
        /// Latest state revision held by the stream.
        current_revision: u64,
    },
}

impl fmt::Display for EventStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventIdOverflow => write!(f, "event ID counter overflowed"),
            Self::InvalidObserverCapacity { capacity, max } => write!(
                f,
                "event observer capacity is outside supported bounds: {capacity} > 0 and <= {max}"
            ),
            Self::LockPoisoned => write!(f, "internal event-stream lock poisoned"),
            Self::ObserverIdOverflow => write!(f, "event observer ID counter overflowed"),
            Self::ObserverClosed => write!(f, "event observer is closed"),
            Self::SnapshotFromDifferentStream => {
                write!(f, "event-stream snapshot belongs to another stream")
            }
            Self::SnapshotEventIdInFuture {
                snapshot_event_id,
                current_event_id,
            } => write!(
                f,
                "event-stream snapshot ID {} is ahead of current ID {}",
                snapshot_event_id.as_u64(),
                current_event_id.as_u64()
            ),
            Self::StateRevisionOverflow => write!(f, "state revision counter overflowed"),
            Self::StaleSnapshot {
                snapshot_revision,
                current_revision,
            } => write!(
                f,
                "stale event-stream snapshot revision {snapshot_revision}; current revision is {current_revision}"
            ),
        }
    }
}

impl Error for EventStreamError {}

/// A per-instance event stream with one total order and independent observers.
///
/// Subscribe before the operation whose events matter; new observers receive only events emitted
/// after subscription. Each observer has a bounded buffer. When that buffer overflows, the
/// observer receives [`EventStreamItem::Lagged`] with the missed-event count and should recover by
/// reading [`EventStream::current_state`] and calling [`EventObserver::resume_after`].
/// A host that imports current state rebuilt from durable storage does not emit an event; existing
/// observers receive [`EventStreamItem::Stale`] and recover through the same snapshot flow.
///
/// This stream is scoped to one library instance. Events from other instances arrive through the
/// shared protocol-state store, not through this in-process stream. Future producers must put the
/// complete public change snapshot in each event value, and trust-change events must wait until
/// trust state exists.
///
/// # Examples
/// ```
/// use roost_core::{EventStream, EventStreamItem};
///
/// let stream = EventStream::with_observer_capacity(Vec::<&str>::new(), 1)?;
/// let observer = stream.subscribe()?;
///
/// stream.emit("first", vec!["first"])?;
/// let Some(EventStreamItem::Event(event)) = observer.poll_next()? else {
///     panic!("expected first event");
/// };
/// assert_eq!(event.id().as_u64(), 1);
///
/// stream.emit("second", vec!["first", "second"])?;
/// stream.emit("third", vec!["first", "second", "third"])?;
/// assert_eq!(
///     observer.poll_next()?,
///     Some(EventStreamItem::Lagged { missed: 1 })
/// );
///
/// let snapshot = stream.current_state()?;
/// assert_eq!(snapshot.event_id().as_u64(), 3);
/// observer.resume_after(&snapshot)?;
/// assert_eq!(observer.poll_next()?, None);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct EventStream<E, S> {
    inner: Arc<Mutex<EventStreamInner<E, S>>>,
}

/// An observer with an independent cursor over an [`EventStream`].
///
/// The cursor is the last event ID reflected by this observer. It advances when the observer
/// consumes an event or resumes after a tagged snapshot.
pub struct EventObserver<E, S> {
    stream: Arc<Mutex<EventStreamInner<E, S>>>,
    id: ObserverId,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ObserverId(u64);

#[derive(Debug)]
struct StreamOrigin;

struct EventStreamInner<E, S> {
    last_event_id: EventId,
    observer_capacity: usize,
    next_observer_id: ObserverId,
    origin: Arc<StreamOrigin>,
    state_revision: u64,
    state: S,
    observers: BTreeMap<ObserverId, ObserverState<E>>,
}

struct ObserverState<E> {
    cursor: EventId,
    buffer: VecDeque<EventEnvelope<E>>,
    missed: u64,
    needs_resume: bool,
    stale: bool,
}

impl<E, S> EventStream<E, S>
where
    E: Clone,
    S: Clone,
{
    /// Creates a stream with the default per-observer buffer capacity.
    #[must_use]
    pub fn new(initial_state: S) -> Self {
        Self::with_capacity_unchecked(initial_state, DEFAULT_OBSERVER_CAPACITY)
    }

    /// Creates a stream with an explicit per-observer buffer capacity.
    ///
    /// # Errors
    /// - [`EventStreamError::InvalidObserverCapacity`] if `observer_capacity` is 0 or greater
    ///   than [`MAX_OBSERVER_CAPACITY`].
    pub fn with_observer_capacity(
        initial_state: S,
        observer_capacity: usize,
    ) -> Result<Self, EventStreamError> {
        validate_observer_capacity(observer_capacity)?;
        Ok(Self::with_capacity_unchecked(
            initial_state,
            observer_capacity,
        ))
    }

    /// Subscribes a new observer at the current stream cursor.
    ///
    /// The observer receives only events emitted after this call returns.
    ///
    /// # Errors
    /// - [`EventStreamError::LockPoisoned`] if the stream lock was poisoned.
    /// - [`EventStreamError::ObserverIdOverflow`] if the internal observer ID counter overflowed.
    pub fn subscribe(&self) -> Result<EventObserver<E, S>, EventStreamError> {
        let mut inner = self.lock_inner()?;
        let id = inner.next_observer_id;
        inner.next_observer_id = id.next().ok_or(EventStreamError::ObserverIdOverflow)?;
        let cursor = inner.last_event_id;
        let observer_capacity = inner.observer_capacity;
        inner.observers.insert(
            id,
            ObserverState {
                cursor,
                buffer: VecDeque::with_capacity(observer_capacity),
                missed: 0,
                needs_resume: false,
                stale: false,
            },
        );
        Ok(EventObserver {
            stream: Arc::clone(&self.inner),
            id,
        })
    }

    /// Commits `event` and `next_state` to the stream in one total order.
    ///
    /// The assigned event ID and state snapshot tag are fixed together at this commit point.
    /// Producers never wait for observers to drain their buffers; slow observers receive lag
    /// signals when their bounded buffers overflow.
    ///
    /// # Errors
    /// - [`EventStreamError::EventIdOverflow`] if no further event IDs can be assigned.
    /// - [`EventStreamError::LockPoisoned`] if the stream lock was poisoned.
    pub fn emit(&self, event: E, next_state: S) -> Result<EventEnvelope<E>, EventStreamError> {
        let mut inner = self.lock_inner()?;
        let id = inner
            .last_event_id
            .next()
            .ok_or(EventStreamError::EventIdOverflow)?;
        let envelope = EventEnvelope { id, event };
        inner.last_event_id = id;
        inner.state = next_state;
        let observer_capacity = inner.observer_capacity;
        for observer in inner.observers.values_mut() {
            observer.push(envelope.clone(), observer_capacity);
        }
        Ok(envelope)
    }

    /// Returns a self-contained state snapshot tagged with the reflected event ID.
    ///
    /// Lagged observers use this snapshot to replace local state, then call
    /// [`EventObserver::resume_after`] to continue after the snapshot tag without a gap.
    ///
    /// # Errors
    /// - [`EventStreamError::LockPoisoned`] if the stream lock was poisoned.
    pub fn current_state(&self) -> Result<EventStreamSnapshot<S>, EventStreamError> {
        let inner = self.lock_inner()?;
        Ok(EventStreamSnapshot {
            origin: Arc::clone(&inner.origin),
            event_id: inner.last_event_id,
            state_revision: inner.state_revision,
            state: inner.state.clone(),
        })
    }

    /// Imports rebuilt current state without emitting a cross-instance event.
    ///
    /// The caller must rebuild `state` from the latest committed durable state while holding the
    /// same host-owned serializer used for protocol-state mutation. The import leaves the local
    /// Event ID unchanged, advances the local state revision, and causes existing observers to
    /// receive [`EventStreamItem::Stale`]. Those observers must apply a fresh snapshot and call
    /// [`EventObserver::resume_after`].
    ///
    /// # Errors
    /// - [`EventStreamError::LockPoisoned`] if the stream lock was poisoned.
    /// - [`EventStreamError::StateRevisionOverflow`] if no further state revisions can be assigned.
    ///
    /// # Examples
    /// ```
    /// use roost_core::{EventStream, EventStreamItem};
    ///
    /// let stream = EventStream::<&str, Vec<&str>>::new(Vec::new());
    /// let observer = stream.subscribe()?;
    /// let snapshot = stream.import_current_state(vec!["committed"])?;
    ///
    /// assert_eq!(observer.poll_next()?, Some(EventStreamItem::Stale));
    /// observer.resume_after(&snapshot)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn import_current_state(
        &self,
        state: S,
    ) -> Result<EventStreamSnapshot<S>, EventStreamError> {
        let mut inner = self.lock_inner()?;
        inner.state_revision = inner
            .state_revision
            .checked_add(1)
            .ok_or(EventStreamError::StateRevisionOverflow)?;
        inner.state = state;
        for observer in inner.observers.values_mut() {
            observer.buffer.clear();
            observer.missed = 0;
            observer.needs_resume = false;
            observer.stale = true;
        }
        Ok(EventStreamSnapshot {
            origin: Arc::clone(&inner.origin),
            event_id: inner.last_event_id,
            state_revision: inner.state_revision,
            state: inner.state.clone(),
        })
    }

    fn with_capacity_unchecked(initial_state: S, observer_capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(EventStreamInner {
                last_event_id: EventId::initial(),
                observer_capacity,
                next_observer_id: ObserverId(0),
                origin: Arc::new(StreamOrigin),
                state_revision: 0,
                state: initial_state,
                observers: BTreeMap::new(),
            })),
        }
    }

    fn lock_inner(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, EventStreamInner<E, S>>, EventStreamError> {
        self.inner
            .lock()
            .map_err(|_| EventStreamError::LockPoisoned)
    }
}

impl<E, S> EventObserver<E, S>
where
    E: Clone,
    S: Clone,
{
    /// Returns the next event, lag signal, or stale-state signal available to this observer.
    ///
    /// If this returns [`EventStreamItem::Lagged`], call [`EventStream::current_state`] on the
    /// owning stream, replace local state with that snapshot, then call
    /// [`Self::resume_after`] before consuming later events. Follow the same recovery flow after
    /// [`EventStreamItem::Stale`].
    ///
    /// # Errors
    /// - [`EventStreamError::LockPoisoned`] if the stream lock was poisoned.
    /// - [`EventStreamError::ObserverClosed`] if this observer is no longer registered.
    pub fn poll_next(&self) -> Result<Option<EventStreamItem<E>>, EventStreamError> {
        let mut inner = self.lock_inner()?;
        let observer = inner
            .observers
            .get_mut(&self.id)
            .ok_or(EventStreamError::ObserverClosed)?;
        if observer.stale {
            observer.stale = false;
            observer.needs_resume = true;
            return Ok(Some(EventStreamItem::Stale));
        }
        if observer.missed > 0 {
            let missed = observer.missed;
            observer.missed = 0;
            observer.needs_resume = true;
            return Ok(Some(EventStreamItem::Lagged { missed }));
        }
        if observer.needs_resume {
            return Ok(None);
        }
        let Some(envelope) = observer.buffer.pop_front() else {
            return Ok(None);
        };
        observer.cursor = envelope.id();
        Ok(Some(EventStreamItem::Event(envelope)))
    }

    /// Returns the last event ID reflected by this observer.
    ///
    /// # Errors
    /// - [`EventStreamError::LockPoisoned`] if the stream lock was poisoned.
    /// - [`EventStreamError::ObserverClosed`] if this observer is no longer registered.
    pub fn cursor(&self) -> Result<EventId, EventStreamError> {
        let inner = self.lock_inner()?;
        Ok(inner
            .observers
            .get(&self.id)
            .ok_or(EventStreamError::ObserverClosed)?
            .cursor)
    }

    /// Resumes this observer after applying a current snapshot from its stream.
    ///
    /// Queued events at or before the snapshot's event ID are skipped. Queued events after the
    /// snapshot's event ID remain available. The snapshot must come from this stream, cannot name
    /// a future Event ID, and must carry the latest current-state import revision.
    ///
    /// # Errors
    /// - [`EventStreamError::LockPoisoned`] if the stream lock was poisoned.
    /// - [`EventStreamError::ObserverClosed`] if this observer is no longer registered.
    /// - [`EventStreamError::SnapshotFromDifferentStream`] if another stream created the snapshot.
    /// - [`EventStreamError::SnapshotEventIdInFuture`] if the snapshot names an Event ID this
    ///   stream has not emitted.
    /// - [`EventStreamError::StaleSnapshot`] if the snapshot predates the latest current-state
    ///   import.
    pub fn resume_after(&self, snapshot: &EventStreamSnapshot<S>) -> Result<(), EventStreamError> {
        let mut inner = self.lock_inner()?;
        let last_event_id = inner.last_event_id;
        let current_revision = inner.state_revision;
        let same_stream = Arc::ptr_eq(&snapshot.origin, &inner.origin);
        let observer = inner
            .observers
            .get_mut(&self.id)
            .ok_or(EventStreamError::ObserverClosed)?;
        if !same_stream {
            return Err(EventStreamError::SnapshotFromDifferentStream);
        }
        if snapshot.event_id > last_event_id {
            return Err(EventStreamError::SnapshotEventIdInFuture {
                snapshot_event_id: snapshot.event_id,
                current_event_id: last_event_id,
            });
        }
        if snapshot.state_revision != current_revision {
            return Err(EventStreamError::StaleSnapshot {
                snapshot_revision: snapshot.state_revision,
                current_revision,
            });
        }
        observer.missed = 0;
        observer.needs_resume = false;
        observer.stale = false;
        if snapshot.event_id > observer.cursor {
            observer.cursor = snapshot.event_id;
        }
        while observer
            .buffer
            .front()
            .is_some_and(|envelope| envelope.id() <= observer.cursor)
        {
            observer.buffer.pop_front();
        }
        observer.update_missed_after_resume(last_event_id);
        Ok(())
    }

    fn lock_inner(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, EventStreamInner<E, S>>, EventStreamError> {
        self.stream
            .lock()
            .map_err(|_| EventStreamError::LockPoisoned)
    }
}

impl ObserverId {
    fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl<E> ObserverState<E> {
    fn push(&mut self, envelope: EventEnvelope<E>, observer_capacity: usize) {
        if self.buffer.len() == observer_capacity {
            self.buffer.pop_front();
            self.missed = self.missed.saturating_add(1);
        }
        self.buffer.push_back(envelope);
    }

    fn update_missed_after_resume(&mut self, last_event_id: EventId) {
        let Some(expected) = self.cursor.next() else {
            self.missed = 0;
            self.needs_resume = false;
            return;
        };
        self.missed = match self.buffer.front() {
            Some(next) if next.id() > expected => next.id().as_u64() - expected.as_u64(),
            None if last_event_id >= expected => last_event_id.as_u64() - expected.as_u64() + 1,
            _ => 0,
        };
        self.needs_resume = self.missed > 0;
    }
}

impl<E, S> Drop for EventObserver<E, S> {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.stream.lock() {
            inner.observers.remove(&self.id);
        }
    }
}

fn validate_observer_capacity(observer_capacity: usize) -> Result<(), EventStreamError> {
    if observer_capacity == 0 || observer_capacity > MAX_OBSERVER_CAPACITY {
        return Err(EventStreamError::InvalidObserverCapacity {
            capacity: observer_capacity,
            max: MAX_OBSERVER_CAPACITY,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_rejects_snapshot_with_future_event_id() {
        let stream = EventStream::<&str, Vec<&str>>::new(Vec::new());
        let observer = stream.subscribe().unwrap();
        let mut snapshot = stream.current_state().unwrap();
        snapshot.event_id = EventId::from_u64(1);

        assert_eq!(
            observer.resume_after(&snapshot),
            Err(EventStreamError::SnapshotEventIdInFuture {
                snapshot_event_id: EventId::from_u64(1),
                current_event_id: EventId::initial(),
            })
        );
    }
}
