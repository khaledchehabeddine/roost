//! Verifies the public Core event-stream API across observer cursor and lag boundaries.

use roost_core::{
    EventEnvelope, EventId, EventStream, EventStreamError, EventStreamItem, MAX_OBSERVER_CAPACITY,
};

type TestStream = EventStream<&'static str, Vec<&'static str>>;

fn assert_event(
    item: Option<EventStreamItem<&'static str>>,
    id: u64,
    event: &'static str,
) -> EventEnvelope<&'static str> {
    match item.expect("expected observer item") {
        EventStreamItem::Event(envelope) => {
            assert_eq!(envelope.id().as_u64(), id);
            assert_eq!(*envelope.event(), event);
            envelope
        }
        EventStreamItem::Lagged { missed } => {
            panic!("expected event, got lag signal for {missed} missed events")
        }
        EventStreamItem::Stale => panic!("expected event, got stale-state signal"),
    }
}

fn assert_lagged(item: Option<EventStreamItem<&'static str>>, missed: u64) {
    assert_eq!(item, Some(EventStreamItem::Lagged { missed }));
}

#[test]
fn event_stream_two_observers_receive_same_events_in_same_order_with_independent_cursors() {
    let stream = TestStream::new(Vec::new());
    let first = stream.subscribe().unwrap();
    let second = stream.subscribe().unwrap();

    let first_event = stream.emit("first", vec!["first"]).unwrap();
    let second_event = stream.emit("second", vec!["first", "second"]).unwrap();

    assert_eq!(first_event.id().as_u64(), 1);
    assert_eq!(second_event.id().as_u64(), 2);
    assert_event(first.poll_next().unwrap(), 1, "first");
    assert_eq!(first.cursor().unwrap().as_u64(), 1);
    assert_eq!(second.cursor().unwrap(), EventId::initial());

    assert_event(second.poll_next().unwrap(), 1, "first");
    assert_event(second.poll_next().unwrap(), 2, "second");
    assert_eq!(second.cursor().unwrap().as_u64(), 2);
    assert_eq!(first.cursor().unwrap().as_u64(), 1);

    assert_event(first.poll_next().unwrap(), 2, "second");
    assert_eq!(first.cursor().unwrap().as_u64(), 2);
}

#[test]
fn event_stream_observer_lag_uses_snapshot_tag_to_resume_without_gap_or_replay() {
    let stream = TestStream::with_observer_capacity(Vec::new(), 2).unwrap();
    let observer = stream.subscribe().unwrap();

    stream.emit("one", vec!["one"]).unwrap();
    stream.emit("two", vec!["one", "two"]).unwrap();
    stream.emit("three", vec!["one", "two", "three"]).unwrap();

    assert_lagged(observer.poll_next().unwrap(), 1);
    let snapshot = stream.current_state().unwrap();
    assert_eq!(snapshot.event_id().as_u64(), 3);
    assert_eq!(snapshot.state(), &vec!["one", "two", "three"]);

    stream
        .emit("four", vec!["one", "two", "three", "four"])
        .unwrap();
    observer.resume_after(&snapshot).unwrap();

    assert_eq!(observer.cursor().unwrap().as_u64(), 3);
    assert_event(observer.poll_next().unwrap(), 4, "four");
    assert_eq!(observer.poll_next().unwrap(), None);
}

#[test]
fn importing_current_state_marks_existing_observers_stale_without_advancing_event_id() {
    let stream = TestStream::new(Vec::new());
    let observer = stream.subscribe().unwrap();

    stream.emit("local", vec!["local"]).unwrap();
    assert_event(observer.poll_next().unwrap(), 1, "local");

    let imported = stream
        .import_current_state(vec!["local", "external"])
        .unwrap();

    assert_eq!(imported.event_id().as_u64(), 1);
    assert_eq!(imported.state_revision(), 1);
    assert_eq!(imported.state(), &vec!["local", "external"]);
    assert_eq!(observer.poll_next().unwrap(), Some(EventStreamItem::Stale));
    assert_eq!(observer.cursor().unwrap().as_u64(), 1);

    observer.resume_after(&imported).unwrap();
    assert_eq!(observer.poll_next().unwrap(), None);
    assert_eq!(stream.current_state().unwrap(), imported);
}

#[test]
fn observer_rejects_snapshot_older_than_latest_state_import() {
    let stream = TestStream::new(Vec::new());
    let observer = stream.subscribe().unwrap();

    let first_import = stream.import_current_state(vec!["first"]).unwrap();
    assert_eq!(observer.poll_next().unwrap(), Some(EventStreamItem::Stale));

    let second_import = stream
        .import_current_state(vec!["first", "second"])
        .unwrap();

    assert_eq!(
        observer.resume_after(&first_import),
        Err(EventStreamError::StaleSnapshot {
            snapshot_revision: 1,
            current_revision: 2,
        })
    );
    assert_eq!(observer.poll_next().unwrap(), Some(EventStreamItem::Stale));

    observer.resume_after(&second_import).unwrap();
    assert_eq!(observer.poll_next().unwrap(), None);
}

#[test]
fn observer_rejects_another_streams_snapshot_without_discarding_local_events() {
    let stream = TestStream::new(Vec::new());
    let observer = stream.subscribe().unwrap();
    stream.emit("local one", vec!["local one"]).unwrap();
    stream
        .emit("local two", vec!["local one", "local two"])
        .unwrap();

    let other_stream = TestStream::new(Vec::new());
    other_stream
        .emit("foreign one", vec!["foreign one"])
        .unwrap();
    other_stream
        .emit("foreign two", vec!["foreign one", "foreign two"])
        .unwrap();
    let foreign_snapshot = other_stream.current_state().unwrap();

    assert_eq!(
        observer.resume_after(&foreign_snapshot),
        Err(EventStreamError::SnapshotFromDifferentStream)
    );
    assert_event(observer.poll_next().unwrap(), 1, "local one");
    assert_event(observer.poll_next().unwrap(), 2, "local two");
}

#[test]
fn event_stream_events_dropped_after_snapshot_trigger_next_lag_signal() {
    let stream = TestStream::with_observer_capacity(Vec::new(), 2).unwrap();
    let observer = stream.subscribe().unwrap();

    stream.emit("one", vec!["one"]).unwrap();
    stream.emit("two", vec!["one", "two"]).unwrap();
    stream.emit("three", vec!["one", "two", "three"]).unwrap();

    assert_lagged(observer.poll_next().unwrap(), 1);
    let snapshot = stream.current_state().unwrap();

    stream
        .emit("four", vec!["one", "two", "three", "four"])
        .unwrap();
    stream
        .emit("five", vec!["one", "two", "three", "four", "five"])
        .unwrap();
    stream
        .emit("six", vec!["one", "two", "three", "four", "five", "six"])
        .unwrap();
    observer.resume_after(&snapshot).unwrap();

    assert_lagged(observer.poll_next().unwrap(), 1);
    let latest = stream.current_state().unwrap();
    observer.resume_after(&latest).unwrap();
    assert_eq!(observer.poll_next().unwrap(), None);
}

#[test]
fn event_stream_new_observer_receives_only_events_after_subscription() {
    let stream = TestStream::new(Vec::new());
    stream.emit("before", vec!["before"]).unwrap();

    let observer = stream.subscribe().unwrap();
    assert_eq!(observer.cursor().unwrap().as_u64(), 1);
    assert_eq!(observer.poll_next().unwrap(), None);

    stream.emit("after", vec!["before", "after"]).unwrap();
    assert_event(observer.poll_next().unwrap(), 2, "after");
    assert_eq!(observer.poll_next().unwrap(), None);
}

#[test]
fn event_stream_slow_observer_does_not_block_other_observers() {
    let stream = TestStream::with_observer_capacity(Vec::new(), 1).unwrap();
    let slow = stream.subscribe().unwrap();
    let fast = stream.subscribe().unwrap();

    stream.emit("first", vec!["first"]).unwrap();
    assert_event(fast.poll_next().unwrap(), 1, "first");

    stream.emit("second", vec!["first", "second"]).unwrap();

    assert_event(fast.poll_next().unwrap(), 2, "second");
    assert_lagged(slow.poll_next().unwrap(), 1);
}

#[test]
fn event_stream_invalid_observer_capacities_are_rejected() {
    assert!(matches!(
        TestStream::with_observer_capacity(Vec::new(), 0),
        Err(EventStreamError::InvalidObserverCapacity {
            capacity: 0,
            max: MAX_OBSERVER_CAPACITY
        })
    ));
    assert!(matches!(
        TestStream::with_observer_capacity(Vec::new(), MAX_OBSERVER_CAPACITY + 1),
        Err(EventStreamError::InvalidObserverCapacity {
            capacity,
            max: MAX_OBSERVER_CAPACITY
        }) if capacity == MAX_OBSERVER_CAPACITY + 1
    ));
    assert!(TestStream::with_observer_capacity(Vec::new(), MAX_OBSERVER_CAPACITY).is_ok());
}
