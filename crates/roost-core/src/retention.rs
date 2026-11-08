use roost_protocol::from_unix_secs;
use std::time::{Duration, SystemTime};

pub(crate) const SECONDS_PER_DAY: u64 = 86_400;
/// How long the relay may hold a message, so how long Roost keeps the keys that open one and waits
/// for its acknowledgment.
pub(crate) const RELAY_HOLD_TIME: Duration = Duration::from_secs(30 * SECONDS_PER_DAY);
// A stored time this far ahead of the clock counts as expired, so a wrong clock can't keep a key
// forever.
const FUTURE_TOLERANCE: Duration = Duration::from_secs(30 * SECONDS_PER_DAY);

/// Returns whether a stored Unix-seconds timestamp is at least `window` old at `now`, or more than
/// 30 days ahead of it.
pub(crate) fn is_expired(timestamp_secs: u64, now: SystemTime, window: Duration) -> bool {
    let Some(timestamp) = from_unix_secs(timestamp_secs) else {
        return true;
    };
    match now.duration_since(timestamp) {
        Ok(age) => age >= window,
        Err(ahead) => ahead.duration() > FUTURE_TOLERANCE,
    }
}
