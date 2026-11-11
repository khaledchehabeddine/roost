use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MILLIS_PER_SEC: u64 = 1_000;

/// Returns whole seconds since the Unix epoch, or `None` before the epoch.
#[must_use]
pub fn to_unix_secs(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|since_epoch| since_epoch.as_secs())
}

/// Returns whole milliseconds since the Unix epoch, or `None` before the epoch or beyond `u64`.
#[must_use]
pub fn to_unix_millis(time: SystemTime) -> Option<u64> {
    let since_epoch = time.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(since_epoch.as_millis()).ok()
}

/// Returns `secs` Unix seconds as Unix milliseconds, or `None` beyond `u64`.
#[must_use]
pub fn unix_secs_to_millis(secs: u64) -> Option<u64> {
    secs.checked_mul(MILLIS_PER_SEC)
}

/// Returns the time `secs` seconds after the Unix epoch, or `None` if the platform cannot
/// represent it.
#[must_use]
pub fn from_unix_secs(secs: u64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// Returns the time `millis` milliseconds after the Unix epoch, or `None` if the platform cannot
/// represent it.
#[must_use]
pub fn from_unix_millis(millis: u64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_millis(millis))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_units_round_trip() {
        let time = from_unix_millis(1_700_000_000_123).unwrap();
        assert_eq!(to_unix_millis(time), Some(1_700_000_000_123));
        assert_eq!(to_unix_secs(time), Some(1_700_000_000));
        assert_eq!(
            from_unix_secs(1_700_000_000).and_then(to_unix_secs),
            Some(1_700_000_000)
        );
    }

    #[test]
    fn times_before_the_epoch_have_no_unix_timestamp() {
        let before_epoch = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(to_unix_secs(before_epoch), None);
        assert_eq!(to_unix_millis(before_epoch), None);
    }
}
