//! Conversions between the app's millisecond timestamps and Roost's time values.
//!
//! The app sees every time value in milliseconds. Roost keeps signed values in the unit their
//! encoding fixes, so seconds fields convert here and refuse millisecond inputs they can't
//! represent.

use crate::error::RoostError;
use roost_protocol::{from_unix_millis, unix_secs_to_millis};
use std::time::SystemTime;

const MILLIS_PER_SEC: u64 = 1_000;

// Converts a Unix-seconds value Roost stores to the app's milliseconds.
pub(crate) fn millis_from_secs(secs: u64, label: &str) -> Result<u64, RoostError> {
    unix_secs_to_millis(secs).ok_or_else(|| RoostError::InvalidData {
        reason: format!("{label} exceeds the millisecond range"),
    })
}

// Converts the app's milliseconds to a value Roost signs or authenticates in whole Unix seconds.
pub(crate) fn whole_secs_from_millis(millis: u64, label: &str) -> Result<u64, RoostError> {
    if !millis.is_multiple_of(MILLIS_PER_SEC) {
        return Err(RoostError::InvalidData {
            reason: format!("{label} must be a whole number of seconds"),
        });
    }
    Ok(millis / MILLIS_PER_SEC)
}

// Converts the app's Unix milliseconds to a time Roost decides with.
pub(crate) fn time_from_millis(millis: u64, label: &str) -> Result<SystemTime, RoostError> {
    from_unix_millis(millis).ok_or_else(|| RoostError::InvalidData {
        reason: format!("{label} is out of range"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_seconds_fields_reject_partial_seconds() {
        assert_eq!(
            whole_secs_from_millis(1_700_000_000_000, "created_at_millis").unwrap(),
            1_700_000_000
        );
        assert!(matches!(
            whole_secs_from_millis(1_700_000_000_001, "created_at_millis"),
            Err(RoostError::InvalidData { .. })
        ));
    }

    #[test]
    fn seconds_beyond_the_millisecond_range_are_rejected() {
        assert!(matches!(
            millis_from_secs(u64::MAX, "created_at"),
            Err(RoostError::InvalidData { .. })
        ));
    }
}
