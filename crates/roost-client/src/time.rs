//! Conversions between host millisecond timestamps and Core's time values.
//!
//! Hosts see every time value in milliseconds. Core keeps signed values in the unit their encoding
//! fixes, so seconds fields convert here and reject millisecond inputs they cannot represent.

use crate::error::RoostError;
use roost_protocol::from_unix_millis;
use std::time::SystemTime;

const MILLIS_PER_SEC: u64 = 1_000;

// Converts a Core Unix-seconds value to host milliseconds.
pub(crate) fn millis_from_secs(secs: u64, label: &str) -> Result<u64, RoostError> {
    secs.checked_mul(MILLIS_PER_SEC)
        .ok_or_else(|| RoostError::InvalidData {
            reason: format!("{label} exceeds the millisecond range"),
        })
}

// Converts host milliseconds to a value Core signs or authenticates in whole Unix seconds.
pub(crate) fn whole_secs_from_millis(millis: u64, label: &str) -> Result<u64, RoostError> {
    if !millis.is_multiple_of(MILLIS_PER_SEC) {
        return Err(RoostError::InvalidData {
            reason: format!("{label} must be a whole number of seconds"),
        });
    }
    Ok(millis / MILLIS_PER_SEC)
}

// Converts host Unix milliseconds to a time Core uses for decisions.
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
