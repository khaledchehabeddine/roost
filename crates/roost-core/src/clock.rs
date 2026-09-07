//! A `Clock` abstraction for reading the current time.
//!
//! Code that depends on the current time reads it through this trait instead of calling the
//! system clock directly. Production uses the real system clock and tests inject a fixed clock so
//! time-dependent behavior is reproducible on every run.

use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

// Error returned when a `Clock` cannot produce a valid Unix timestamp.
#[derive(Debug)]
pub(crate) enum ClockError {
    // The underlying time source is before the Unix epoch.
    BeforeEpoch,
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClockError::BeforeEpoch => write!(f, "clock is before Unix epoch"),
        }
    }
}

impl Error for ClockError {}

// A source of the current time.
pub(crate) trait Clock: Send + Sync {
    // Returns the current time in whole seconds since the Unix epoch.
    // Errors with `ClockError::BeforeEpoch` if the time source predates the Unix epoch.
    fn now_unix_secs(&self) -> Result<u64, ClockError>;
}

// The production `Clock`, backed by the operating-system wall clock, wired in by `KeyStore::new`.
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> Result<u64, ClockError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .map_err(|_| ClockError::BeforeEpoch)
    }
}

// A fixed-time `Clock` for deterministic tests. Returns the configured second count.
#[cfg(test)]
pub(crate) struct ManualClock(u64);

#[cfg(test)]
impl ManualClock {
    pub(crate) fn new(now_unix_secs: u64) -> Self {
        ManualClock(now_unix_secs)
    }
}

#[cfg(test)]
impl Clock for ManualClock {
    fn now_unix_secs(&self) -> Result<u64, ClockError> {
        Ok(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_returns_configured_time() {
        assert_eq!(ManualClock::new(42).now_unix_secs().unwrap(), 42);
    }
}
