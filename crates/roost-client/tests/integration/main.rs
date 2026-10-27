//! Flows between hosts through roost-client's exported API.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "a test panics on an unexpected result so the failure reports its line"
)]

mod identity_context;
mod sessions;
mod support;
