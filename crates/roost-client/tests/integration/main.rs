//! Flows between hosts through roost-client's exported API.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "clippy.toml's test allowance misses these tests' helper functions, which panic on an unexpected result too"
)]

mod identity_context;
mod sessions;
mod support;
