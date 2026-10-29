//! Handshakes, ratchets, and Sealed Sender Frames through roost-crypto's public API.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "clippy.toml's test allowance misses these tests' helper functions, which panic on an unexpected result too"
)]

mod peer_session;
mod protocol_properties;
mod sealed_frame;
mod support;
