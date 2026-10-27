//! Handshakes, ratchets, and Sealed Sender Frames through roost-crypto's public API.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "a test panics on an unexpected result so the failure reports its line"
)]

mod peer_session;
mod protocol_properties;
mod sealed_frame;
mod support;
