//! Flows between Devices through roost-core's public API, committed through a test host.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "clippy.toml's test allowance misses these tests' helper functions, which panic on an unexpected result too"
)]

mod authenticated_sessions;
mod backup_restore;
mod blocking_rotates_inbox;
mod contact_state;
mod first_contact;
mod grant_updates;
mod inbox_rotation;
mod message_operations;
mod missing_sessions;
mod prekey_ids;
mod prepared_blocking;
mod prepared_identity_host_commit;
mod prepared_inbox_rotation;
mod prepared_key_store_operation_lifecycle;
mod prepared_key_store_operation_recovery;
mod protocol_state;
mod protocol_state_corruption;
mod protocol_state_host_store;
mod protocol_state_trace_properties;
mod recovery;
mod safety_number;
mod support;
mod transport_binding;
mod unblocking;
