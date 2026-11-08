//! Flows between devices through the public API, committed through a test app.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

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
mod prepared_identity_app_commit;
mod prepared_key_store_operation_lifecycle;
mod prepared_key_store_operation_restarts;
mod protocol_state;
mod protocol_state_app_database;
mod protocol_state_corruption;
mod protocol_state_trace_properties;
mod recovery;
mod support;
mod transport_binding;
mod unblocking;
