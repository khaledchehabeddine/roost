# v0.9.0 Public API Review

This note records the public Rust API review for backup, binding, and distribution-facing release
work. It is audit metadata; source declarations and tests remain authoritative.

## Scope

- Backup export/import: `aether-core::KeyStore`.
- Protocol-state load/commit, wipe, contact, trust, blocking, pending acknowledgment, retry, and
  hardening surfaces: `aether-core::ProtocolStateEngine` and related public records.
- Sealed-sender messages, sender certificates, safety numbers, discovery keys, prekeys, and event
  streams: `aether-core` public records and errors.
- Swift/Kotlin binding declarations: `aether-uniffi` `#[uniffi::export]` objects, records, enums,
  and foreign traits.
- Mobile distribution scripts and workflows: shell/CI interfaces only; no Rust API changes.

## Review Result

- No new Rust public API was required for signed release artifacts or pinned checksums.
- Backup APIs expose encrypted identity backup behavior without exposing secret-bearing internal
  structs.
- Protocol-state APIs preserve opaque host-persisted blobs and return mutation outputs with state
  updates for atomic host commits.
- Binding APIs keep generated Swift/Kotlin outputs as build artifacts, not checked-in source.
- Unsupported major versions for Messages, Protocol State Blobs, and backups surface as faults.
- Release verification scripts are developer/release interfaces, not library APIs.

## Boundary Notes

- Aether performs no network I/O; hosts own transport wrappers and caller-added identifiers outside
  encoded Messages.
- Protocol State Blobs are secret-bearing live key material and require host at-rest protection
  comparable to identity-key storage.
- Identity backup restore is a fresh compromise boundary and does not restore Sessions or Protocol
  State Blobs.
- Post-handshake messages carry sealed Identity Key transcript signatures; first-contact sender
  material uses a sealed key-possession proof. Aether does not provide a deniable messaging mode or
  message franking.
