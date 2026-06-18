# Security

This page records denial-of-service hardening behavior that callers must preserve when integrating
the protocol core.

## Current Guarantees

- Messages authenticate the sealed-sender frame before plaintext, sender identity material, payload
  kind, or Message metadata are surfaced.
- Protocol State Blobs are versioned, opaque caller-persisted values. Unsupported or malformed
  blobs fault instead of silently resetting state.
- X3DH and established Messages bind the peer Identity Key so a Session cannot be relabeled under a
  different verified Identity.
- Replay, skipped-key, acknowledgment, and malformed-input paths are bounded by documented caps.
- Secret-bearing Rust values avoid debug formatting where they own key or plaintext material, and
  heap secrets are wrapped for zeroization at library boundaries.

## Known Limitations

- The library does not provide metadata protection: transport routing data, timing, IP unlinking,
  batching, and traffic-shaping remain host responsibilities.
- The library does not provide endpoint-compromise protection. If a Device, host secure-storage
  implementation, or caller-owned plaintext copy is compromised, the library cannot protect values
  already exposed to that endpoint.
- The library does not implement network rate limiting, abuse throttling, or transport retries.
- Sender Certificate validation is caller-timed and depends on caller-provided trusted signing keys
  and revocation inputs.
- Post-handshake messages carry sealed Identity Key transcript signatures; first-contact sender
  material uses a sealed key-possession proof. Aether does not provide a deniable messaging mode or
  message franking.
- The library does not claim protection against rooted, jailbroken, malware-compromised, or
  otherwise untrusted endpoints.

## Resource Limits

Core rejects externally influenced inputs before expensive work where the boundary is visible:
encoded Messages before parsing or state loading, Protocol State Blobs before version-specific
decode, and Sender Certificate material before validation. Defaults target general mobile clients;
callers on constrained hosts may lower supported limits through the public Rust hardening config.

Default ceilings:

- encoded Message: the sealed-frame encoded limit from `aether-crypto`
- Message ciphertext payload: 128 KiB
- Protocol State Blob: 64 KiB for ratchet/session, deduplication, and contact blobs
- pending-acknowledgment blob: bounded by pending Message and acknowledgment digest caps
- Sender Certificate: 16 KiB
- sender signature: 4 KiB
- deduplication capacity: 1024 by default, configurable from 64 through 2048
- pending acknowledgments: 1024
- processed acknowledgment digests: 1024

Sealed Payload Padding uses fixed buckets from 32 through 65536 bytes. The decrypted payload stores
a 4-byte original-length prefix and zero fill; malformed buckets, impossible lengths, and nonzero
fill reject.

## Caller Responsibilities

Consumers must store Protocol State Blobs in an atomic, durable, crash-consistent, and
integrity-preserving store. Load the required blobs before one operation, commit all returned state
updates atomically with any outbound Message or acknowledgment, and serialize concurrent mutation
for one Identity's protocol state.

Protocol State Blobs are secret-bearing live key material. Protect them at rest with controls
comparable to identity-key storage.

The library does not implement transport batching, IP unlinking, network rate limiting, or
metadata protection. Host applications own those policies and all network I/O. Caller-added
identifiers outside the encoded Message are outside Aether's sealed-sender boundary.

Unsupported major versions for Messages, Protocol State Blobs, and backups reject as faults. They
are not guessed, silently discarded, or reinitialized.

Identity backup restore rewinds only Identity material. Treat restore as a fresh compromise
boundary: wipe or replace Protocol State Blobs before session recovery or re-handshake.

## Replay, Retry, and Skipped Keys

Received encrypted Messages are deduplicated by a bounded, identity-scoped digest window over the
encoded sealed-sender frame bytes. Byte-identical replays return duplicate outcomes without
regenerating user-visible delivery or acknowledgment effects.

Pending acknowledgments and processed acknowledgment digests are bounded. Retry queries update
state only when a retry instruction becomes due; repeated queries at the same reference time do not
create additional churn.

The Double Ratchet enforces per-step and total skipped-key caps. Cap pressure rejects the Message
instead of silently evicting retained skipped keys, and unauthenticated skipped-key pressure does
not mark a Session unrecoverable.

## Prekey Exhaustion

One-time pre-keys are optional in published prekey bundles. When the current one-time pre-key pool
is exhausted, callers may publish a signed-pre-key-only bundle; the X3DH fallback remains valid but
lacks the extra one-time-pre-key Diffie-Hellman contribution.

One-time pre-key generation stays within the current Discovery Key Epoch. Rotating the Discovery
Key clears prior-Epoch one-time pre-key secrets, and stale, missing, consumed, or mismatched
one-time pre-key references fail distinctly at the protocol or KeyStore layer.
