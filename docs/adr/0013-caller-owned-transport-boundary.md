# Caller-Owned Transport Boundary

**Status:** Accepted

Encoded Messages and Acknowledgment Artifacts cross the API as opaque protocol values that callers
may send over any route they choose per send. Retry Instructions are host-local scheduling outputs;
callers may retransmit the enclosed Message, but the instruction metadata itself is not a transport
payload. The library performs no network IO, stores no transport routing policy, and does not
authenticate a general transport envelope; any transport-level signing, headers, identifiers,
batching, retry scheduling, rate limiting, or abuse controls belong to the host application. A
caller may opt into authenticating an opaque Transport Binding as sealed-frame associated data, as
defined by [ADR 0021](0021-opaque-transport-bindings.md), but the caller owns its encoding and
meaning. Protocol APIs accept caller-supplied signature bytes where the protocol needs them, while
transport signing and verification remain host-owned and outside the UniFFI surface.

## Considered Options

- Library-selected transport routing. Rejected because the protocol core has no network IO and
  cannot own app-specific delivery, push, Relay, or retry policy.
- Canonical transport-authentication envelope. Rejected because consumers need different metadata
  and versioning contracts; ADR 0021 authenticates opaque caller-owned bytes without defining them.
- Treating transport authentication as sender authenticity. Rejected because sender authenticity is
  established by X3DH identity binding, certificates, and sealed message transcripts after protocol
  authentication, while transport authentication proves only a caller-defined outer channel.

## Consequences

- Caller-added identifiers, headers, push tokens, and route metadata are outside sealed sender
  unless the host includes their canonical encoding in the exact Transport Binding bytes passed to
  a bound operation.
- Release verification checks protocol outputs and artifact authenticity, not host transport
  contracts.

## Verification Evidence

- `docs/security.md` records that transports expose routing metadata and that host applications own
  network IO, rate limiting, batching, and caller-added identifiers.
- `crates/roost-core/tests/transport_binding.rs` verifies authentication of exact caller bytes;
  the `roost-swift` and `roost-kotlin` package tests verify platform conversion.
- `crates/roost-core/docs/adr/0009-encrypted-acknowledgments-and-retries.md` records that
  acknowledgments and retries are returned to the consumer for transport instead of sent by Core.
