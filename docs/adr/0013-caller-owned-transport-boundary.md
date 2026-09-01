# Caller-Owned Transport Boundary

**Status:** Accepted

Encoded Messages and Acknowledgment Artifacts cross the API as opaque protocol values that callers
may send over any route they choose per send. Retry Instructions are host-local scheduling outputs;
callers may retransmit the enclosed Message, but the instruction metadata itself is not a transport
payload. The library performs no network IO, stores no transport routing policy, and does not
authenticate a general transport envelope; any transport-level signing, headers, identifiers,
batching, retry scheduling, rate limiting, or abuse controls belong to the host application. The
narrow exception is the canonical Relay Route defined by
[ADR 0020](0020-authenticated-relay-route-associated-data.md): its protocol version, route kind,
recipient signing key, and selected prekey identifiers are authenticated as sealed-frame associated
data. Protocol APIs accept caller-supplied signature bytes where the protocol needs them, but
transport signing and verification remain host-owned and outside the UniFFI surface.

## Considered Options

- Library-selected transport routing. Rejected because the protocol core has no network IO and
  cannot own app-specific delivery, push, Relay, or retry policy.
- Canonical transport-authentication envelope. Rejected because callers need transport-specific
  metadata and Relay-facing contracts outside the encrypted Message bytes; ADR 0020 authenticates
  only the minimal cryptographic Relay Route.
- Treating transport authentication as sender authenticity. Rejected because sender authenticity is
  established by X3DH identity binding, certificates, and sealed message transcripts after protocol
  authentication, while transport authentication proves only a caller-defined outer channel.

## Consequences

- Caller-added identifiers, headers, push tokens, and route metadata beyond ADR 0020's canonical
  Relay Route are outside sealed sender and must not be documented as protected by the library.
- Release verification checks protocol outputs and artifact authenticity, not host transport
  contracts.

## Verification Evidence

- `docs/security.md` records that transports expose routing metadata and that host applications own
  network IO, rate limiting, batching, and caller-added identifiers.
- `crates/aether-uniffi/docs/api-coverage.md` records that binding docs avoid transport-routing and
  transport-authentication layout claims.
- `crates/aether-core/docs/adr/0009-encrypted-acknowledgments-and-retries.md` records that
  acknowledgments and retries are returned to the consumer for transport instead of sent by Core.
