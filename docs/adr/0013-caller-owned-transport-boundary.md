# Caller-Owned Transport Boundary

**Status:** Accepted

Encoded Messages and Acknowledgment Artifacts cross the API as opaque protocol values that callers
may send over any route they choose per send. Retry Instructions are host-local scheduling outputs;
callers may retransmit the enclosed Message, but the instruction metadata itself is not a transport
payload. The library performs no network IO, stores no transport routing policy, and does not
authenticate a transport envelope; any transport-level signing, headers, identifiers, batching,
retry scheduling, rate limiting, or abuse controls belong to the host application. Protocol APIs
accept caller-supplied signature bytes where the protocol needs them, but transport signing and
verification are host-owned and outside the UniFFI surface, so they do not define a canonical
transport-authentication layout or make caller-added identifiers part of the sealed-sender boundary.

## Considered Options

- Library-selected transport routing. Rejected because the protocol core has no network IO and
  cannot own app-specific delivery, push, Relay, or retry policy.
- Canonical transport-authentication envelope. Rejected because callers need transport-specific
  metadata and Relay-facing contracts outside the encrypted Message bytes.
- Treating transport authentication as sender authenticity. Rejected because sender authenticity is
  established by X3DH identity binding, certificates, and sealed message transcripts after protocol
  authentication, while transport authentication proves only a caller-defined outer channel.

## Consequences

- Caller-added identifiers, headers, push tokens, and route metadata are outside sealed sender and
  must not be documented as protected by the library.
- Release verification checks protocol outputs and artifact authenticity, not host transport
  contracts.

## Verification Evidence

- `docs/security.md` records that transports expose routing metadata and that host applications own
  network IO, rate limiting, batching, and caller-added identifiers.
- `docs/public-api-review-v0.9.0.md` records that the public API performs no network IO and keeps
  transport wrappers host-owned.
- `crates/aether-core/docs/adr/0009-encrypted-acknowledgments-and-retries.md` records that
  acknowledgments and retries are returned to the consumer for transport instead of sent by Core.
