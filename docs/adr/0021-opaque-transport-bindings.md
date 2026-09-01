# Authenticate Opaque Transport Bindings

**Status:** Accepted

Aether accepts an optional, non-empty Transport Binding of at most 1 KiB and authenticates its
exact bytes as sealed-frame external associated data. The bytes are public and caller-owned:
Aether never defines their schema, interprets them, transmits them, or stores them. Bound X3DH
receive operations take a separate PreKey Selection so Core can locate retained signed-prekey
state and validate the Message's optional one-time-prekey identifier without decoding a
consumer-specific transport format.

## Considered Options

- Keep a typed Relay Route and its canonical codec in Aether. Rejected because a shared protocol
  core must not name one consumer or own that consumer's transport versioning.
- Ask the host to implement a runtime transport adapter. Rejected because the byte value is the
  complete cryptographic seam; a callback adds FFI and lifecycle complexity without strengthening
  authentication.
- Accept an unconstrained `Vec<u8>` on every operation. Rejected because a named bounded value
  makes retention and denial-of-service requirements explicit at both Rust and UniFFI boundaries.

## Consequences

- Consumers own a canonical, unambiguous encoding and may preserve an existing wire encoding
  outside Aether.
- Changing any binding byte causes authentication failure. The caller must retain the exact value
  with each outbound Message and acknowledgment used for retransmission.
- PreKey Selection is lookup input, not a transport codec. A consumer that needs selected
  identifiers authenticated as transport metadata must include them in its Transport Binding.
- Aether can guarantee byte authentication but cannot assert the binding's consumer-defined
  semantics.
