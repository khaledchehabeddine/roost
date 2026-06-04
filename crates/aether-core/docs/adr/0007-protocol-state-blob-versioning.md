# Protocol State Blob Versioning

**Status:** Accepted

Protocol State Blobs use a Core-owned major/minor envelope read before the version-specific payload is decoded, because consumers persist opaque bytes and Core needs a stable place to reject unsupported major versions before ratchet/session internals are interpreted. Supported older versions migrate only when represented by checked-in golden fixtures, and successful migrations are written back as the current envelope, because implicit pre-release compatibility would make malformed or stale protocol state indistinguishable from deliberate migration input.

## Considered Options

- Keep a single flat version byte. Rejected because it cannot express supported legacy fixture formats separately from the current major format.
- Let `aether-crypto` own the outer blob version. Rejected because Protocol State Blobs are Core persistence records addressed by Core kind/key, while Crypto owns only the inner ratchet/session codec.
