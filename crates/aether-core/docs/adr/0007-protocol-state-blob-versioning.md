# Protocol State Blob Versioning

**Status:** Accepted

Protocol State Blobs use a Core-owned major/minor envelope read before the version-specific payload is decoded, because consumers persist opaque bytes and Core needs a stable place to reject unsupported versions before ratchet/session internals are interpreted. During pre-release, the current build accepts only the current envelope and rejects non-current envelope versions as faults. Within the current envelope, session and contact payloads carry their own body version and decode dual-bodied: the current body shape is tried first, then the immediately prior shape (session bodies without the bound contact identity key; contact bodies without the blocking flag, which decode as unblocked). The fallback is a deliberate, bounded pre-release exception to the no-upgrade-path stance — it let existing development state survive the v0.7.0 body additions — and the prior-shape fallbacks retire at the next body revision or at v1.0.0, whichever comes first.

## Considered Options

- Keep a single flat version byte. Rejected because the Core envelope should remain independent of the versioned payload body it protects.
- Let `aether-crypto` own the outer blob version. Rejected because Protocol State Blobs are Core persistence records addressed by Core kind/key, while Crypto owns only the inner ratchet/session codec.
