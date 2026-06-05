# Protocol State Blob Versioning

**Status:** Accepted

Protocol State Blobs use a Core-owned major/minor envelope read before the version-specific payload is decoded, because consumers persist opaque bytes and Core needs a stable place to reject unsupported versions before ratchet/session internals are interpreted. During pre-release, the current build accepts only the current envelope and current wrapped session-state body, rejects non-current envelope versions as faults, and rejects stale current-version body shapes as malformed blobs.

## Considered Options

- Keep a single flat version byte. Rejected because the Core envelope should remain independent of the versioned payload body it protects.
- Let `aether-crypto` own the outer blob version. Rejected because Protocol State Blobs are Core persistence records addressed by Core kind/key, while Crypto owns only the inner ratchet/session codec.
