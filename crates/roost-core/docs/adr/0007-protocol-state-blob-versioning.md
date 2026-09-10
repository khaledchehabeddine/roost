# Protocol State Blob Versioning

**Status:** Accepted

Protocol State Blobs use a Core-owned major/minor envelope read before the version-specific payload is decoded, because consumers persist opaque bytes and Core needs a stable place to reject unsupported versions before ratchet/session internals are interpreted. The shipped release-candidate envelope is `1.0`; non-current envelope versions reject as faults rather than reset, restore, or silent migration signals. Within that `1.0` envelope, session body version 4 uses one tagged representation for active contact-unbound, active contact-bound, and unrecoverable states. Ratchet bytes are borrowed during decoding so validation failures do not leave an unprotected heap copy. Contact body version 2 includes the blocking flag. There are no alternate readers or contact-state fallbacks.

When persisted user data must survive upgrades, each supported migration needs a focused test that reads the previous format and checks the next write. The MVP makes no compatibility promise for earlier prerelease bodies; unsupported versions remain explicit faults.

## Considered Options

- Keep a single flat version byte. Rejected because the Core envelope should remain independent of the versioned payload body it protects.
- Let `roost-crypto` own the outer blob version. Rejected because Protocol State Blobs are Core persistence records addressed by Core kind/key, while Crypto owns only the inner ratchet/session codec.
- Silently reinitialize unknown blobs. Rejected because reset can desynchronize Ratchet state,
  deduplication, acknowledgments, contacts, and host outbox commits.
