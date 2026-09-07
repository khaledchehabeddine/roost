# Protocol State Blob Versioning

**Status:** Accepted

Protocol State Blobs use a Core-owned major/minor envelope read before the version-specific payload is decoded, because consumers persist opaque bytes and Core needs a stable place to reject unsupported versions before ratchet/session internals are interpreted. The shipped release-candidate envelope is `1.0`; non-current envelope versions reject as faults rather than reset, restore, or silent migration signals. Within that `1.0` envelope, session body version 4 uses one tagged representation for active contact-unbound, active contact-bound, and unrecoverable states. Ratchet bytes are borrowed during decoding so validation failures do not leave an unprotected heap copy. Contact body version 2 includes the blocking flag. There are no alternate readers or contact-state fallbacks.

Post-1.0 same-major migrations must be explicit and fixture-backed before release. A supported body shape needs checked-in fixtures, decode coverage, and clear rewrite behavior on the next state update; unsupported major versions remain rejection cases, and pre-release legacy upgrade paths are not added unless a future decision scopes them directly.

## Considered Options

- Keep a single flat version byte. Rejected because the Core envelope should remain independent of the versioned payload body it protects.
- Let `roost-crypto` own the outer blob version. Rejected because Protocol State Blobs are Core persistence records addressed by Core kind/key, while Crypto owns only the inner ratchet/session codec.
- Silently reinitialize unknown blobs. Rejected because reset can desynchronize Ratchet state,
  deduplication, acknowledgments, contacts, and host outbox commits.

## Verification Evidence

- `crates/roost-core/tests/fixtures/protocol_state_blobs_v1.md` pins the `1.0` envelope, current
  decoded bodies, current session variants, current contact state, and unsupported-version rejection.
- `docs/protocol-state-invariant-tests.md` records corruption and rollback scenarios that fault
  rather than silently reinitialize state.
