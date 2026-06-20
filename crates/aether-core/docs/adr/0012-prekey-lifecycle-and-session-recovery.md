# Prekey Lifecycle and Session Recovery

**Status:** Accepted

Prekey lifecycle remains in KeyStore-owned `prekey/*` records instead of a parallel protocol-state
blob. Publication uses caller-created signed pre-keys, callers enforce the weekly rotation cadence,
the immediately superseded signed pre-key is retained for a library-fixed 7-day grace window, and
Discovery Key rotation immediately destroys prior-Epoch signed and one-time prekey secrets.
One-time pre-keys are caller-replenished on demand, consumed exactly once after an authenticated
matching X3DH first message, and rejected when missing, already consumed, stale, or mismatched.

## Considered Options

- Implicit signed-pre-key rotation during publication. Rejected. Publication should be a pure read
  of caller-prepared material so consumers control when new bundles become visible.
- Keeping multiple superseded signed pre-keys. Rejected. Retaining only the immediately superseded
  key covers in-flight bundles while bounding secret retention and review surface.
- Representing PreKey State as `ProtocolStateKind::PreKey`. Rejected. Existing KeyStore storage is
  already the authoritative secret lifecycle boundary, while protocol-state blobs are consumer-held
  operation state.
- Automatically replenishing one-time pre-keys in the receive path. Rejected. Publication and
  directory freshness are caller-visible operations, while receive should consume only the referenced
  local secret.
- Retrying after an authenticated terminal condition. Rejected. Messages under a Dead Session
  remain permanently undecryptable; recovery is to fetch a fresh prekey bundle, run X3DH, and
  install a new Session.
- Treating incoming skipped-key cap overflow as terminal. Rejected. The ratchet header is not
  authenticated until AEAD verification succeeds, so cap overflow rejects the Message without
  marking the Session dead.

## Consequences

- A Session-Unrecoverable Event emits at most once per Dead Session, and later Messages against the
  same marker return an unrecoverable outcome with no plaintext.
- Rotating the Discovery Key is the only operation that immediately invalidates all prior-Epoch
  prekey secrets.
- Superseded signed pre-key grace is measured from supersession time, not original key creation.
- Consumed one-time pre-keys are destroyed before reuse can occur; callers publish replenished
  one-time pre-key bundles explicitly.

## Verification Evidence

- `crates/aether-uniffi/docs/api-coverage.md` records binding coverage for signed-prekey rotation,
  one-time-prekey replenishment, consumed-key rejection, stale-epoch detection, and session
  recovery/re-handshake entry points.
- `docs/security.md` records signed-prekey-only fallback when one-time pre-key pools are exhausted
  and distinct failures for stale, missing, consumed, or mismatched one-time pre-key references.
