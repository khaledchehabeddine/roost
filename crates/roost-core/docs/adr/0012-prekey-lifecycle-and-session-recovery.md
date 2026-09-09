# Prekey Lifecycle and Session Recovery

**Status:** Accepted

Prekey lifecycle remains in KeyStore-owned `prekey/*` records instead of a parallel protocol-state
blob. Core allocates stable unsigned 64-bit signed- and one-time-prekey identifiers from independent
monotonic sequences that restart at zero for each Discovery Key Epoch. Signed pre-keys rotate on a
weekly cadence, and up to five superseded keys are retained for 30 days from supersession so
transport entries admitted before rotation remain decryptable; Discovery Key or emergency inbox
rotation immediately destroys every prior-Epoch prekey secret. One-time pre-keys are
caller-replenished on demand, consumed exactly once after an authenticated matching X3DH first
message, and rejected when missing, already consumed, stale, or mismatched.

## Considered Options

- Implicit signed-pre-key rotation during publication. Rejected. Publication should be a pure read
  of caller-prepared material so consumers control when new bundles become visible.
- Retaining only the immediately superseded signed pre-key. Rejected because weekly rotation and
  the 30-day supported delivery-retention window allow several previously admitted initials to
  remain deliverable at once.
- Silently evicting an unexpired retained signed pre-key. Rejected because that converts a bounded
  local capacity condition into undecryptable admitted transport entries; an early manual rotation
  fails instead, while emergency inbox rotation explicitly destroys the Epoch.
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
- Signed-prekey retention is measured from supersession time, not original key creation, and ends at
  the 30-day boundary.
- Transport admission policy rejects new initials against a superseded signed-prekey identifier.
  Core trusts the host to validate that a retained-key delivery was admitted before supersession.
- Stable identifiers are lookup metadata rather than part of the signed-prekey signature payload;
  a host that treats them as transport-security inputs includes them in the authenticated Transport
  Binding.
- Backup restore preserves the backed-up Discovery Key but marks both prekey stores unusable until
  inbox rotation advances the Epoch, preventing identifier reuse from stale or cloned backups.
- Consumed one-time pre-keys are destroyed before reuse can occur; callers publish replenished
  one-time pre-key bundles explicitly.

## Verification Evidence

- Core's `signed_prekey` and `one_time_prekey` unit tests cover rotation, retention and pool
  bounds. `crates/roost-core/tests/prekey_identifiers.rs` covers publication and selection across
  the public API; prepared-operation and recovery tests cover restart behavior.
- `docs/security.md` records signed-prekey-only fallback when one-time pre-key pools are exhausted
  and distinct failures for stale, missing, consumed, or mismatched prekey references.
