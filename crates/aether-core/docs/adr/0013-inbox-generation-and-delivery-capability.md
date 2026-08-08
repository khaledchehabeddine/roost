# Inbox Generation And Delivery Capability

**Status:** Accepted

The inbox generation is the discovery key's epoch — one number, not two — rebased so identity
creation starts at generation 1 rather than epoch 0 (AE-IDN-07). The recipient delivery capability
is stored in the discovery-key blob, which moves to version 2, so a single write advances the
generation and replaces both the discovery key and the capability. Aether returns the capability
only through `KeyStore::current_delivery_capability` and publishes its verifier through
`PublicationBundle::recipient_delivery_verifier`; it never registers, validates, or transmits a
capability (AE-IDN-09).

Two counters would have had to move in lockstep forever, and the relay stores only one number per
inbox (REL-RLY-70, REL-RLY-88). If they ever diverged, prekey validity and delivery authorization
would disagree about which generation is current — and because blocking works by rotating the inbox
so a blocked contact's capability stops being accepted (AE-BLK-08), a divergence would mean a
blocked contact could still deliver. One number makes that class of failure unrepresentable rather
than something every future change has to preserve.

## Considered Options

- Keep the discovery-key epoch 0-based and track the inbox generation separately. Rejected. It
  avoids changing a published value today, but the relay would still receive exactly one number, so
  the other becomes an internal concept that nonetheless appears in the IK→DK binding signature and
  the X3DH associated data. Once identities register with generation ≠ epoch, reconciling them is a
  live migration.
- Derive the capability from the discovery key instead of storing it. Rejected. The capability must
  be independently rotatable and must not be recoverable from public material; deriving it from key
  material would make a discovery-key compromise also a delivery-authorization compromise.
- Recompute the capability per read, as the DK→IK binding does
  ([0009 in aether-crypto](../../../aether-crypto/docs/adr/0009-discovery-to-identity-binding.md)).
  Not applicable. That binding is a deterministic function of existing material; a capability is
  fresh randomness (AE-IDN-06) and has nothing to recompute from.

## Consequences

- Discovery-key blob version 1 is not readable. It is rejected by the length check before the
  version byte is examined. No production identity is affected: neither Relay client has
  implemented backup export or restore, so no v1 backup exists outside test fixtures.
- `tests/fixtures/identity_backup_v2.json` was regenerated, since the backup envelope carries the
  discovery-key blob verbatim. The envelope format itself is unchanged — only its payload.
- `PublicationBundle` gained `recipient_delivery_verifier`, changing the generated Kotlin and Swift
  record shape.
- Existing locally-stored identities from v0.9.0 debug builds must be reset and re-created. This is
  cheap now and would not have been after Relay registration ships, which is the reason for doing
  the rebase at this point rather than later.
