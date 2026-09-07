# Discovery-To-Identity Binding

**Status:** Accepted

The DK→IK half of the mutual key binding (AE-KEY-04) signs the identity key's two public halves and
nothing else — context `AetherDKToIK-v1:` over `ik_x25519 || ik_ed25519` — while the IK→DK half
continues to cover the discovery key's epoch and creation timestamp. The asymmetry is deliberate: a
permanent identity key signs many discovery keys over its lifetime, so that direction needs an epoch
to say *which* one it authorized, whereas a fresh discovery key is minted per inbox generation and
therefore already identifies the generation it belongs to. Freshness for this direction is enforced
by the relay's inbox registry refusing to serve rotated discovery keys (Relay REL-RLY-72,
REL-RLY-76), not by the signature.

## Considered Options

- Mirror the IK→DK layout, adding inbox generation and a timestamp. Rejected. It would make each
  signature self-dating without trusting the registry, but it requires amending a finalized v1.0
  specification whose AE-KEY-04 says the DK-to-IK signature covers both IK public halves, and it
  adds fields two independent implementations must agree on byte-for-byte — the same surface that
  produced an incorrect proof-of-work preimage on 2026-08-02.
- Reuse the existing `AetherIKBinding-v1:` context for both the IK self-binding and this direction.
  Rejected. The two cover identical bytes, so a shared context would let a signature made for one
  purpose satisfy the other, which is precisely the separation AE-KEY-02 requires.

## Consequences

- The signature stays valid across rotations, so Relay's lookup and prekey-fetch endpoints
  (REL-RLY-74, REL-RLY-75) can serve a stored copy without regard to when it was made.
- A leaked historical discovery-key secret yields a signature indistinguishable from a fresh one.
  This is contained by the registry, which will not serve a rotated discovery key — the guarantee
  lives in the relay rather than in the cryptography, and that placement is the substance of this
  decision.
- Both directions derive their payload from one shared function, so the two cannot drift apart.
- `docs/domain-separation.md` publishes the context string and preimage as the normative
  cross-implementation reference, with a known-answer vector derived per
  [0005-cryptographic-test-vector-derivation.md](0005-cryptographic-test-vector-derivation.md).
