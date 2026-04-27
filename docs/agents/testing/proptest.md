# Property-Based Testing

**Status: forward-looking.** Hermes does not currently use `proptest` or `quickcheck`. This file is a placeholder for when invariant-based testing earns its keep.

## When to introduce

Add proptest when an invariant must hold across a *space* of inputs too large to enumerate by example:

- Encrypt-then-decrypt round-trip across arbitrary plaintexts
- Ratchet state serialization round-trip across arbitrary state shapes
- Out-of-order delivery across arbitrary message orderings

For crypto *primitives*, KATs (see [kat-vectors.md](kat-vectors.md)) are stronger — don't use proptest there.

## Pattern when introduced

- Strategies use seeded RNGs (`ChaCha20Rng::from_seed(...)`), not `OsRng` — proptest needs reproducibility
- Properties are pure (deterministic given input, no side effects)
- Failures shrink to minimal counterexamples
- Capture failing seeds for CI reproducibility

## See also

- `proptest` book: <https://proptest-rs.github.io/proptest/>
- [kat-vectors.md](kat-vectors.md) — preferred for primitive correctness
- [integration-tests.md](integration-tests.md) — preferred for protocol-level scenarios
