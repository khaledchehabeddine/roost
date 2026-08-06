# Rust Quality

Inspect the task and load only the direct references that apply. Load multiple references when the change crosses boundaries.

- [Crypto](references/crypto.md): cryptographic primitives, randomness, secrets, constant-time comparisons, protocol state, or attacker-controlled bounds.
- [Public APIs and errors](references/public-apis-errors.md): crate ownership, visibility, naming, errors, compatibility, or general Rust code shape.
- [Async and performance](references/async-performance.md): suspension, streams, concurrency, cancellation, blocking work, allocations, or caller-visible cost.
- [UniFFI](references/uniffi.md): exported bindings, foreign traits, adapters, generated consumers, or FFI errors and secrets.
- [Tests](references/tests.md): unit, integration, boundary, protocol-invariant, known-answer, or deterministic tests.
- [Dependencies](references/dependencies.md): manifests, lockfile, MSRV, supply chain, or dependency changes.
- [Rustdoc](references/rustdoc.md): crate, module, public-item, error, panic, safety, performance, or example documentation.

Read `CONTRIBUTING.md` before Git workflow decisions. Verify with the narrowest relevant `scripts/check.sh` command; use `quick` as the minimum implementation gate and `full --base <base>` only for the publish workflow.
