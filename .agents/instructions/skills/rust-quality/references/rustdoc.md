# Rustdoc

## Tiers

- T1: UniFFI-exported APIs, read through generated SDK bindings.
- T2: cross-crate `pub` items in `aether-core` and `aether-crypto`.
- T3: crate-private and private items.

## Item documentation

- T1 and T2 require a summary. Start function summaries with a third-person verb and type summaries with a noun phrase.
- T1 requires a purpose, lifecycle, threading, and invariants discussion plus a realistic executable example. T2 adds discussion when behavior is non-obvious and an example when setup, state, parameter combinations, or invariants are not evident from the signature. Plain data, trivial trait impls, infallible single-purpose constructors, simple accessors, and self-evident calls need no T2 example. T3 uses inline comments only when needed.
- Every T1 or T2 `Result` function documents all caller-observable variants, including deep `From` chains.
- Document every reachable T1 panic, non-obvious T2 panic, and every public `unsafe fn` safety contract. Omit empty sections.
- Add `# Performance` only for caller-visible scheduling or resource-planning costs.
- Keep claims about atomicity, rollback, partial failure, detectability, and limitations aligned with code.
- Document caller-relevant limitations explicitly; never rely on silence to imply them.

## Crates, modules, and links

- Give every crate a one-line summary, audience and purpose overview, executable quick start, non-trivial concepts, and feature flags when present.
- Give a public module a purpose statement and a lifecycle diagram when sequencing is non-trivial. Document an internal module only when its purpose is not obvious; give a newly split module a one-line orientation when parent context still matters.
- Crate and module docs orient readers. Do not restate item-level contracts unless repetition adds navigation context.
- Use intra-doc links when they clarify a public contract. Prefer short link text and explicit targets only when resolution or name ambiguity requires them.
- Use plain text for domain concepts, private items, and repeated mentions that add no navigation value. Avoid naming the crate or project when surrounding docs provide the context.
- Keep private implementation details out of public docs unless they affect correct use, interoperability, resource planning, or error interpretation. Use `O(...)` only when the measured dimension is explicit and clearer than prose.

## Examples

- Use `?` instead of `unwrap`. Hide setup and trailing `Ok` when that improves the rendered example; show `fn main` only when the entry point is part of the example.
- Use `no_run` only for examples requiring hardware or external services; use `ignore` only when an example cannot compile.
- Keep `rlib` in UniFFI crate types so doctests are not silently skipped.
- Use `must` for requirements and `should` for recommendations.
- Run `scripts/check.sh docs`; for a narrow iteration, `cargo doc -p <crate> --no-deps` must complete without warnings.
