# Rust Docs Style

## Tiers

Three audience-based tiers, by location:

- T1 — UniFFI-exposed APIs in `crates/hermes-uniffi/`, read by SDK consumers via the generated bindings.
- T2 — Cross-crate `pub` items in `hermes-core`, `hermes-crypto`, and `hermes-transport-ble`, read by Rust contributors wiring the crates together.
- T3 — `pub(crate)` or private items in any crate, read by contributors editing the crate itself.

## Per-tier content

|                      | T1                                                             | T2                                                             | T3                         |
|----------------------|----------------------------------------------------------------|----------------------------------------------------------------|----------------------------|
| Summary line         | Required, third-person verb                                    | Required, third-person verb                                    | Optional                   |
| Discussion paragraph | Required — purpose, lifecycle, threading, invariants           | Optional, when non-obvious                                     | Inline `//` if needed      |
| `# Examples`         | Always — executable Rust doctest, realistic usage              | Non-trivial APIs only — minimal example                        | Never                      |
| `# Errors`           | Every `Result`-returning fn; list the variants this fn returns | Every `Result`-returning fn; list the variants this fn returns | Inline `//` if non-obvious |
| `# Panics`           | Every panic (UniFFI propagates as client-side aborts)          | Non-obvious panics only                                        | Inline `//` if non-obvious |
| `# Safety`           | N/A (UniFFI rejects `unsafe`)                                  | Every `unsafe fn` — non-negotiable                             | Inline `//` if non-obvious |
| `# Performance`      | Big-O complexity and allocations                               | Same, when not obvious from the signature                      | Skip                       |
| Tone                 | Third-person / passive                                         | Third-person / passive                                         | Third-person / passive     |

## Crate-level (`//!` in lib.rs)

Required for every crate, regardless of tier:
- One-line summary
- Overview paragraph describing what the crate does and who it's for
- A `# Examples` quick-start (executable doctest)
- Key concepts or mental model, when non-trivial
- Feature flags, when applicable

## Module-level (`//!` in module files)

- Public modules (exposed across the crate or via UniFFI) inherit the tier of their items. They require a purpose statement, an entry-point listing, and a lifecycle diagram when non-trivial.
- Internal modules (`mod` or `pub(crate) mod`) can be omitted unless their purpose isn't obvious from the name.

## When T2 requires `# Examples`

Skip:
- Plain data struct (`pub struct Foo { pub bar: u32 }`)
- Trivial trait impls (`From`, `Into`, `Display`)
- Single-purpose constructor that can't fail
- Getter/setter on a simple state

Require:
- Fallible API (anything returning `Result`)
- API with state/lifecycle (sessions, ratchets, builders)
- Subtle invariants (cipher modes, KDF parameters)
- Multiple valid parameter combinations

## Standard conventions (all tiers)

- Function summary starts with third-person verb ("Returns", "Generates", "Parses")
- Type summary is a noun phrase ("A cryptographic session shared between two peers.")
- Use intra-doc link syntax for cross-references: `[Type]` or `[Type::method]`.
- Doctests run as part of `cargo test` by default. Mark an example `no_run` when it needs hardware or external services. Use `ignore` only as a last resort, when the example can't compile (e.g., pseudocode).
- Examples use `?` operator over `unwrap()` for error handling
- Use `must` for hard requirements, `should` for recommendations

## Lint enforcement

Doc presence is enforced mechanically via `Cargo.toml [lints]` — see the workspace and per-crate lint config for current coverage. T1 (`hermes-uniffi`) is configured strictest because its surface ships to external bindings consumers.

Lints catch missing docs only. Tier-based content quality (T1/T2/T3 sections, `# Examples`, tone) is reviewed by the `rust-docs` skill.
