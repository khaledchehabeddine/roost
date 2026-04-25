# Rust Docs Style Reference

Three audience-based tiers.

## Per-tier content

|                      | T1 (UniFFI)                                                    | T2 (cross-crate `pub`)                    | T3 (internal)              |
|----------------------|----------------------------------------------------------------|-------------------------------------------|----------------------------|
| Summary line         | Required, third-person verb                                    | Required, third-person verb               | Optional                   |
| Discussion paragraph | Required — purpose, lifecycle, threading, invariants           | Optional, when non-obvious                | Inline `//` if needed      |
| `# Examples`         | Always — executable Rust doctest, realistic usage              | Non-trivial APIs only — minimal example   | Never                      |
| `# Errors`           | Every `Result`-returning fn; list the variants this fn returns | Every `Result`-returning fn               | Inline `//` if non-obvious |
| `# Panics`           | Every panic (UniFFI propagates as client-side aborts)          | Non-obvious panics only                   | Inline `//` if non-obvious |
| `# Safety`           | N/A (UniFFI rejects `unsafe`)                                  | Every `unsafe fn` — non-negotiable        | Inline `//` if non-obvious |
| `# Performance`      | Hot-path / surprising cost                                     | Surprising cost (`O(n²)`, alloc, syscall) | Skip                       |
| Tone                 | Conversational; "you" OK in Discussion                         | Third-person / passive; avoid "you"       | Author's choice            |

## Crate-level (`//!` in lib.rs)

Required for every crate, regardless of tier:
- One-line summary (matches `Cargo.toml` description)
- Overview paragraph: what the crate does, who it's for
- `# Examples` quick-start (executable doctest)
- Key concepts / mental model if non-trivial
- Feature flags if any

## Module-level (`//!` in module files)

- Public modules (exposed across crate or via UniFFI) inherit the tier of their items. Required: purpose statement, entry-point listing, lifecycle/diagram if non-trivial
- Internal modules (`mod`/`pub(crate) mod`) — omit unless purpose isn't obvious from the name

## T2 trivial vs.non-trivial criterion (when `# Examples` is required)

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
- Intra-doc links: `[Type]` or `[Type::method]` syntax
- Doctest default: executable. `no_run` for hardware/external deps. `ignore` only as last resort
- Examples use `?` operator over `unwrap()` for error handling
- Use `must` for hard requirements, `should` for recommendations

## Lint enforcement

Per-crate via `Cargo.toml [lints]`:
- `hermes-uniffi`: `missing_crate_level_docs = "warn"` + `missing_docs = "warn"`
- Other crates: inherit workspace `missing_crate_level_docs = "warn"` only
