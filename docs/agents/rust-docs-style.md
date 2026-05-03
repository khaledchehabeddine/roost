# Rust Docs Style

## Tiers

- T1 — UniFFI-exposed APIs in `crates/hermes-uniffi/`, including `#[uniffi::export(with_foreign)]` traits. Read by SDK consumers via the generated bindings
- T2 — Cross-crate `pub` items in `hermes-core`, `hermes-crypto`, and `hermes-transport-ble`, read by Rust contributors wiring the crates together
- T3 — `pub(crate)` or private items in any crate, read by contributors editing the crate itself

## Per-tier content

|                      | T1                                                                                | T2                                                             | T3                         |
|----------------------|-----------------------------------------------------------------------------------|----------------------------------------------------------------|----------------------------|
| Summary line         | Required, third-person verb                                                       | Required, third-person verb                                    | Optional                   |
| Discussion paragraph | Required — purpose, lifecycle, threading, invariants                              | Optional, when non-obvious                                     | Inline `//` if needed      |
| `# Examples`         | Always — executable Rust doctest, realistic usage                                 | Only when the call pattern isn't obvious from the signature    | Never                      |
| `# Errors`           | Every `Result`-returning fn; list every reachable variant including via deep `From` chains | Every `Result`-returning fn; list every reachable variant     | Inline `//` if non-obvious |
| `# Panics`           | Required, even when "Never panics"                                                | Non-obvious panics only                                        | Inline `//` if non-obvious |
| `# Safety`           | N/A (UniFFI rejects `unsafe`)                                                     | Every `unsafe fn`                                              | Inline `//` if non-obvious |
| `# Performance`      | Big-O complexity and allocations                                                  | Optional, when non-obvious                                     | Never                      |

## Foreign-implementable traits (T1, `#[uniffi::export(with_foreign)]`)

Per-method `# Examples` are meaningless without an impl. Substitute:

- A trait-level `# Implementing` section pointing to a reference implementation in the workspace
- Per-method `# Performance` and `# Panics` (the contract on implementors)
- Per-method `# Errors` (which variants the implementor must surface)

## Crate-level (`//!` in lib.rs)

Required for every crate, regardless of tier:

- One-line summary
- Overview paragraph describing what the crate does and who it's for
- A `# Examples` quick-start (executable doctest)
- Key concepts or mental model, when non-trivial
- Feature flags, when applicable

## Module-level (`//!` in module files)

- Public modules (exposed across the crate or via UniFFI) inherit the tier of their items. They require a purpose statement, an entry-point listing, and a lifecycle diagram when non-trivial
- Internal modules (`mod` or `pub(crate) mod`) can be omitted unless their purpose isn't obvious from the name
- Newly-split modules where parent context matters get a brief one-liner; skip when the file name is self-explanatory

## When T2 requires `# Examples`

Skip:

- Plain data struct (`pub struct Foo { pub bar: u32 }`)
- Trivial trait impls (`From`, `Into`, `Display`)
- Single-purpose constructor that can't fail
- Getter/setter on a simple state
- Methods whose usage is self-evident from name + signature

Require:

- Fallible API (anything returning `Result`) where setup isn't obvious from the signature alone
- API with state/lifecycle (sessions, ratchets, builders)
- Subtle invariants (cipher modes, KDF parameters)
- Multiple valid parameter combinations

## `# Errors` chain coverage

For T1 and T2, `# Errors` must list every variant reachable from the function — including ones surfaced via `From` impl conversions one or more levels deep. The function's direct call site isn't enough; trace through every `?` to the variants the caller can observe.

## Recovery guidance in `# Errors`

When variants have meaningfully different recovery actions, the `# Errors` block must distinguish them. Pre-mutation failures and post-commit failures often need different recovery — list them separately. Single-line "see the variant doc" is acceptable when the variants share a recovery action.

## Standard conventions (all tiers)

- Function summary starts with third-person verb ("Returns", "Generates", "Parses")
- Type summary is a noun phrase ("A cryptographic session shared between two peers.")
- Use intra-doc link syntax for cross-references: `[Type]` or `[Type::method]`. Don't link to private items from public docs — `cargo doc` rejects it under `RUSTDOCFLAGS=-D warnings`
- Doctests run as part of `cargo test` by default. Mark an example `no_run` when it needs hardware or external services. Use `ignore` only as a last resort, when the example can't compile (e.g., pseudocode)
- UniFFI crates with only `cdylib`/`staticlib` crate-types skip doctests silently — add `rlib` to crate-type so doctests are verified
- Examples use `?` operator over `unwrap()` for error handling
- Use `must` for hard requirements, `should` for recommendations
