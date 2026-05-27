# Rust Docs Style

## Tiers

- T1 — UniFFI-exposed APIs in `crates/aether-uniffi/`, read by SDK consumers via the generated bindings
- T2 — Cross-crate `pub` items in `aether-core` and `aether-crypto`, read by Rust contributors wiring the crates together
- T3 — `pub(crate)` or private items in any crate, read by contributors editing the crate itself

## Per-tier content

|                      | T1                                                                                         | T2                                                          | T3                         |
|----------------------|--------------------------------------------------------------------------------------------|-------------------------------------------------------------|----------------------------|
| Summary line         | Required, third-person verb                                                                | Required, third-person verb                                 | Optional                   |
| Discussion paragraph | Required — purpose, lifecycle, threading, invariants                                       | Optional, when non-obvious                                  | Inline `//` if needed      |
| `# Examples`         | Always — executable Rust doctest, realistic usage                                          | Only when the call pattern isn't obvious from the signature | Never                      |
| `# Errors`           | Every `Result`-returning fn; list every reachable variant including via deep `From` chains | Every `Result`-returning fn; list every reachable variant   | Inline `//` if non-obvious |
| `# Panics`           | Reachable panics only; omit otherwise                                                      | Non-obvious panics only                                     | Inline `//` if non-obvious |
| `# Safety`           | N/A (UniFFI rejects `unsafe`)                                                              | Every `unsafe fn`                                           | Inline `//` if non-obvious |
| `# Performance`      | Optional; only for non-obvious caller-visible costs                                        | Optional, when non-obvious                                  | Never                      |

## When T2 requires `# Examples`

Skip:

- Plain data struct (`pub struct Foo { pub bar: u32 }`)
- Trivial trait impls (`From`, `Into`, `Display`)
- Single-purpose constructor that can't fail
- Getter/setter on a simple state
- Methods whose usage is self-evident from name and signature

Require:

- Fallible API (anything returning `Result`) where setup isn't obvious from the signature alone
- API with state/lifecycle (sessions, ratchets, builders)
- Subtle invariants (cipher modes, KDF parameters)
- Multiple valid parameter combinations

## `# Errors` chain coverage

- T1 and T2 `# Errors` blocks list every variant the caller can observe, including ones surfaced through `From` chains across multiple `?` operators, not just the direct call site

## Doc-claim accuracy

- Doc claims (atomicity, rollback, partial-failure handling, detectability) must match what the code does
- Document limitations explicitly, not by silence
- Crate and module docs orient the reader. Avoid restating item-level contracts unless the repetition adds navigation context

## Known-answer tests (KAT)

- Derivation source preference: RFC vectors → reference implementation → independent crate/library → hand-derived (flag for security-auditor review)
- Expected outputs must never be derived against the implementation under test
- Test functions are grouped together within the file, before related non-KAT behavior tests
- Expected outputs live in named constants (`<PRIMITIVE>_KAT_EXPECTED`)
- Derivation comment goes on the test, not the constant
- Test comments follow `Source` → `Inputs` → `Derivation` → `Output` (`Source` line names the reference tool and API call (e.g., `pyca/cryptography 46 HKDF-SHA256`))
- Derivation pseudocode uses `text` code fences
- Both directions (encrypt/decrypt, sign/verify) reference the same expected constant

## Crate-level (`//!` in lib.rs)

Required for every crate, regardless of tier:

- One-line summary
- Overview paragraph describing what the crate does and who it's for
- A `# Examples` quick-start (executable doctest)
- Key concepts when non-trivial
- Feature flags, when applicable

## Module-level (`//!` in module files)

- Public modules inherit the tier of their items. Requires a purpose statement, plus a lifecycle diagram when state or sequencing is non-trivial
- Internal modules (`mod` or `pub(crate) mod`) can be omitted unless their purpose isn't obvious from the name
- Newly split modules where parent context matters get a brief one-liner. Skip when the file name is self-explanatory

## Standard conventions (all tiers)

- Function summary starts with third-person verb ("Returns", "Generates", "Parses")
- Type summary is a noun phrase ("A cryptographic session shared between two peers.")
- Use intra-doc links for public API items when navigation helps explain the contract: `[Type]`, `[Type::method]`, or `[Type::Variant]`
- Prefer short rendered link text. Use explicit targets when rustdoc cannot resolve the short form or the target is outside lexical scope: ``[`Type`](crate::module::Type)`` or ``[`Type`](other_crate::Type)``. Show the full path in rendered text only when the namespace differentiates two same-named items in the same doc block
- Use plain text for domain concepts, private items in public docs, and repeat mentions unless each link clarifies a distinct contract
- Avoid naming the crate or project when the surrounding docs already make the context clear
- Public docs include implementation details only when they affect correct use, resource planning, interoperability, or error interpretation
- Performance sections are not mandatory. Include them only when callers need the cost for scheduling, resource planning, or avoiding repeated expensive work. Use `O(...)` notation only when the metric is explicit and clearer than prose
- Doctests run as part of `cargo test` by default. Mark an example `no_run` when it needs hardware or external services. Use `ignore` only as a last resort, when the example can't compile (e.g., pseudocode)
- Prefer hidden setup and hidden trailing `Ok::<_, _>(())` over visible `fn main` wrappers. Show `fn main` only when the entry point is part of the example
- UniFFI crates with only `cdylib`/`staticlib` crate-types skip doctests silently, add `rlib` to crate-type so doctests are verified
- Examples use `?` operator over `unwrap()` for error handling
- Use `must` for hard requirements, `should` for recommendations
