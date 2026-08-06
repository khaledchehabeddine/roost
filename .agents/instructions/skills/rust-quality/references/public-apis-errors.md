# Public APIs and Errors

## Ownership and visibility

- `aether-crypto` owns cryptographic primitives and protocol mechanics. `aether-core` owns entities and orchestration. `aether-uniffi` adapts the Core API for generated clients.
- Treat modules as organization, not API boundaries. Every `pub` item needs an out-of-crate consumer; a `lib.rs` re-export alone is not a consumer.
- Expose a secret-bearing form only for a consumer that specifically needs the secret.
- Do not use glob `pub use` exports.

## Compatibility and naming

- Treat source compatibility across crates and generated Swift/Kotlin compatibility as public API constraints.
- A binary-breaking FFI change, including a `#[repr(C)]` layout change or removed `#[uniffi::export]`, requires a major version bump.
- At `#[uniffi::export]`, spell out crypto terms; allow only universal acronyms such as URL, HTTP, and JSON.
- Across crates, allow established primitive acronyms such as KDF, AEAD, HKDF, and MAC, but spell out protocol-internal terms. `pub(crate)` and local scopes may use protocol shorthand.
- Use verbs for actions, nouns for accessors, and `is_*` or `has_*` for predicates. Do not prefix accessors with `get_`.
- Use `try_*` only when the same scope also exposes a non-fallible variant.
- Use `Type::new` for the canonical constructor, `from_<form>` for alternate inputs, and `with_<thing>` for builder-style construction.
- Use `*Error` for errors and `*Bundle` for related public material. Use `*Manager` only beside the type it manages and `*Store` for a facade over multiple managers. Avoid `*Helper`, `*Util`, and `*Service`.
- Order modules as declarations, uses, types, traits, impls, then functions; group each impl with its type or trait.
- Prefer short local names for one obvious value and role names when same-shaped values coexist.

## Errors

- Define a domain error type per crate. Return `Result` on every failure path; `unwrap()`, `expect()`, `panic!()`, `todo!()`, and `unimplemented!()` are forbidden outside tests.
- Write operator-facing error text with a lowercase first word, no trailing period, and enough stable context to debug chained errors.
- Never include keys, plaintext, seeds, tokens, or other secret bytes in error text. Use stable identifiers such as key IDs or message numbers.
- Keep internal errors out of public signatures and map them at crate and FFI boundaries without discarding actionable source context.
