# Rust style

## Declarations and naming

- Module ordering: `mod` declarations → `use` declarations → types → traits → impls → functions, with each impl grouped with the type or trait it implements
- No `pub use` glob re-exports
- Local names: short when one obvious value is in scope; role names when same-shaped values coexist (including tests)
- Functions: verbs for actions (`generate_*`, `rotate_*`, `verify_*`); nouns for accessors (`current_bundle`, `public_key`); predicates with `is_*`/`has_*`
- No `get_` prefix on accessors
- `try_*` prefix only when contrasting with a non-fallible variant in the same scope — not as a generic `Result`-returning marker
- Constructors: `Type::new(...)` canonical; `Type::from_<form>(...)` for alternate sources (e.g., `from_secret_bytes`); `Type::with_<thing>(...)` for builder-style
- Type suffixes:
  - `*Error` for errors
  - `*Bundle` for containers of related public material
  - `*Manager` only when paired with the type it manages (e.g., `IdentityManager` vs `Identity`)
  - `*Store` for facades composing multiple managers (e.g., `KeyStore` over `IdentityManager` + `SignedPreKeyManager`)
  - Avoid `*Helper`, `*Util`, `*Service`

## Errors

- Each crate defines its own domain error type
- All error paths return `Result` — `unwrap()`, `expect()`, and `panic!()` are banned outside of tests
- Error text (Display, Debug, source chain) is for operator logs — concise, debug-useful, lowercase first word, no trailing period (composes via `{e}` chaining)
- Never include secret material — key bytes, plaintext, seeds. Reference by stable identifiers (key IDs, message numbers) instead

## Async

- A function is `async` only when its natural implementation suspends on an event it does not produce — network response, peer message, subscriber pull, timer
- Suspension justifies `async` when at least one of these holds:
  - the surrounding subsystem can interleave multiple such waits
  - cancellation, timeout, retries, or backpressure are part of the operation's contract
- Functions returning a `Stream` whose items arrive over time qualify
- CPU-bound work (AEAD, KDFs, signing), single bounded syscalls (one keychain read), and "could block in theory" are not justification

## Dependencies

- Necessity check before adding any dep — can the standard library or an existing dep cover the need?
- MSRV of any added dep must be ≤ workspace MSRV (see [`rust-toolchain.toml`](../../../../../rust-toolchain.toml))
- For crypto-adjacent crates (touching keys, signatures, encryption, KDFs): require maintainer reputation (RustCrypto org, dalek-cryptography, etc.) and audit history
- Prefer audited crates
- Pin major versions in each crate's `Cargo.toml`; hoist shared deps to `[workspace.dependencies]`. Update via `cargo update -p <crate>` with reasoning in the commit message
- When adding or updating dependencies, review known advisories, licenses, sources, maintenance status, and new transitive duplicates
