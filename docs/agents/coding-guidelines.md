# Coding guidelines

Shared coding and agent-configuration policy for both runtimes.

## Agent Config

- Customizations that benefit collaborators on this project must live in project scope (`.agents/`, `.claude/`, `.codex/`, `AGENTS.md`, `CLAUDE.md`)
- Customization may live in user scope only if it neither shapes the project's workflow nor improves agent quality for collaborators
- When updating one agent's customization, mirror the behavioral change in the other agent's equivalent (Claude ↔ Codex). Stylistic patterns differ between agents per their respective documentation
- Follow the structure and style from existing peer customizations of the same type within the same agent
- Pattern-skill body items follow a cohesive ordering (workflow, scope, criticality, frequency, etc.)
- Pattern-skill descriptions list the same items as the body, in the same order
- Skills that set `paths:` must not restate the location filter in their description — `paths:` gates autoloading
- Customization descriptions don't explicitly reference the project name (Roost). Literal paths like `crates/roost-client` are exceptions

## Async

- A function is `async` only when its natural implementation suspends on an event it does not produce — network response, peer message, subscriber pull, timer
- Suspension justifies `async` when at least one of these holds:
  - the surrounding subsystem can interleave multiple such waits
  - cancellation, timeout, retries, or backpressure are part of the operation's contract
- Functions returning a `Stream` whose items arrive over time qualify
- CPU-bound work (AEAD, KDFs, signing), single bounded syscalls (one keychain read), and "could block in theory" are not justification

## Crypto

- Cryptographic primitives:
  - Encryption: XChaCha20-Poly1305
  - Key exchange: X25519
  - Signing: Ed25519
  - Key derivation: Argon2id
- Production randomness must come from the OS CSPRNG — `OsRng` or `getrandom`. No `thread_rng()`, seeded, or non-cryptographic RNGs outside test modules
- AEAD nonces must be derived alongside the message key via HKDF — never randomly under a long-lived key
- Every HKDF call must use a distinct, non-empty `info` string for domain separation
- Wrap heap secrets (`Vec<u8>`, decrypted output) and FFI-bound values in `Zeroizing` immediately — before validation or early returns. Stack-locals consumed immediately by a constructor don't need wrapping
- Custom secret-bearing structs derive `Zeroize, ZeroizeOnDrop`. Mark fields with `#[zeroize(skip)]` if they are non-secret or if the field's type doesn't impl `Zeroize` (e.g., `ed25519_dalek::Signature`)
- Types holding secret material must not derive `Clone`, `Debug`, or `Serialize` unless they also derive `ZeroizeOnDrop` — add a comment explaining why
- Comparisons of MACs, keys, tokens, or hashes must use `subtle::ConstantTimeEq`, never `==`
- Collections sized by external input (`HashMap`, `Vec`) must have a hard cap constant
- Protocol invariants (Double Ratchet, X3DH): replay rejection, ratchet ordering, key expiration, skipped-key caps — see [crypto protocol state](crypto-protocol-state.md) for detail

## Dependencies

- Necessity check before adding any dep — can the standard library or an existing dep cover the need?
- MSRV of any added dep must be ≤ workspace MSRV (see [`rust-toolchain.toml`](../../rust-toolchain.toml))
- For crypto-adjacent crates (touching keys, signatures, encryption, KDFs): require maintainer reputation (RustCrypto org, dalek-cryptography, etc.) and audit history
- Prefer audited crates
- Pin major versions in each crate's `Cargo.toml`; hoist shared deps to `[workspace.dependencies]`. Update via `cargo update -p <crate>` with reasoning in the commit message
- Dependabot owns vulnerability alerts and security-update PRs; the maintainer configures it in GitHub
- When adding or updating dependencies, review licenses, sources, maintenance status, and new transitive duplicates

## Error Handling

- Each crate defines its own domain error type
- All error paths return `Result` — `unwrap()`, `expect()`, and `panic!()` are banned outside of tests
- Error text (Display, Debug, source chain) is for operator logs — concise, debug-useful, lowercase first word, no trailing period (composes via `{e}` chaining)
- Never include secret material — key bytes, plaintext, seeds. Reference by stable identifiers (key IDs, message numbers) instead

## Public API

- Modules are organizational, not public-API boundaries
- `pub` minimization — every `pub` item needs an out-of-crate user (a `pub use` at `lib.rs` doesn't count)
- Secret-bearing types additionally require a consumer who specifically needs the secret form
- Acronym tolerance scales with proximity to consumers, tightest at the FFI boundary:
  - `#[uniffi::export]` (T1): none except universal (`URL`, `HTTP`, `JSON`); all crypto terms spelled out (`signed_prekey`, not `spk`)
  - Cross-crate `pub` (T2): industry-standard primitives only (`KDF`, `AEAD`, `HKDF`, `MAC`); no protocol-internal acronyms (`SPK`, `OPK`, `IK`)
  - `pub(crate)` (T3): protocol shorthand fine (`spk`, `ik`, `ek`, `dh`, `ad`)
  - Function-local: anything readable in context
- Public types must follow project rustdoc guidelines — see [Rust documentation style](rust-docs-style.md)
- Binary-breaking FFI changes (struct field layout under `#[repr(C)]`, removing a `#[uniffi::export]`) require a major version bump

## Rust Style

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

## Tests

- Test names define behavior scope. Assertions should prove that named behavior and its required preconditions
- Avoid duplicate coverage at the same responsibility layer. Higher-level tests focus on the contract added by that layer
- Keep tests and their setup for concrete consumer failures; simple forwarding and duplicated fixtures need no separate suite
- Keep repeated coverage when it protects a security/protocol invariant or verifies behavior across an API, persistence, serialization, FFI, or other boundary
- Inline unit tests live in `#[cfg(test)] mod tests { ... }` at the bottom of the source file they exercise
- Integration tests live in `crates/<crate>/tests/<scenario>.rs` and exercise only the public API; if a test needs an internal item, the test belongs inline
- One scenario per integration test file
- Module docstring on integration tests states the scenario and what crosses what boundary
- Test-only dependencies live under `[dev-dependencies]` in Cargo.toml
- Test assertions must not depend on `SystemTime::now()` or `OsRng` outputs — both may be opaque inputs (e.g., relative timestamps, round-trip keys)
- No shared mutable state across tests — each test owns its `Setup` via a `setup()` function, no `static mut` or `Lazy<>`

## UniFFI

- FFI-incompatible core types must be wrapped in the `roost-client` crate — `&str`, `&[u8]`, lifetimes, trait objects without `#[uniffi::export(with_foreign)]`, tuples, external-crate types without conversion
- Secret bytes cross as bare `Vec<u8>` and wrap in `Zeroizing` immediately in the adapter layer, not client code
- Stateful types wrap with `#[derive(uniffi::Object)]` and interior mutability — decouples internal type evolution from FFI stability
- Foreign-implementable traits use `#[uniffi::export(with_foreign)]` to let clients implement Rust-callable traits
- Errors crossing the UniFFI boundary must use `#[derive(uniffi::Error)]` — library errors and panics cannot propagate
- Internal errors convert to `ClientError` via `From` impls
- `ClientError` variants describe failures in client-relevant terms (e.g., `AlreadyExists`, `NotFound`)
- Internal failures the client cannot meaningfully handle (e.g., lock poisoning, KDF output overflow) reduce to a generic `InternalError { reason: String }` — `reason` is for logs, not client logic
