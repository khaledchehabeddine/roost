---
paths:
  - "**/*.rs"
---

# Rust Style Rules

- Module ordering: `mod` declarations → `use` declarations → types → traits → impls → functions
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
