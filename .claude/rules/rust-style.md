---
paths:
  - "**/*.rs"
---

# Rust Style Rules

## Module structure

- Module ordering: `mod` declarations → `use` declarations → types → traits → impls → functions
- No `pub use` glob re-exports

## Naming

- **Functions:** verbs for actions (`generate_*`, `rotate_*`, `verify_*`); nouns for accessors (`current_bundle`, `public_key`); predicates with `is_*`/`has_*`
- **No `get_` prefix** on accessors — Rust convention drops it
- **`try_*` prefix only when contrasting** with a non-fallible variant in the same scope. Don't use it as a generic "this returns `Result`" marker
- **Constructor shape:** `Type::new(...)` is canonical; `Type::from_<form>(...)` for alternate sources (e.g., `from_secret_bytes`); `Type::with_<thing>(...)` for builder-style
- **Type suffixes:** `*Error` for error types, `*Bundle` for "container of related public material", `*Manager` only when paired with the type it manages (e.g., `IdentityManager` vs `Identity`). Avoid `*Helper`, `*Util`, `*Service`
- **Constants** are `SCREAMING_SNAKE_CASE` regardless of scope; acronym handling follows the public-API scope ladder — see [public-api.md](public-api.md)
