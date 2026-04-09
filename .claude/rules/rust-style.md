---
paths:
  - "**/*.rs"
---

# Rust Style Rules

- `//!` module docs required on every `lib.rs` and public module
- Module ordering: `use` declarations → types → traits → impls → functions
- No `pub use` glob re-exports
