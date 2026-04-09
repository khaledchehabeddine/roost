---
paths:
  - "**/*.rs"
---

Based on the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/). Follow standard rustdoc conventions (`# Errors`, `# Panics`, `# Examples`) on all `pub` items. Project-specific additions:

- `//!` module docs required on every `lib.rs` and public module
- Module ordering: `use` declarations → types → trait impls → functions
- No `pub use` glob re-exports
