---
name: rust-docs
description: Add or update Rust doc comments on public items. Accepts a file or crate path as input.
---

## Steps

1. Read the Rust Style section in `AGENTS.md` for doc comment conventions
2. If no target path is provided, ask the user for the crate or file path
   - Crate name: find all `pub` items across the crate
   - File path: scope to that file only
3. Audit and update doc comments on `pub` items following the style guide
4. Run `cargo doc -p <crate> --no-deps` and confirm no warnings
5. Show the user a summary of what was added or changed
