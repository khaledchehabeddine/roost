---
name: rust-docs
description: Add or update Rust doc comments on public items
argument-hint: <file-or-crate-path>
allowed-tools: Bash(cargo doc *) Edit MultiEdit Read
---

## Task

1. Read the **Rust Style Guide** section in `CLAUDE.md` for doc comment conventions
2. If `$ARGUMENTS` is not provided, ask the user for the target crate or file path. If a crate name: find all `pub` items across the crate. If a file path: scope to that file only
3. Audit and update doc comments on `pub` items following the style guide
4. Run `cargo doc -p <crate> --no-deps` and confirm no warnings
5. Show the user a summary of what was added or changed
