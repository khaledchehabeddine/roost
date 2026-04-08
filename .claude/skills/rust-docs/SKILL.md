---
name: rust-docs
description: Add or update Rust doc comments on public items following the style guide in CLAUDE.md
argument-hint: <file-or-crate-path>
disable-model-invocation: true
allowed-tools: Read, Edit, MultiEdit, Bash(cargo doc *)
---

## Task

### 1. Read the Rust Style Guide

- Read the **Rust Style Guide** section in `CLAUDE.md` for doc comment conventions

### 2. Scope the target

- If `$ARGUMENTS` is a crate name (e.g., `hermes-crypto`): find all `pub` items across the crate
- If `$ARGUMENTS` is a file path: scope to that file only

### 3. Audit and update doc comments

For each `pub` item missing or with incomplete docs:
- Add `///` with a single-sentence summary as the first line
- Add `# Errors` section if the item returns `Result`
- Add `# Panics` section only if the item can actually panic
- Add `# Examples` section for non-obvious APIs
- Skip private helpers unless the logic is subtle

For `lib.rs` files:
- Ensure a `//!` module doc exists at the top — one sentence explaining what the module provides

### 4. Verify

- Run `cargo doc -p <crate> --no-deps` and confirm no warnings

### 5. Summary

- Show the user a summary of what was added or changed
