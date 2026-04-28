---
description: Audit and update documentation on Rust symbols per the project's documentation tier system.
argument-hint: [crate-or-file-path]
allowed-tools: Bash(cargo doc *) Edit MultiEdit Read
paths: "**/*.rs"
---

When auditing or updating Rust doc comments:

1. **Determine the target**: use `$ARGUMENTS` if provided (crate name or file path), otherwise ask the user
2. **Read the style spec**: [docs/agents/rust-docs-style.md](../../../docs/agents/rust-docs-style.md) for the tier's conventions
3. **Audit existing docs**: add or update so each item conforms to the tier
4. **Verify**: `cargo doc -p <crate> --no-deps` and confirm no warnings
