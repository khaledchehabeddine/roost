---
name: rust-docs
description: Trigger when the user wants to add or update /// doc comments on public Rust items. Not for inline code comments, README files, or non-Rust documentation.
---

# Rust Docs

## Workflow

1. Determine target: if no crate or file path is provided, ask the user
2. Read [docs/agents/rust-docs-style.md](../../../docs/agents/rust-docs-style.md) for the tier's doc style spec
3. Audit existing docs against the spec; add or update so each item conforms
4. Run `cargo doc -p <crate> --no-deps` and confirm no warnings
