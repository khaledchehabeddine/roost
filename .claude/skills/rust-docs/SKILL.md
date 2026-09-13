---
description: Audit and update symbol, crate and module documentation against the shared style reference.
argument-hint: [crate-or-file-path]
allowed-tools: Bash(cargo doc *) Bash(cargo test *) Bash(RUSTDOCFLAGS=*) Edit MultiEdit Read
paths: "**/*.rs"
---

Use `$ARGUMENTS` as the target when supplied.

Read and follow [the shared rust-docs workflow](../../../docs/agents/workflows/rust-docs.md).
