---
name: rust-docs
description: Add or update Rust doc comments
argument-hint: [crate-or-file-path]
allowed-tools: Bash(cargo doc *) Edit MultiEdit Read
paths: "**/*.rs"
---

Audit and update Rust doc comments:
1. Determine target: `$ARGUMENTS` if provided (crate name or file path), otherwise ask the user
2. Identify the tier per file location:
   - `crates/hermes-uniffi/` → T1 (rich)
   - `crates/hermes-core/`, `crates/hermes-crypto/`, `crates/hermes-transport-ble/` → T2 (standard Rust)
   - `pub(crate)` or private items in any crate → T3 (minimal)
3. Read [reference.md](reference.md) for the tier's doc style spec
4. Audit existing docs against the spec; add or update so each item conforms
5. Run `cargo doc -p <crate> --no-deps` and confirm no warnings
