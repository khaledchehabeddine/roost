---
name: rust-docs
description: Trigger when the user wants to add or update /// doc comments on public Rust items. Not for inline code comments, README files, or non-Rust documentation.
---

## Steps

1. Determine target: if no crate or file path is provided, ask the user
2. Identify the tier per file location:
   - `crates/hermes-uniffi/` → **T1** (rich)
   - `crates/hermes-core/`, `crates/hermes-crypto/`, `crates/hermes-transport-ble/` → **T2** (standard Rust)
   - `pub(crate)` or private items in any crate → **T3** (minimal)
3. Read [docs/agents/rust-docs/style.md](../../../docs/agents/rust-docs/style.md) for the tier's doc style spec
4. Audit existing docs against the spec; add or update so each item conforms
5. Run `cargo doc -p <crate> --no-deps` and confirm no warnings
