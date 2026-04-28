---
name: Crate lints not configured
description: rust-docs/style.md asserts a `[lints]` table in each Cargo.toml that does not actually exist
type: project
---

`docs/agents/rust-docs/style.md` lines 63-68 contain a "Lint enforcement" table claiming `hermes-uniffi` enforces `missing_crate_level_docs = "warn"` and `missing_docs = "warn"` via `Cargo.toml [lints]`, with other crates inheriting `missing_crate_level_docs` from a workspace setting.

**Why:** As of 2026-04-28 (commit on chore/ai-integration-upgrade), no `[lints]` section exists in `Cargo.toml` (workspace root), `crates/hermes-core/Cargo.toml`, `crates/hermes-crypto/Cargo.toml`, `crates/hermes-transport-ble/Cargo.toml`, or `crates/hermes-uniffi/Cargo.toml`. The doc describes intended state, not current state.

**How to apply:** When reviewing rustdoc-related changes or doc-tier compliance, do NOT assume `cargo build` flags missing docs. The enforcement is currently aspirational — the choice is either (a) wire the lints into Cargo.toml so style.md reflects reality, or (b) soften style.md to "intended enforcement" wording. Flag this drift if a change touches either side.
