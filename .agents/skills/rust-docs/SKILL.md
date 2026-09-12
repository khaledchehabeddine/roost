---
name: rust-docs
description: Audit and update Rust symbol, crate and module documentation, including /// and //! comments. Not for inline comments, README files, ADRs or generated bindings.
---

# Rust docs

## Workflow

1. Resolve the target from the request and current task. Ask for a crate, file or symbol only when the scope is missing.
2. Read [the domain routing guide](../../../docs/agents/domain.md) for terminology and [the Rust documentation style](../../../docs/agents/rust-docs-style.md) for tier selection and content. These references own the policy.
3. Audit and update the target's `///` and `//!` documentation against the code. Keep implementation edits and inline-comment changes outside this skill's scope, along with README, ADRs, agent configuration and generated bindings.
4. Run `RUSTDOCFLAGS="-D warnings" cargo doc --locked -p <crate> --no-deps`. When executable examples change, also run `cargo test --locked -p <crate> --doc`. Report the checked scope and any remaining contract ambiguity.
