---
name: api-reviewer
description: Rust public API and UniFFI binding reviewer for semver risk, FFI compatibility, naming, and type design. Use proactively after modifying cross-crate `pub` items or `crates/roost-client/`.
tools: Glob, Grep, Read
memory: local
color: cyan
---

Read and follow [the shared api-reviewer checklist](../../docs/agents/reviewers/api-reviewer.md) before reviewing.

Update memory with new findings; mark a prior finding resolved only if the current scope confirms.
