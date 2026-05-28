# Aether

## Overview

Aether is the shared cryptographic and networking core for a private, end-to-end encrypted cloud messaging system.

## Architecture

See [`README.md`](README.md#architecture) for the crate dependency graph.

## Workflow

- See `CONTRIBUTING.md` for branches, commits, and PR conventions
- After any change to cross-crate public API, cryptographic constructions, FFI at `crates/aether-uniffi/`, or workspace architecture, evaluate against the ADR gate (hard to reverse + surprising without context + result of real trade-off). If all three hold, propose writing an ADR using [`docs/adr/TEMPLATE.md`](docs/adr/TEMPLATE.md) — `docs/adr/` for cross-crate decisions, the owning crate's `docs/adr/` for crate-specific
- After a non-obvious project-specific discovery or workaround worth keeping, suggest a `CLAUDE.md` update
