# Aether

## Overview

Aether is the shared cryptographic and networking core for a private, end-to-end encrypted cloud messaging system.

## Architecture

See [`README.md`](README.md#architecture) for the crate dependency graph.

## Decision Records

ADRs preserve why a decision was made so future contributors — human or agent — inherit the context. After changes to cross-crate public API, crypto, FFI, or architecture, propose one only when all three hold:

1. **Hard to reverse** — the cost of changing your mind later is meaningful
2. **Surprising without context** — a future reader will wonder "why did they do it this way?"
3. **The result of a real trade-off** — there were genuine alternatives, and you picked one for specific reasons

If any of the three is missing, skip the ADR. Use [`docs/adr/TEMPLATE.md`](docs/adr/TEMPLATE.md) for format. Place cross-crate decisions in `docs/adr/` and crate-specific decisions in the owning crate's `docs/adr/`.

## Workflow

- See `CONTRIBUTING.md` for branches, commits, and PR conventions
- After a non-obvious project-specific discovery or workaround worth keeping, suggest a `CLAUDE.md` update
