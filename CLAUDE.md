# Hermes

## Overview

Hermes is the shared cryptographic and networking core for a private, peer-to-peer encrypted messaging system that works offline over short-range wireless links.

## Architecture

Ports-and-adapters layout. Crate dependencies (`A → B` means "A depends on B"):

- `hermes-crypto`
- `hermes-core` → `hermes-crypto`
- `hermes-transport-ble` → `hermes-core`
- `hermes-uniffi` → `hermes-core`, `hermes-transport-ble`

## Workflow

- Follow `CONTRIBUTING.md` for Git workflows.

## Rules

Loaded on-demand from `.claude/rules/` by file path:

- `crypto.md` — crypto primitives and security constraints (hermes-crypto, hermes-core)
- `rust-style.md` — doc comment and code structure conventions (all .rs files)
- `uniffi.md` — UniFFI naming conventions (hermes-uniffi)
