# Hermes

## Overview

Hermes is the shared cryptographic and networking core for a private, peer-to-peer encrypted messaging system that works offline over short-range wireless links.

## Architecture

Ports-and-adapters layout. Crate dependencies (`A → B` means "A depends on B"):

- `hermes-crypto`
- `hermes-core` → `hermes-crypto`
- `hermes-transport-ble` → `hermes-core`
- `hermes-uniffi` → `hermes-core`, `hermes-transport-ble`

## Git Workflow

See `CONTRIBUTING.md` for branches, commits, and PR conventions.
