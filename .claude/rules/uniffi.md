---
paths:
  - "crates/hermes-uniffi/**"
---

# UniFFI Rules

- FFI-incompatible core types must be wrapped within this crate
- Errors crossing the UniFFI boundary must use `#[derive(uniffi::Error)]` — library errors and panics cannot propagate
