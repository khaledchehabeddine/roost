---
paths:
  - "crates/**/*.rs"
---

# Error Handling Rules

- Each crate defines its own domain error type
- All error paths return `Result` — `unwrap()`, `expect()`, and `panic!()` are banned outside of tests
- Error text (Display, Debug, source chain) is for operator logs — concise, debug-useful, lowercase first word, no trailing period (composes via `{e}` chaining)
- Never include secret material — key bytes, plaintext, seeds. Reference by stable identifiers (key IDs, message numbers) instead
