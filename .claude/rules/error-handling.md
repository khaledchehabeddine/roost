---
paths:
  - "crates/**/*.rs"
---

# Error Handling Rules

- Each crate defines its own domain error type
- All error paths return `Result` — `unwrap()`, `expect()`, and `panic!()` are banned outside of tests
- Error `Display` implementations should be detailed enough to debug from logs alone — not localized UI strings
- Error `Display` must never include secret material — key bytes, plaintext, decrypted output, or seeds. Use reference identifiers (key IDs, message numbers) instead
