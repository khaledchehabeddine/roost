---
paths:
  - "crates/**/*.rs"
---

# Error Handling Rules

## Domain types

- Each crate defines its own domain error type
- All error paths return `Result` — `unwrap()`, `expect()`, and `panic!()` are banned outside of tests

## `Display` impls

- Detailed enough to debug from logs alone — not localized UI strings
- Lowercase first word, no trailing period (consistent across the workspace)
- Acronym handling follows the public-API scope ladder — see [public-api.md](public-api.md)
- Never include secret material — key bytes, plaintext, decrypted output, or seeds. Use reference identifiers (key IDs, message numbers) instead

## Variant docs and recovery

- Every error variant doc states the recovery action a caller should take
- Every method's `# Errors` distinguishes pre-mutation failures from post-commit failures when the recovery action differs
- No blanket "on any error, do X" wording — that hides the variant where the recovery is destructive (e.g., "reset on wrong passphrase" deletes a valid identity)

## Doc-claim discipline

- Every guarantee a doc comment makes (atomicity, rollback, partial-failure handling, detectability) must match what the code actually does
- Limitations get documented explicitly, not implied by silence
