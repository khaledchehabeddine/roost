---
paths:
  - "**/*.rs"
---

# Rustdoc Rules

- Document only what cannot be inferred from name, signature, variant types, or visibility
- Document "why" decisions when not captured in a decision record; reference the DR when one exists
- Match the brevity of sibling types in the same file as a baseline
- Prefer deleting a doc over leaving a low-information one
