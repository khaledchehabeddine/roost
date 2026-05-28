---
description: Scaffold a new architectural decision record
argument-hint: [short-title]
disable-model-invocation: true
allowed-tools: Bash(ls *) Read Write
---

When scaffolding a decision record:

1. **Read the template**: [ADR_TEMPLATE.md](./ADR_TEMPLATE.md)
2. **Pick the context** — ask the user which one:
   - `workspace` → `docs/adr/`
   - `aether-core` → `crates/aether-core/docs/adr/`
   - `aether-crypto` → `crates/aether-crypto/docs/adr/`
   - `aether-uniffi` → `crates/aether-uniffi/docs/adr/`
3. **Find the next number**: `ls <chosen-path>/[0-9]*.md`, take the highest and add one. If the directory does not exist yet, start at `0001`.
4. **Generate the filename**: `NNNN-<short-title-kebab-case>.md` from `$ARGUMENTS`, confirm with the user.
5. **Ask what was decided** — capture the decision and main reasoning in 1–3 sentences.
6. **Write the file** at `<chosen-path>/NNNN-<short-title-kebab-case>.md` using the template.
