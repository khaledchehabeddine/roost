---
description: Scaffold a new architectural decision record
argument-hint: [short-title]
disable-model-invocation: true
allowed-tools: Bash(ls *) Read Write
---

When scaffolding a decision record:

1. **Pick the context** — ask the user which one:
   - `workspace` → `docs/adr/`
   - `aether-core` → `crates/aether-core/docs/adr/`
   - `aether-crypto` → `crates/aether-crypto/docs/adr/`
   - `aether-uniffi` → `crates/aether-uniffi/docs/adr/`
2. **Find the next number**: `ls <chosen-path>/[0-9]*.md`, take the highest and add one. If the directory does not exist yet, start at `0001`.
3. **Generate the filename**: `NNNN-<short-title-kebab-case>.md` from `$ARGUMENTS`, confirm with the user.
4. **Ask what was decided** — capture the decision and main reasoning in 1–3 sentences.
5. **Write the file** at `<chosen-path>/NNNN-<short-title-kebab-case>.md` using this template:

    ```markdown
    # {Short Title of the Decision}

    **Status:** Accepted

    {1–3 sentence body that captures both the decision and the main reasoning.}
    ```
