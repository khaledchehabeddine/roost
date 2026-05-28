---
name: decision-record
description: Trigger when the user wants to record a new architectural decision. Not for updating, superseding, or deleting existing records.
---

# Decision Record

## Workflow

1. Ask the user which context the decision belongs to:
   - `workspace` → `docs/adr/`
   - `aether-core` → `crates/aether-core/docs/adr/`
   - `aether-crypto` → `crates/aether-crypto/docs/adr/`
   - `aether-uniffi` → `crates/aether-uniffi/docs/adr/`
2. Find the next four-digit number: run `ls <chosen-path>/[0-9]*.md`, take the highest and add one. If the directory does not exist yet, start at `0001`.
3. Generate filename `NNNN-<short-title-kebab-case>.md` from the provided title; confirm with the user
4. Ask the user: "What was decided?"
5. Ask the user: "Why?"
6. Write `<chosen-path>/NNNN-<short-title-kebab-case>.md` using this template, combining the decision and reasoning into a 1–3 sentence body:

    ```markdown
    # {Short Title of the Decision}

    **Status:** Accepted

    {1–3 sentence body combining the decision and the main reasoning.}
    ```
