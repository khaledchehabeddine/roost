---
name: decision-record
description: Trigger when the user wants to record a new architectural decision. Not for updating, superseding, or deleting existing records.
---

# Decision Record

## Workflow

1. Read [ADR_TEMPLATE.md](./ADR_TEMPLATE.md) for the decision record format
2. Ask the user which context the decision belongs to:
   - `workspace` → `docs/adr/`
   - `aether-core` → `crates/aether-core/docs/adr/`
   - `aether-crypto` → `crates/aether-crypto/docs/adr/`
   - `aether-uniffi` → `crates/aether-uniffi/docs/adr/`
3. Find the next four-digit number: run `ls <chosen-path>/[0-9]*.md`, take the highest and add one. If the directory does not exist yet, start at `0001`.
4. Generate filename `NNNN-<short-title-kebab-case>.md` from the provided title; confirm with the user
5. Ask the user: "What was decided?"
6. Ask the user: "Why?"
7. Write `<chosen-path>/NNNN-<short-title-kebab-case>.md` using the template, combining the decision and reasoning into a 1–3 sentence body
