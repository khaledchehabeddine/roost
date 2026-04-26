---
name: decision-record
description: Trigger when the user wants to record a new architectural decision. Not for updating, superseding, or deleting existing records.
---

## Steps

1. Read [docs/decisions/TEMPLATE.md](../../../docs/decisions/TEMPLATE.md) for the decision record format
2. Find the next four-digit number: run `ls docs/decisions/[0-9]*.md`, take the highest and add one
3. Generate filename `NNNN-<short-title-kebab-case>.md` from the provided title, confirm with user
4. Ask the user: "What was decided?"
5. Ask the user: "Why?"
6. Write `docs/decisions/NNNN-<short-title-kebab-case>.md` using the template with today's date and the user's answers
