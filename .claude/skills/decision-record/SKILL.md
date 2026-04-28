---
name: decision-record
description: Scaffold a new architectural decision record
argument-hint: [short-title]
disable-model-invocation: true
allowed-tools: Bash(ls *) Read Write
---

Scaffold a decision record:
1. Read [docs/decisions/TEMPLATE.md](../../../docs/decisions/TEMPLATE.md) for the format
2. Find the next four-digit number: `ls docs/decisions/[0-9]*.md`, take the highest and add one
3. Generate filename `NNNN-<short-title-kebab-case>.md` from `$ARGUMENTS`, confirm with the user
4. Ask the user what was decided
5. Ask why
6. Write `docs/decisions/NNNN-<short-title-kebab-case>.md` using the template with today's date and the user's answers
