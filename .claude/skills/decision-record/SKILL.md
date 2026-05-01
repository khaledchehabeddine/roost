---
description: Scaffold a new architectural decision record
argument-hint: [short-title]
disable-model-invocation: true
allowed-tools: Bash(ls *) Read Write
---

When scaffolding a decision record:

1. **Read the template**: [docs/decisions/TEMPLATE.md](../../../docs/decisions/TEMPLATE.md)
2. **Find the next number**: `ls docs/decisions/[0-9]*.md`, take the highest and add one
3. **Generate the filename**: `NNNN-<short-title-kebab-case>.md` from `$ARGUMENTS`, confirm with the user
4. Ask what was decided
5. Ask why
6. **Write the file**: `docs/decisions/NNNN-<short-title-kebab-case>.md` using the template, today's date, and the user's answers
