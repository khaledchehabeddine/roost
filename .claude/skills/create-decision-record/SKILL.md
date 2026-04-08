---
name: create-decision-record
description: Scaffold a new architectural decision record
argument-hint: <short-title>
disable-model-invocation: true
allowed-tools: Bash(ls *) Read Write
---

## Context

- Existing decisions: !`ls docs/decisions/`

## Task

1. Read `template.md` for the decision record format
2. Determine the next sequential four-digit number from the existing files
3. Generate kebab-case filename from `$ARGUMENTS`: `NNNN-<short-title>.md`, confirm with user
4. Ask the user: "What was decided?"
5. Ask the user: "Why?"
6. Write the file to `docs/decisions/NNNN-<short-title>.md` using the template with today's date and the user's answers
7. Show the created file path and content for review
