---
name: create-decision-record
description: Scaffold a new architectural decision record in docs/decisions/
argument-hint: <short-title>
disable-model-invocation: true
allowed-tools: Bash(ls:*), Read, Write
---

## Context

- Existing decisions: !`ls docs/decisions/`

## Task

1. Determine the next sequential four-digit number from the existing files
2. Use `$ARGUMENTS` as the decision title to generate a kebab-case filename: `NNNN-<short-title>.md`
3. Ask the user: "What was decided?" — wait for response
4. Ask the user: "Why?" — wait for response
5. Write the completed file to `docs/decisions/NNNN-<short-title>.md` with today's date, the user's answers, and the title derived from `$ARGUMENTS`
6. Show the user the created file path and content for review

## Additional Resources

- For the decision record template, see [template.md](template.md)
