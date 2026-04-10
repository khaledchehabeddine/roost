---
name: design-review
description: Interview the user about a design or feature plan until resolved
argument-hint: <design or feature to review>
disable-model-invocation: true
allowed-tools: Bash(gh milestone list *) Bash(ls *) Read
---

## Context

- Relevant crates: !`ls crates/`

## Task

Interview the user about **$ARGUMENTS** one question at a time until every decision branch is resolved. Walk down each branch, resolving dependencies between decisions one-by-one. For each question, provide your recommended answer with brief reasoning.

If phase context is needed, run `gh milestone list --json title,description --jq '.[] | "\(.title) — \(.description)"' | sort` and ask the user to select one.
If a question can be answered by reading the codebase, read the relevant file(s) instead of asking.
Skip questions already answered by the codebase or resolved in prior turns.
