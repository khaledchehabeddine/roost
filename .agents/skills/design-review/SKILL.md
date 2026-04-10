---
name: design-review
description: Trigger when the user wants to walk through a design or feature plan interactively, resolving decisions one at a time. Not for code review, implementation, or post-merge retrospectives.
---

## Steps

1. Run `ls crates/` to identify relevant crates
2. Interview the user one question at a time, walking down each decision branch and resolving dependencies between decisions
3. For each question, provide a recommended answer with brief reasoning
4. If phase context is needed, run `gh milestone list --json title,description --jq '.[] | "\(.title) — \(.description)"' | sort` and ask the user to select one
5. If a question can be answered by reading the codebase, read the relevant files instead of asking
6. Skip questions already answered by the codebase or resolved in prior turns
