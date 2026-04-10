---
name: design-review
description: Interview the user about a design or feature plan until every decision branch is resolved. Do not use for code review or implementation tasks.
---

## Steps

1. Run `ls crates/` to identify relevant crates
2. Interview the user one question at a time, walking down each decision branch and resolving dependencies between decisions
3. For each question, provide a recommended answer with brief reasoning
4. If phase context is needed, run `gh milestone list --json title,description --jq '.[] | "\(.title) — \(.description)"' | sort` and ask the user to select one
5. If a question can be answered by reading the codebase, read the relevant files instead of asking
6. Skip questions already answered by the codebase or resolved in prior turns
