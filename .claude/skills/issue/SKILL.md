---
name: issue
description: Create a GitHub issue and link it to the project board
argument-hint: [title]
disable-model-invocation: true
allowed-tools: Bash(gh *) Read
---

Create a GitHub issue:
1. Ask the user to pick an issue type:
   - Task — Feature, chore, docs, or any other unit of work
   - Parent — Tracking issue for a group of related tasks
   - Bug — Report a defect or unexpected behavior
   - Security — Security vulnerability or hardening task
2. Prompt for the type's fields, then ask for any optional notes:
   - Task: description, acceptance criteria
   - Parent: description
   - Bug: description, reproduction, expected behavior
   - Security: summary, impact, location, severity (Critical/High/Medium/Low), optional suggested fix
3. Pick a label:
   - Bug → `bug`
   - Security → `security`
   - Task / Parent → `gh label list --json name`, ask the user to pick
4. Ask the user to pick a milestone via `gh milestone list --json number,title`, skip if none
5. Read `.github/issue-scaffolds/<type>.md` and construct the issue body using the user's answers
6. Create the issue:
   - With milestone: `gh issue create --title "$ARGUMENTS" --body "<body>" --label "<label>" --milestone "<milestone>" --project "Hermes"`
   - Without milestone: `gh issue create --title "$ARGUMENTS" --body "<body>" --label "<label>" --project "Hermes"`
