---
name: issue
description: Create a GitHub issue and link it to the project board
argument-hint: <title>
disable-model-invocation: true
allowed-tools: Bash(gh *)
---

## Context

- Available labels: !`gh label list --json name`
- Available milestones: !`gh milestone list --json number,title`

## Task

1. Use `$ARGUMENTS` as the issue title
2. Ask the user to pick an issue type:
   - **Task** — Feature, docs, chore, or any other unit of work
   - **Parent** — Tracking issue for a group of related tasks
   - **Bug** — Report a defect or unexpected behavior
   - **Security** — Security vulnerability or hardening task
3. Based on type, prompt for the relevant fields:
   - **Task**: description, acceptance criteria
   - **Parent**: description
   - **Bug**: description, reproduction steps, expected behavior
   - **Security**: summary, impact, location, severity (Critical/High/Medium/Low), optional suggested fix
4. Ask: "Any notes to add?" — skip if none
5. Pick a label:
   - Bug → auto-apply `bug`
   - Security → auto-apply `security`
   - Task / Parent → ask the user to pick from available labels
6. Ask the user to optionally pick a milestone — skip if none
7. Read the corresponding template from `templates/<type>.md` and construct the issue body with the user's answers
8. Create the issue:
   - With milestone: `gh issue create --title "<title>" --body "<body>" --label "<label>" --milestone "<milestone>" --assignee "@me" --project "Hermes"`
   - Without milestone: `gh issue create --title "<title>" --body "<body>" --label "<label>" --assignee "@me" --project "Hermes"`
9. Show the created issue URL
