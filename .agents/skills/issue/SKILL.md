---
name: issue
description: Trigger when the user wants to file a new GitHub issue on the project board. Not for editing, closing, or triaging existing issues.
---

# Create Issue

## Workflow

1. Ask the user to pick an issue type:
   - **Task** — Feature, chore, docs, or any other unit of work
   - **Parent** — Tracking issue for a group of related tasks
   - **Bug** — Report a defect or unexpected behavior
   - **Security** — Security vulnerability or hardening task
2. Prompt for the type's fields, then ask for any optional notes:
   - **Task**: summary, acceptance criteria
   - **Parent**: summary
   - **Bug**: summary, reproduction, expected behavior
   - **Security**: summary, impact, location, severity (Critical/High/Medium/Low), optional suggested fix
3. Pick a label:
   - **Task / Parent** → run `gh label list --json name`, ask the user to pick
   - **Bug** → `bug`
   - **Security** → `security`
4. Ask the user to pick a milestone via `gh milestone list --json number,title`; skip if none
5. Read the corresponding template from `.github/issue-scaffolds/<type>.md` and construct the issue body with the user's answers
6. Create the issue:
   - With milestone: `gh issue create --title "<title>" --body "<body>" --label "<label>" --milestone "<milestone>" --project "Hermes"`
   - Without milestone: `gh issue create --title "<title>" --body "<body>" --label "<label>" --project "Hermes"`
