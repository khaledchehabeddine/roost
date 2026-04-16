---
name: issue
description: Trigger when the user wants to file a new GitHub issue on the Hermes project board. Not for editing, closing, or triaging existing issues.
---

## Steps

1. Run `gh label list --json name` and `gh milestone list --json number,title` to fetch options
2. Use the provided title as the issue title
3. Ask the user to pick an issue type:
   - **Task** — Feature, docs, chore, or any other unit of work
   - **Parent** — Tracking issue for a group of related tasks
   - **Bug** — Report a defect or unexpected behavior
   - **Security** — Security vulnerability or hardening task
4. Based on type, prompt for the relevant fields:
   - **Task**: description, acceptance criteria
   - **Parent**: description
   - **Bug**: description, reproduction steps, expected behavior
   - **Security**: summary, impact, location, severity (Critical/High/Medium/Low), optional suggested fix
5. Ask: "Any notes to add?" — skip if none
6. Pick a label:
   - Bug → auto-apply `bug`
   - Security → auto-apply `security`
   - Task / Parent → ask the user to pick from available labels
7. Optionally pick a milestone — skip if none
8. Read the corresponding template from `assets/<type>.md` and construct the issue body with the user's answers
9. Create the issue:
   - With milestone: `gh issue create --title "<title>" --body "<body>" --label "<label>" --milestone "<milestone>" --assignee "@me" --project "Hermes"`
   - Without milestone: `gh issue create --title "<title>" --body "<body>" --label "<label>" --assignee "@me" --project "Hermes"`
10. Show the created issue URL
