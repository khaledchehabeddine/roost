---
name: create-issue
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
2. Ask the user: "Describe the task or bug?"
3. Ask the user: "What are the acceptance criteria?" — each criterion becomes a checklist item
4. Ask the user: "Any notes to add? (context, links, edge cases)" — skip if none
5. Ask the user to pick a label from the fetched labels
6. Ask the user to optionally pick a milestone — skip if none
7. Read `template.md` and write the issue body with the user's answers
8. Create the issue:
   - With milestone: `gh issue create --title "<title>" --body "<body>" --label "<label>" --milestone "<milestone>" --assignee "@me" --project "Hermes"`
   - Without milestone: `gh issue create --title "<title>" --body "<body>" --label "<label>" --assignee "@me" --project "Hermes"`
9. Show the created issue URL
