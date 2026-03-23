---
description: Create a GitHub issue following the project template and link it to the Hermes project board
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
3. Ask the user: "What are the acceptance criteria?"— each criterion becomes a checklist item
4. Ask the user: "Any notes to add? (context, links, edge cases)", skip if not provided
5. Ask the user to pick a label from the fetched labels above
6. Ask the user to optionally pick a milestone from the fetched milestones above — skip if not provided
7. Use `template.md` to write the issue body with the user's answers
8. Create the issue:
   - If milestone provided: `gh issue create --title "<title>" --body "<body>" --label "<label>" --milestone "<milestone>" --assignee "@me" --project "Hermes"`
   - If no milestone: `gh issue create --title "<title>" --body "<body>" --label "<label>" --assignee "@me" --project "Hermes"`
9. Show the user the created issue URL

## Additional resources

- For the issue body template, see [template.md](template.md)
