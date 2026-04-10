---
name: create-issue
description: Create a GitHub issue and link it to the project board. Accepts an issue title as input. Do not use for editing or closing existing issues.
---

## Steps

1. Run `gh label list --json name` and `gh milestone list --json number,title` to fetch options
2. Ask the user: "Describe the task or bug?"
3. Ask the user: "What are the acceptance criteria?" — each becomes a checklist item
4. Ask the user: "Any notes to add? (context, links, edge cases)" — skip if none
5. User picks a label from the fetched labels
6. User optionally picks a milestone — skip if none
7. Read `assets/template.md` and write the issue body with the user's answers
8. Create the issue:
   - With milestone: `gh issue create --title "<title>" --body "<body>" --label "<label>" --milestone "<milestone>" --assignee "@me" --project "Hermes"`
   - Without: `gh issue create --title "<title>" --body "<body>" --label "<label>" --assignee "@me" --project "Hermes"`
9. Show the created issue URL
