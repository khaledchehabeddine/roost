# Create Issue

1. Confirm the issue title and select one scaffold:
   - `task`: summary and acceptance criteria.
   - `parent`: summary and child-work boundary.
   - `bug`: summary, reproduction, and expected behavior.
   - `security`: summary, impact, location, severity, and optional mitigation.
2. Read `.github/issue-scaffolds/<type>.md` and populate only supported sections. Ask for missing required facts; do not invent reproduction or impact claims.
3. Select metadata:
   - For task or parent issues, list repository labels and ask when the label is ambiguous.
   - Use `bug` for bug reports and `security` for security work.
   - List milestones and let the user select one or choose none.
4. Show the final title, body, labels, milestone, and project. Require explicit confirmation before the external create action.
5. Create the issue with `gh issue create`, adding the selected milestone when present and the `Aether` project.
6. Return the created issue URL. Do not edit, close, or triage other issues under this workflow.
