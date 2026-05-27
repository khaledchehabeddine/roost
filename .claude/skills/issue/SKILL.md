---
description: Create a GitHub issue and link it to the project board
argument-hint: [title]
disable-model-invocation: true
allowed-tools: Bash(gh *) Read
---

When creating a GitHub issue:

1. **Pick an issue type**:
   - **Task** — feature/chore/docs unit
   - **Parent** — tracking issue for related child tasks
   - **Bug** — defect or unexpected behavior
   - **Security** — vulnerability or hardening task
2. **Prompt for the type's fields**:
   - **Task** — summary + acceptance criteria
   - **Parent** — summary
   - **Bug** — summary + reproduction + expected behavior
   - **Security** — summary + impact + location + severity (Critical/High/Medium/Low) + optional suggested fix
   - Then ask for any optional notes
3. **Pick a label**:
   - Task / Parent → `gh label list --json name`, ask the user to pick
   - Bug → `bug`
   - Security → `security`
4. **Pick a milestone**:
   - `gh milestone list --json number,title`, ask the user
   - Skip if none
5. **Build the body**: read the template at `.github/issue-scaffolds/<type>.md` and fill with the user's answers
6. **Create the issue**:
   - With milestone: `gh issue create --title "$ARGUMENTS" --body "<body>" --label "<label>" --milestone "<milestone>" --project "Aether"`
   - Without milestone: same command minus `--milestone`
