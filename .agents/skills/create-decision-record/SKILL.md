---
name: create-decision-record
description: Scaffold a new architectural decision record. Accepts a short title as input. Do not use for updating or superseding existing records.
---

## Steps

1. Run `ls docs/decisions/` to find existing records
2. Read `assets/template.md` for the decision record format
3. Determine the next sequential four-digit number from existing files
4. Generate kebab-case filename from the provided title: `NNNN-<short-title>.md`, confirm with user
5. Ask the user: "What was decided?"
6. Ask the user: "Why?"
7. Write the file to `docs/decisions/NNNN-<short-title>.md` using the template with today's date and the user's answers
8. Show the created file path and content for review
