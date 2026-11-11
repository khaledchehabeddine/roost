# Roost

## Context

- @README.md
- Before changing what Roost does, read [FEATURES.md](FEATURES.md).
- Before changing a design, read the [ADRs](docs/adr/) that cover it.
- Before naming a domain concept, read [GLOSSARY.md](GLOSSARY.md).

## Workflow

- Make the smallest complete change for the task.
- Choose the simplest design that keeps the next likely change easy.
- Update any document or comment the change makes outdated.
- When you review a change, apply the skills that cover the files it touches.
- Keep working files, such as plans and notes, out of commits.
- When you learn a preference or workaround worth keeping, suggest which instruction file to add it to.
- When the user corrects a mistake that could happen again, propose the smallest change to a skill or document that prevents it.

## Skills

- When committing changes or amending a commit, pushing a branch, or creating or updating a pull request, use the commit-push skill.
- When naming a domain concept or editing the glossary, or when making a decision that is costly to reverse or editing an ADR, use the domain-modeling skill.
- When working with Rust code or Cargo.toml files, use the rust skill.
- When finishing a change, before reporting it done, use the verify skill.
- When writing documentation, skills, code comments, commit messages, or pull requests, use the writing skill.
