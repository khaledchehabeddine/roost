# Roost

This is the canonical project policy for agents. See [README.md](README.md) for orientation,
setup and the crate dependency graph.

## Coding guidelines

Before changing code, dependencies, tests, or agent configuration, read the applicable sections of
[the shared coding guidelines](docs/agents/coding-guidelines.md). Runtime rules route to that policy.

## Decision Records

ADRs preserve why a decision was made so future contributors — human or agent — inherit the context. After changes to cross-crate public API, crypto, FFI, or architecture, propose one only when all three hold:

1. **Hard to reverse** — the cost of changing your mind later is meaningful
2. **Surprising without context** — a future reader will wonder "why did they do it this way?"
3. **The result of a real trade-off** — there were genuine alternatives, and you picked one for specific reasons

If any of the three is missing, skip the ADR. Use [`docs/adr/TEMPLATE.md`](docs/adr/TEMPLATE.md) for format. Place cross-crate decisions in `docs/adr/` and crate-specific decisions in the owning crate's `docs/adr/`.

## Agent skills

### Issue tracker

Issues and specs use GitHub; before any tracker operation, read `docs/agents/issue-tracker.md`.

### Triage labels

Triage maps categories and states to repository labels; before changing either, read `docs/agents/triage-labels.md`.

### Domain docs

Domain docs are multi-context; before exploring a crate or proposing terminology or architecture, read `docs/agents/domain.md`.

## Workflow

- Optimize for one maintainer: retain tooling for demonstrated current value or a named future need that would be costly to add later
- Carry authorized work through implementation and verification; preserve the task's scope across follow-ups
- Resolve routine choices from context. Reuse supplied answers and approvals; ask when an unresolved decision materially affects the result
- Explicit user instructions take precedence over skill guidelines. Before a skill causes a pause, complete independent authorized work, then link its `SKILL.md` and quote the blocking instruction
- Keep code, diffs, and secrets off external tools without approval. Commit and push only through the `commit-push` skill when requested
- Invoke configured reviewers for their documented change types; run independent reviews in parallel
- Complete required checks. Broaden or repeat verification only for new changes, failures, or unresolved concerns; use file validation for documentation and configuration edits unless project checks require more
- Report the result, verification, and material limitations in concise plain English; use lists when they aid comparison or sequencing
- See `CONTRIBUTING.md` for branches, commits, and PR conventions
- After a non-obvious project-specific discovery or workaround worth keeping, suggest an `AGENTS.md` update
