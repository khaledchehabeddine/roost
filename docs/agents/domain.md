# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT_MAP.md`** at the repo root: select every context relevant to the task, then read each linked `CONTEXT.md`.
- **`docs/adr/`**: read system-wide ADRs that touch the area.
- **`crates/<crate>/docs/adr/`**: read crate-scoped ADRs for each selected context when the directory exists.

If an optional ADR directory does not exist, proceed silently. When `CONTEXT_MAP.md` exists, every linked `CONTEXT.md` is required: report a missing target rather than silently dropping its context. The `domain-modeling` skill creates domain docs lazily when terms or decisions are resolved.

## File structure

Multi-context layout:

```
/
├── CONTEXT_MAP.md
├── docs/adr/                           ← system-wide decisions
└── crates/
    ├── <crate>/
    │   ├── CONTEXT.md
    │   └── docs/adr/                   ← crate-specific decisions
    └── <crate>/
        ├── CONTEXT.md
        └── docs/adr/
```

## Use the glossary's vocabulary

When output names a domain concept in an issue title, proposal, hypothesis, or test, use the term defined by the selected context. Avoid synonyms that its glossary rejects.

If a needed concept is absent, reconsider whether the project uses it; otherwise note the gap for `domain-modeling`.

## Flag ADR conflicts

If output contradicts an existing ADR, surface it explicitly:

> _Contradicts ADR-0007 (event-sourced orders), but worth reopening because…_
