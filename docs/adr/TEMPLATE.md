# ADR Template

The format for an Architectural Decision Record.

## Format

```markdown
# {Short Title of the Decision}

**Status:** Accepted

{1–3 sentence body that captures both the decision and the main reasoning.}
```

That's it. An ADR can be a single paragraph. The value is in recording *that* a decision was made and *why* — not in filling out sections.

## Optional Sections

Only include these when they add genuine value. Most ADRs won't need them.

- **Considered Options** — one bullet per rejected alternative with a brief rationale.
- **Consequences** — one bullet per downstream effect.

## Numbering

Sequential within each `docs/adr/` folder: scan `[0-9]*.md`, take the highest, add one. Workspace-wide `docs/adr/` and each per-crate `crates/<crate>/docs/adr/` number independently.

## Example

```markdown
# Logs Append-Only

**Status:** Accepted

All audit log entries are append-only and never modified or deleted, even on corrections. A correction is written as a new entry referencing the original, because mutability would break the audit trail's integrity guarantee and forensic investigators rely on append-only semantics to detect tampering.

## Considered Options

- Mutable log entries with edit history. Rejected. Reconstructing the truth from edit history is fragile and depends on the edit-history feature working correctly.
- Delete-on-correction with archived backups. Rejected. Creates ambiguity about which version is canonical and the archive becomes another mutable surface.

## Consequences

- Storage grows monotonically; periodic archival to cold storage is required.
- Corrections require two writes (the correction entry plus a reference link), which is more code but reads more clearly.
```
