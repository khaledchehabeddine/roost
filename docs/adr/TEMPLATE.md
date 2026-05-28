# ADR Template

The format for an Architectural Decision Record.

## Format

```markdown
# {Short Title of the Decision}

**Status:** Accepted

{1–3 sentence body that captures both the decision and the main reasoning.}
```

That's it. An ADR can be a single paragraph. The value is in recording *that* a decision was made and *why* — not in filling out sections.

## Example

```markdown
# Cryptographic Primitive Selection

**Status:** Accepted

X25519 (key exchange) and Ed25519 (signing) are the cryptographic primitives for Aether, both derived from Curve25519 via the audited `x25519-dalek` and `ed25519-dalek` crates. Curve25519 is chosen for constant-time arithmetic by design, compact 32-byte keys, transparent parameter design, and shared audit surface across both operations — one curve, one audit, proven in Signal and Tor production deployments.
```

## Optional Sections

Only include these when they add genuine value. Most ADRs won't need them.

- **Considered Options** — one bullet per rejected alternative with a brief rationale.
- **Consequences** — one bullet per downstream effect.

## Numbering

Sequential within each `docs/adr/` folder: scan `[0-9]*.md`, take the highest, add one. Workspace-wide `docs/adr/` and each per-crate `crates/<crate>/docs/adr/` number independently.

## When to Open an ADR

Open an ADR when all three are true:

1. **Hard to reverse** — the cost of changing your mind later is meaningful
2. **Surprising without context** — a future reader will wonder "why on earth did they do it this way?"
3. **The result of a real trade-off** — there were genuine alternatives, and you picked one for specific reasons

If any of the three is missing, skip the ADR. Trivial fixes and reversible choices don't need one.
