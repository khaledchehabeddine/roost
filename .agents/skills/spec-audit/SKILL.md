---
name: spec-audit
description: Trigger when auditing a Hermes implementation against an authoritative specification (RFC, Signal whitepaper, NIST publication). Walks the spec section-by-section, tags conformance, surfaces a concise summary in the conversation. Not for general code review — use rust-code-reviewer for that.
---

## Steps

### 1. Identify the spec

Ask the user (or use provided argument). Common targets:

- Signal Double Ratchet (<https://signal.org/docs/specifications/doubleratchet/>)
- X3DH (<https://signal.org/docs/specifications/x3dh/>)
- HKDF — RFC 5869
- ChaCha20-Poly1305 — RFC 8439 / XChaCha — draft-irtf-cfrg-xchacha
- Ed25519 — RFC 8032
- Argon2 — RFC 9106

### 2. Identify the implementation surface

Ask the user which crate/module, or grep for likely files (e.g., `crates/hermes-crypto/src/double_ratchet.rs` for Double Ratchet).

### 3. Fetch the spec

If URL-accessible, fetch via web tool. Otherwise ask the user to paste the relevant section.

### 4. Walk the spec section by section

For each normative requirement:

- Quote the spec sentence (or pseudocode block)
- Locate the corresponding implementation (`file:line` reference)
- Tag the conformance:
  - **✓ Conformant** — implementation matches spec exactly
  - **✗ Divergent** — intentional deviation; note Hermes' justification (cite ADR if one exists)
  - **⚠ Ambiguous** — spec is unclear; note our interpretation
  - **⊘ Unimplemented** — spec describes optional/future functionality not yet built

### 5. Surface findings

Concise conversation summary, not a separate file. Lead with **Divergent** and **Unimplemented** (high priority), then **Ambiguous**, then **Conformant** as a count only. Each non-conformant item: spec section + `file:line` reference. Offer the full Conformant list on request.

### 6. Suggest follow-ups

- For every **divergent** finding without an existing ADR, suggest scheduling a `decision-record` to capture the rationale
- For every **unimplemented** finding that is security-relevant, suggest opening a security issue via the `issue` skill
- Do NOT auto-create issues or ADRs — only suggest

## See also

- `security-auditor` subagent (this skill produces the input; security-auditor enforces conformance at commit time)
- `crypto-patterns` skill — for crypto-specific spec audits
- `docs/decisions/` — past ADRs documenting Hermes' deliberate divergences
