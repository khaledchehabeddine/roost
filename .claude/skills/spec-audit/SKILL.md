---
name: spec-audit
description: Audit a Hermes implementation against an authoritative specification (RFC, Signal whitepaper, NIST publication). Walks the spec section-by-section, tags each requirement as conformant/divergent/ambiguous/unimplemented, surfaces a concise summary in the conversation. Use when implementing or modifying spec-defined protocols.
argument-hint: [spec-name-or-url]
allowed-tools: Bash(grep *) Bash(find *) Read WebFetch
---

Audit an implementation against a specification:

1. Identify the spec: `$ARGUMENTS` if provided (URL or canonical name), otherwise ask. Common targets:
   - Signal Double Ratchet (<https://signal.org/docs/specifications/doubleratchet/>)
   - X3DH (<https://signal.org/docs/specifications/x3dh/>)
   - HKDF — RFC 5869
   - ChaCha20-Poly1305 — RFC 8439 / XChaCha — draft-irtf-cfrg-xchacha
   - Ed25519 — RFC 8032
   - Argon2 — RFC 9106
2. Identify the implementation surface — ask the user which crate/module, or grep for likely files (e.g., `crates/hermes-crypto/src/double_ratchet.rs` for Double Ratchet)
3. Fetch the spec if URL-accessible (`WebFetch`); otherwise ask the user to paste the relevant section
4. Walk the spec section by section. For each normative requirement:
   - Quote the spec sentence (or pseudocode block)
   - Locate the corresponding implementation (`file:line` reference)
   - Tag the conformance:
     - **✓ Conformant** — implementation matches spec exactly
     - **✗ Divergent** — intentional deviation; note Hermes' justification (cite ADR if one exists)
     - **⚠ Ambiguous** — spec is unclear; note our interpretation
     - **⊘ Unimplemented** — spec describes optional/future functionality not yet built
5. Surface findings in the conversation as a concise summary — lead with Divergent and Unimplemented (high priority), then Ambiguous, then Conformant as a count only. Each non-conformant item: spec section + `file:line` reference. Offer the full Conformant list on request
6. For every divergent finding without an existing ADR, suggest `/decision-record` to capture the rationale
7. For every security-relevant unimplemented finding, suggest `/issue` to track. Do NOT auto-create either

Pairs with `security-auditor` (this skill produces the input; security-auditor enforces conformance at commit time).
