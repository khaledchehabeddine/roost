# Repository Review Rubric

Apply this living rubric to the cleanup stack and future repository changes. Update its rules in
place when review feedback establishes a project-wide preference. Suggested customizations are
notes, not active policy, until implemented separately.

## Target state

Leave every tracked file intentional, role-correct, concise, internally consistent, and verifiable.
Preserve current product specifications unless the task explicitly changes them. Keep the local
quality interface deterministic so contributors and future orchestration can produce comparable
results without repository-specific guesswork.

"Perfect" means every applicable rule below passes and every known in-scope finding is resolved. It
does not mean unbounded polish or speculative work.

## Acceptance

- `PASS`: every applicable rule is satisfied.
- `BLOCK`: an unresolved current-specification, correctness, security, auditability, file-role,
  clarity, or unnecessary-scope problem exists.
- `DEFER`: an idea may help later but is not required by the current specification or an accepted
  cheap abstraction.
- Do not use numeric scores or trade one failing category against another.
- Report a finding only when it identifies a violated rule or current requirement. Record subjective
  preferences as feedback candidates instead of blockers.
- For each blocking finding, name the applicable rule, concrete evidence, impact, and smallest
  complete correction. Do not bundle unrelated corrections into one finding.
- Make every exception explicit. Record the approving human, rationale, and compensating evidence;
  correctness and security exceptions require evidence addressing the stated failure or threat.

## Decision order

1. Protect correctness, security, and auditability.
2. Satisfy current product specifications and accepted decisions.
3. Prefer the clearest minimal design.
4. Optimize performance only with evidence.
5. Reduce raw code only after the preceding constraints pass.

Surface conflicts between these priorities. Do not silently change product behavior to satisfy a
preferred implementation pattern. When authoritative sources conflict or ownership is unclear,
block and ask instead of inferring a resolution.

## Change discipline

- Implement the smallest complete change that satisfies the task and every applicable standard.
- Do not add compatibility, migration, configurability, extensibility, or fallback behavior unless
  the current specification requires it.
- Do not clean unrelated files opportunistically.
- Give each cleanup PR an explicit file or responsibility scope. Leave every owned file at the final
  standard before that PR passes.
- After the cleanup, require every modified file to satisfy its complete file-type contract,
  including pre-existing problems within that file. Change other files only when required callers,
  consumers, tests, documentation, or generated outputs must move with it.
- Prefer deletion, direct code, standard-library facilities, and existing repository mechanisms over
  new layers.

### Cheap abstraction exception

Accept an abstraction beyond the immediate specification only when every condition holds:

1. It serves the current change and a named, already-planned future use.
2. Adding it now costs less than implementing those uses independently.
3. It is local and reversible, with no speculative public API, dependency, configuration, or
   operational state.
4. The current change exercises and tests it.
5. It keeps ownership, security behavior, and control flow explicit.

One current consumer plus one concrete near-term consumer is sufficient. If any condition fails,
defer the abstraction.

## File-type contracts

| File type | Passing standard |
|---|---|
| Rust production code | Preserve required behavior and security properties; use safe, idiomatic, readable Rust; minimize visibility, allocation, cloning, dependencies, and state; model failures explicitly; document public caller contracts; measure claimed performance benefits. |
| Rust tests | Prove one named behavior and its preconditions deterministically; retain boundary, invariant, malformed-input, compatibility, and security evidence where responsibility changes; avoid duplicate same-layer coverage. |
| Rustdoc | State the caller contract concisely, including errors, panics, safety, limitations, and material costs where applicable; add examples only when they clarify correct use. |
| Swift or Kotlin reference consumer | Compile against generated APIs, use idiomatic target-language ownership and errors, and demonstrate only the repository-owned integration contract. |
| Product specification | Declare current required behavior, constraints, and acceptance outcomes without prescribing implementation unless the mechanism is itself a requirement. |
| Domain glossary | Declare canonical domain vocabulary, ownership, cardinality, and unresolved ambiguity without product requirements or implementation plans. |
| Context map | Declare bounded-context locations and directional relationships without duplicating their glossaries. |
| ADR | Preserve context, decision, alternatives, and consequences; record only hard-to-reverse, surprising trade-offs; supersede changed accepted decisions instead of rewriting history. |
| Protocol or security guide | State normative invariants, algorithms, limits, trust boundaries, and threats without issue history or transient release status. |
| README, architecture, onboarding, or contribution guide | Serve its named audience with current entry points, ownership, and procedures; keep unique facts in one canonical location. |
| CI, release, or operational runbook | Use direct imperative procedures, prerequisites, gates, failure handling, and verification steps. |
| Agent instruction or reviewer | Use direct imperative workflow, explicit scope, concrete stop conditions, and auditable output; keep one canonical body and avoid optional polish findings. |
| Agent adapter | Contain only native discovery or invocation metadata plus one route to its canonical body; keep trigger order aligned across supported agents. |
| Shell script | Be deterministic, quoted, shell-checked, explicit about prerequisites and exit behavior, safe around destructive paths, and free of implicit tool installation. |
| CI workflow | Invoke the same named local checks, use least privilege and pinned inputs, cancel superseded work, scope caches and expensive jobs, and expose a stable aggregate result. |
| Manifest, lockfile, or configuration | Contain only necessary entries, express supported versions and policy explicitly, preserve generated ownership where applicable, and pass its native validator. |
| Generated binding or artifact | Regenerate deterministically from an identified source, remain drift-free, and pass representative consumer or verification checks; never hand-polish generated output. |
| Fixture or cryptographic vector | Record trustworthy provenance, stable encoding, expected behavior, and replay or independent validation; contain no production secret. |
| Package or release material | Resolve from the exact intended revision, preserve version consistency, and verify reproducibility, checksums, signatures, provenance, and consumer installation as applicable. |

Apply the closest contract to an unlisted file type and add a row when the distinction recurs.

## Repository sustainability

- Keep one documented local entry point for repository checks. CI and future orchestration call its
  named commands instead of reconstructing project logic.
- Keep checks deterministic, base-aware where selection depends on a diff, and explicit about
  missing tools. Never install tools implicitly.
- Automate a rule only when the check is cheap, stable, and unlikely to create false positives.
  Assign judgment rules to a named review rather than approximating them with brittle text scans.
- Keep Aether independent of any specific tracker or orchestrator. Integration should require
  configuration and command invocation, not changes to product architecture or quality policy.

## Feedback handling

- **Rule:** generalizable across future work; update this rubric and suggest a durable customization.
- **Clarification:** an existing rule was ambiguous; tighten it in place.
- **Exception:** specific to one change; record it in that PR only.
- **Deferred idea:** potentially useful but outside current specifications; track it separately.

Use Git history as the change record. Do not add review anecdotes or a duplicate changelog here.

## Customization candidates

Keep every candidate here until a later review explicitly approves implementing it.

| Rule group | Suggested customization | Why |
|---|---|---|
| Decision order and minimal complete change | `AGENTS.md` | These principles should shape every repository mutation once promoted. |
| Cheap abstraction exception | `AGENTS.md` and the simplifier reviewer | Implementers need the eligibility test; simplification review should reject speculative layers. |
| Scoped cleanup and touched-file enforcement | `commit-push` and applicable reviewers | Publication review owns the exact diff and can enforce complete in-scope cleanup. |
| Rust, tests, dependencies, UniFFI, and rustdoc contracts | Rust quality router and matching references | Task-specific detail should load only when relevant. |
| Documentation and domain-model contracts | Domain-modeling or documentation guidance | Document roles need focused maintenance instructions rather than always-on detail. |
| Agent customization contracts | Agent-configuration guidance and deterministic adapter checks | Canonical ownership and native adapter integrity benefit from shared instructions plus cheap validation. |
| Shell, CI, binding, packaging, and release contracts | Focused instructions plus named `scripts/check.sh` commands | Procedures belong in guidance; deterministic properties belong in executable checks. |
| Review verdict and finding shape | Canonical reviewer bodies | Reviewers should apply the same strict acceptance semantics without duplicating the whole rubric. |
| Tracker or orchestration integration | Project-local integration configuration only when selected | Keep quality policy independent from Symphony, Linear, or any replacement. |
