# Domain Modeling

Maintain the domain glossary, bounded contexts, context relationships, and architectural decisions without turning them into product specifications or implementation plans.

## Workflow

1. Read `CONTEXT_MAP.md`, then every affected `CONTEXT.md` and relevant accepted ADR.
2. Compare proposed language and behavior with the model, product documentation, and code. Surface contradictions before editing.
3. Test ownership and context boundaries with concrete scenarios, including failure and persistence boundaries.
4. Choose one canonical term for each concept. Update the owning glossary when the term or boundary is resolved; record unresolved conflicts under `Flagged Ambiguities`.
5. Update the context map only when a context or relationship changes. Ask before creating or reorganizing contexts.
6. Check whether a new ADR is warranted. Do not rewrite an accepted decision to make history look current.

## Templates

- Use [CONTEXT_TEMPLATE.md](templates/CONTEXT_TEMPLATE.md) for a context glossary.
- Use [CONTEXT_MAP_TEMPLATE.md](templates/CONTEXT_MAP_TEMPLATE.md) for context ownership and relationships.
- Use [ADR_TEMPLATE.md](templates/ADR_TEMPLATE.md) for a new or superseding decision.

## Boundaries

- Put terminology, ownership, cardinality, and conflicting synonyms in `CONTEXT.md`.
- Put context locations and directional relationships in `CONTEXT_MAP.md`.
- Put product behavior and requirements in product documentation.
- Put implementation mechanics in code or technical documentation.
- Propose an ADR only when the decision is hard to reverse, surprising without context, and a genuine trade-off.
- Place workspace decisions in `docs/adr/` and crate-owned decisions in `crates/<crate>/docs/adr/`.
- Supersede a changed accepted decision with a new ADR. Deprecate it only when it no longer applies and has no replacement.
