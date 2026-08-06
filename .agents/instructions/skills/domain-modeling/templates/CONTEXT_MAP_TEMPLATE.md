# Context Map Template

```markdown
# Context Map

## Contexts

- [{Context Name}]({path/to/CONTEXT.md}) — {owned domain responsibility}

## Relationships

- **{Provider} → {Consumer}**: {information, capability, or model supplied}
```

- Use `A → B` when A supplies B. Use `A ↔ B` only for a genuinely bidirectional relationship.
- Omit `Relationships` when contexts are independent.
- Describe ownership and integration boundaries, not implementation call graphs.
