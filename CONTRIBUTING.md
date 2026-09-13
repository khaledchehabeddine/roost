# Contributing

Branches use `<type>/<short-description>`; types follow the repository's GitHub labels.

Commits use an imperative summary and concrete change bullets:

```text
<type>: <summary>
- <what changed>
```

Types: `feat`, `fix`, `chore`, `docs`, `ci`, `refactor`, `test`.
Append a `Co-Authored-By:` trailer when an AI agent contributed.

Use the [PR template](.github/PULL_REQUEST_TEMPLATE.md). CI must pass before review completion.

Run the checks in [CI](docs/ci.md) before submitting. Agent workflows follow the project policy
in [AGENTS.md](AGENTS.md).

## Documentation ownership

| Document | Owns |
| --- | --- |
| `README.md` | Orientation, setup, crate graph and documentation links |
| `CONTRIBUTING.md` | Contributor workflow, branches, commits and PR conventions |
| `AGENTS.md` and `docs/agents/` | Project agent policy, shared workflows, reviewer checklists and coding guidance |
| `CLAUDE.md`, `.claude/`, `.agents/`, `.codex/` | Runtime loading, registration, invocation, permissions and attribution |
| `CONTEXT_MAP.md` and crate `CONTEXT.md` files | Domain vocabulary and context relationships |
| Workspace and crate ADRs | Decisions, alternatives and rationale |
| Rustdoc | Symbol, module and crate contracts under the [Rust documentation style](docs/agents/rust-docs-style.md) |

Update the owner and link to it from other documents. Keep historical v0.15.0 release material
accurate for that release.
