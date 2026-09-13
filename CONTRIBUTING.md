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

Use the existing checks in [CI](docs/ci.md) for the affected behavior before submitting.
Documentation and configuration changes need only the relevant content and file-format validation
locally; required CI still applies. Agent contributions follow [AGENTS.md](AGENTS.md).

## Issues

Issues and PRs use GitHub at `github.com/RelayNet/roost`. Build issue bodies from the matching
[issue form](.github/ISSUE_TEMPLATE/) and use its required fields and declared options.
Reuse supplied labels and milestones; optional tracking metadata is not a prerequisite to filing.

## Documentation ownership

| Document | Owns |
| --- | --- |
| `README.md` | Orientation, setup, crate graph and documentation links |
| `CONTRIBUTING.md` | Contributor workflow, branches, commits and PR conventions |
| `AGENTS.md` | Repository-wide standards for agent contributions |
| `.agents/instructions/` | Shared customization bodies, grouped by type |
| `CLAUDE.md`, `.agents/skills/`, `.claude/`, `.codex/` | Runtime loading, invocation, permissions and attribution |
| `CONTEXT_MAP.md` and crate `CONTEXT.md` files | Domain vocabulary and context relationships |
| Workspace and crate ADRs | Decisions, alternatives and rationale |
| Rustdoc | Symbol, module and crate contracts under the [Rust documentation style](.agents/instructions/skills/rust/references/documentation.md) |

Update the owner and link to it from other documents. Keep historical v0.15.0 release material
accurate for that release.
