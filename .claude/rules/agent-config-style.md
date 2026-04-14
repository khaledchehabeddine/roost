---
paths:
  - ".agents/**"
  - ".claude/**"
  - ".codex/**"
  - "AGENTS.md"
  - "CLAUDE.md"
---

# Agent Config Style

When creating or modifying agents, skills, rules, or root config files (`AGENTS.md`, `CLAUDE.md`):

- State principles only — no inline code examples, worked scenarios, or "for instance" blocks that age
- Every line must be actionable — if it restates what the tool already enforces or what the code already shows, delete it
- Keep Claude and Codex configs in sync — changes to one must be mirrored to the other
- Leverage each tool's native features:
  - Claude: path-scoped `.claude/rules/`, `!` context injection, `allowed-tools`, `disable-model-invocation`
  - Codex: `AGENTS.md` inline guidelines, `.codex/agents/` TOML definitions
- Don't duplicate rules across layers — if a rule lives in a path-scoped file, don't repeat it in the root config
