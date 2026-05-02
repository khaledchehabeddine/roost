---
paths:
  - ".agents/**"
  - ".claude/**"
  - ".codex/**"
  - "AGENTS.md"
  - "CLAUDE.md"
---

# Agent Config Rules

- Customizations that benefit collaborators on this project must live in project scope (`.agents/`, `.claude/`, `.codex/`, `AGENTS.md`, `CLAUDE.md`)
- Customization may live in user scope only if it neither shapes the project's workflow nor improves agent quality for collaborators
- When updating one agent's customization, mirror the behavioral change in the other agent's equivalent (Claude ↔ Codex). Stylistic patterns differ between agents per their respective documentation
- Follow the structure and style from existing peer customizations of the same type within the same agent
- Pattern-skill body items follow a cohesive ordering (workflow, scope, criticality, frequency, etc.)
- Pattern-skill descriptions list the same items as the body, in the same order
- Skills that set `paths:` must not restate the location filter in their description — `paths:` gates autoloading
- Customization descriptions don't explicitly reference the project name (Hermes). Literal paths like `crates/hermes-uniffi` are exceptions
