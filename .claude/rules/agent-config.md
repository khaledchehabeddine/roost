---
paths:
  - ".agents/**"
  - ".claude/**"
  - ".codex/**"
  - "AGENTS.md"
  - "CLAUDE.md"
---

# Agent Config Rules

- When updating one agent's customization, mirror the behavioral change in the other agent's equivalent (Claude ↔ Codex). Stylistic patterns differ between agents per their respective documentation — do not harmonize style across agents
- Follow the structure and style from existing peer customizations of the same type within the same agent — applies to root config files, rules, agents, and skills
