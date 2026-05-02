# Contributing

## Branches

Format: `<type>/<short-description>`

Types match the repo's GitHub labels — run `gh label list` to see the current set.

### Example

```
feature/ble-peer-discovery
```

## Commits

Format: `<type>: <summary>\n- <what changed>\n- <what changed>`

Types: `feat` `fix` `chore` `docs` `ci` `refactor` `test`

If an AI agent contributed, append a `Co-Authored-By:` trailer naming the agent.

### Example

```
feat: add Curve25519 key generation to hermes-crypto
- Add `generate_keypair()` returning `(PublicKey, SecretKey)`
- Add `KeyPair` struct to hermes-crypto public API
- Add unit tests for key generation and round-trip encoding

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

## Pull Requests

- All CI workflows must pass
- See [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) for the required PR structure

## Worktrees

For parallel sessions in isolation. `commit-push` creates the conformant branch at commit time regardless of how the worktree was spawned, so the conventions above are unchanged.

- **Claude Code:** `claude --worktree <name>`
- **Codex App:** select "Worktree" in the thread composer
- **Codex CLI:** `git worktree add --detach <path> origin/HEAD && cd <path> && codex`
