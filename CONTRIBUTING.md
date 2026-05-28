# Contributing

## Branches

Format: `<type>/<short-description>`

Types match the repo's GitHub labels — run `gh label list` to see the current set.

### Example

```
feature/signed-prekey-rotation
```

## Commits

Format: `<type>: <summary>\n- <what changed>\n- <what changed>`

Types: `feat` `fix` `chore` `docs` `ci` `refactor` `test`

If an AI agent contributed, append a `Co-Authored-By:` trailer naming the agent.

### Example

```
feat: add Curve25519 key generation to aether-crypto
- Add `generate_key_pair()` returning `(PublicKey, SecretKey)`
- Add `KeyPair` struct to aether-crypto public API
- Add unit tests for key generation and round-trip encoding

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

## Pull Requests

- All CI workflows must pass
- See [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) for the required PR structure

## Decision Records

Architectural decisions live as ADRs:

- `docs/adr/` — cross-crate / workspace-wide decisions
- `crates/<crate>/docs/adr/` — crate-specific decisions

Filename: `NNNN-slug.md`, sequential within each folder. Format: see [`docs/adr/TEMPLATE.md`](docs/adr/TEMPLATE.md).

Open an ADR when a change is all three of:

1. **Hard to reverse** — the cost of changing your mind later is meaningful
2. **Surprising without context** — a future reader will wonder "why did they do it this way?"
3. **The result of a real trade-off** — there were genuine alternatives, and you picked one for specific reasons

Trivial fixes and reversible choices don't need one.

In Claude Code, `/design-review-with-docs` grills a plan and offers ADRs that pass the gate. ADRs may also be written by hand using the template above.
