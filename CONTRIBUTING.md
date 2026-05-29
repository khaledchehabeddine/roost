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
