# Contributing

## Branches

Format: `<type>/<short-description>`

Types match the repo's GitHub labels — run `gh label list` to see the current set.

### Example

```
feature/ble-peer-discovery
```

## Commits

Format: `<type>: <summary>\n\n- <what changed>\n- <what changed>`

Types: `feat` `fix` `chore` `docs` `ci` `refactor` `test`

### Example

```
feat: add Curve25519 key generation to hermes-crypto

- Add `generate_keypair()` returning `(PublicKey, SecretKey)`
- Add `KeyPair` struct to hermes-crypto public API
- Add unit tests for key generation and round-trip encoding
```

## Pull Requests

- All CI workflows must pass
- See [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) for the required PR structure
