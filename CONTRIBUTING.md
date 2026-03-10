# Contributing to Hermes

## Commits

Format: `<type>: <summary>\n\n- <what changed>\n- <what changed>`

Types: `feat` `fix` `chore` `docs` `ci` `refactor` `test`

```
feat: add Curve25519 key generation to hermes-crypto

- Add `generate_keypair()` returning `(PublicKey, SecretKey)`
- Add `KeyPair` struct to hermes-crypto public API
- Add unit tests for key generation and round-trip encoding
```

## Branches

Format: `<type>/<short-description>`

```
feat/ble-peer-discovery
fix/empty-payload-crash
chore/update-dependencies
```

## Pull Requests

- All CI workflows must pass
- Reference a decision document (`docs/decisions/`) if the PR introduces or changes an architectural choice

## Error Handling

- All error paths return `Result` — `unwrap()`, `expect()`, and `panic!()` are banned outside of tests
- Each crate defines its own domain error type
- Errors never cross the UniFFI boundary — only domain errors defined in the UniFFI Definition Language (UDL) propagate to the platform layer

## Crate-Specific Rules

Each crate defines its own constraints in `crates/<name>/README.md`. Read it before contributing to that crate.