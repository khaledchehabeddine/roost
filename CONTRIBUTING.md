# Contributing to Hermes

## Branches

Format: `<type>/<short-description>`

```
enhancement/ble-peer-discovery
bug/empty-payload-crash
chore/update-dependencies
```

## Commits

Format: `<type>: <summary>\n\n- <what changed>\n- <what changed>`

Types: `feat` `fix` `chore` `docs` `ci` `refactor` `test`

```
feat: add Curve25519 key generation to hermes-crypto

- Add `generate_keypair()` returning `(PublicKey, SecretKey)`
- Add `KeyPair` struct to hermes-crypto public API
- Add unit tests for key generation and round-trip encoding
```

## Pull Requests

- All CI workflows must pass
- See `.github/PULL_REQUEST_TEMPLATE.md` for the required PR structure

## Error Handling

- All error paths return `Result` — `unwrap()`, `expect()`, and `panic!()` are banned outside of tests
- Each crate defines its own domain error type
- Errors never cross the UniFFI boundary — only domain errors defined in the UniFFI Definition Language (UDL) propagate to the platform layer
- Error `Display` implementations should be detailed and developer-facing

## Crate-Specific Rules

Each crate's purpose is documented in its `lib.rs` module docs (`//!`). Workspace-wide crate dependency rules live in `CLAUDE.md`.
