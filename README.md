# Hermes

Cross-platform networking engine for encrypted peer-to-peer messaging over Bluetooth Low Energy (BLE). All cryptographic and transport logic lives here, exposed to Swift and Kotlin via UniFFI.

## Setup

```bash
git clone git@github.com:RelayNet/hermes.git
cd hermes
rustup show
cargo build --workspace
```

## Commands

| Command                        | What it does              |
|--------------------------------|---------------------------|
| `cargo build`                  | Build all crates          |
| `cargo test`                   | Run all tests             |
| `cargo clippy -- -D warnings`  | Lint — matches CI         |
| `cargo fmt --check`            | Format check — matches CI |

## Docs

- `docs/decisions/` — architectural decisions and reasoning
- `CONTRIBUTING.md` — commit format, branch naming, project-wide rules
- `crates/<n>/README.md` — crate-specific constraints
