# Security

## Status

Roost has had no independent security audit. Its tests show that the code does what its authors intended. They don't show that the design is secure. Don't use Roost to protect real conversations.

## Known Limits

The [README](README.md#limits) lists what Roost doesn't provide, such as post-quantum protection and group messaging.

## Supported Versions

Only the latest release receives fixes.

## Reporting a Vulnerability

Report a vulnerability in private, through "Report a vulnerability" on the repository's Security tab. Don't open a public issue for it.

Include:

- The Roost version.
- What an attacker can do.
- The steps to reproduce it.

## Scope

In scope:

- The Rust crates in this repository.
- The Swift and Kotlin packages built from them.

Out of scope:

- An app's storage adapter, database, and networking.
- Any relay.
- The limits the README lists.
