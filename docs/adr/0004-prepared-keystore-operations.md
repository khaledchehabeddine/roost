# Prepared KeyStore Operations

No transaction covers both SecureStorage and the app's database, so Roost stages each key change in SecureStorage as a prepared KeyStore operation. The app reserves it before its own commit, then finalizes it after or aborts it once it knows the commit failed. The operation survives a crash until the app does either.

## Alternatives

- Change keys at once and repair app state later: after a crash, Roost couldn't tell a lost app update from a completed key change.
- Abort the operation when the app releases it: a release says nothing about whether the commit happened.
