# Prepared KeyStore Operations

No transaction covers both SecureStorage and the app's database, so Roost stages every key change in SecureStorage, where its secrets stay, as a prepared KeyStore operation. The app reserves it before its own commit, then finalizes it after that commit or aborts it once it knows the commit failed. An operation that a crash leaves open survives until the app finalizes or aborts it.

## Alternatives

- Change keys at once and repair app state later: after a crash, Roost couldn't tell a lost app update from a completed key change.
- Abort an operation when the app releases it: a release says nothing about whether the app's commit happened.
