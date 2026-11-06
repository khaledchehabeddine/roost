# Prepared KeyStore Operations

No transaction covers both SecureStorage and the app's database, so Core stages every key change inside SecureStorage, where its secrets stay, as a prepared KeyStore operation. The app reserves it before its own commit and finalizes it after, or aborts it once it knows that commit failed. Reserving checks that SecureStorage hasn't changed since preparation, and an operation a crash leaves open survives until the app finalizes or aborts it.

## Alternatives

- Change keys at once and repair app state later: after a crash, Core couldn't tell a lost app update from a completed key change.
- Add a transaction to SecureStorage that also commits app state: Core doesn't own the app's database, and a callback can't make both stores commit together.
- Abort an operation when the app releases it: a release says nothing about whether the app's commit happened.
