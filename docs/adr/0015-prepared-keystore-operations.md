# Prepared KeyStore Operations

No transaction covers both SecureStorage and the app's database, and staged secrets must stay in SecureStorage. So Core stages every key change inside SecureStorage as a Prepared KeyStore Operation, which travels in the state changes it belongs to, such as those of a first Message that uses a one-time prekey, and the app reserves it before its own commit and finalizes it after, or aborts it once it knows that commit failed. Reserving checks that SecureStorage hasn't changed since preparation, and an operation a crash leaves open stays recoverable until the app finalizes or aborts it.

## Alternatives

- Change keys at once and repair app state later: after a crash, Core couldn't tell a lost app update from a completed key change.
- Add a transaction to SecureStorage that also commits app state: Core doesn't own the app's database, and a callback can't make both stores commit together.
- Abort an operation when the app releases it: a release says nothing about whether the app's commit happened.
- Accept a first Message that uses a one-time prekey in its own call: the app would have to tell first Messages apart before decrypting them.
