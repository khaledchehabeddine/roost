# Prepared KeyStore Operations

No transaction covers both SecureStorage and the app's database, and staged secrets must stay in SecureStorage. So Core stages every key change inside SecureStorage as a Prepared KeyStore Operation, which the app finalizes after its own commit, or aborts once it knows that commit failed. At startup, Core finishes or aborts any operation a crash left open.

## Alternatives

- Change keys at once and repair app state later: after a crash, Core couldn't tell a lost app update from a completed key change.
- Add a transaction to SecureStorage that also commits app state: Core doesn't own the app's database, and a callback can't make both stores commit together.
