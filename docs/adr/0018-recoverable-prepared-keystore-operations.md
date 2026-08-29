# Coordinate KeyStore Mutations with Recoverable Prepared Operations

**Status:** Accepted

Every production KeyStore mutation returns a Prepared KeyStore Operation instead of changing
authoritative key entries eagerly. Core stages secret mutations in a bounded, Core-owned journal
inside SecureStorage and returns a stable identifier, SecureStorage preconditions, and provisional
output; the host asks Core to commit, atomically persists related Protocol State Blob updates and
the identifier in its own transaction, then finalizes, aborting only after proving that transaction
did not commit. Startup reconciliation is required because no atomic transaction spans platform
SecureStorage and the host database, while staged secrets must not cross into host storage.

## Considered Options

- Keep eager SecureStorage mutations and repair host state afterward. Rejected because a crash
  cannot distinguish an unapplied host update from an already-published key mutation.
- Extend SecureStorage with a transaction that also commits Protocol State Blobs. Rejected because
  Core does not own the host database and a foreign storage callback cannot make both systems one
  atomic resource.
- Require SecureStorage compare-and-exchange for the journal. Rejected because platform secret
  stores do not expose one portable conditional-update primitive, while AE-STA-06 already requires
  one host-owned per-identity serializer for mutations; that serializer spans this whole lifecycle.
- Store staged secret mutations with the host operation record. Rejected because it moves private
  key material outside the platform secret-store boundary.

## Consequences

- A committed or finalizing operation blocks ordinary KeyStore work until recovery finalizes or
  aborts it. One host-owned per-identity actor or lock must serialize the entire prepare through
  finalize, abort, or ambiguous-commit reconciliation lifecycle across every KeyStore instance and
  process sharing that identity namespace; separately constructed instances do not share Core's
  in-process mutex.
- Finalization records progress around each idempotent SecureStorage mutation, so retry can repeat a
  mutation after an ambiguous storage failure without rolling secret state backward.
- SecureStorage implementations must make each entry update durable and non-tearing; Core can
  recover cross-entry progress, but it cannot repair a partially written journal entry.
- Prepared operations and terminal tombstones are bounded; sufficiently old terminal identifiers
  may eventually return `NotFound` instead of an idempotent terminal status.
- Even a no-op provisional result owns a journal record and must be finalized or aborted.
