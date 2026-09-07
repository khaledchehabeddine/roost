# Protocol State Invariant Tests

Issue 114 coverage uses bounded generated traces plus deterministic negative scenarios. These tests
verify the public contract without treating ADR or context documents as executable code.

## Generated Trace Model

Generated traces produce short sequences of encrypted Messages over one Session. The model records
the expected plaintext for each Message, delivers Messages in generated order, and asserts each
accepted Message decrypts exactly once. Replays run after the receiver commits advanced blobs, so
byte-identical retries must hit the Deduplication Set before Ratchet state is loaded or mutated.

The crypto-only trace model exercises the Ratchet directly. It covers bidirectional sends,
out-of-order delivery inside skipped-key bounds, replay rejection after state advancement, and
continued use after the final generated step.

## Serialized Host-Store Model

Core tests model a host store that owns Protocol State Blobs. Each operation reads a snapshot,
returns updates with Core-computed absent or digest conditions, and commits them atomically.
The model also uses a host transaction token to serialize reads across the complete identity. The model rejects stale commits and
conflicting writes, proving Library Instances do not reuse forked authoritative in-memory state
across operations.

## Rollback And Corruption Model

Rollback tests commit only complete update sets. If a simulated host commit is interrupted, the
last fully committed Message, advanced Protocol State Blob, and Deduplication Set remain the only
visible state. Corruption tests replace committed blobs with malformed bytes and assert Core
surfaces decode faults rather than silently reinitializing state.

## Session Recovery Model

Dead Session tests use the existing unrecoverable-session marker. The first observation returns one
Session-Unrecoverable Event with a conditional update that records the recovery signal. The host
commits both before scheduling recovery. Later Messages
under the same Dead Session return the same unrecoverable outcome without duplicate recovery signals or
automatic X3DH churn. A new Session initializer cannot overwrite a live or dead Session. Recovery
conditionally wipes the old Session, then installs a fresh handshake through an absent-condition
host commit; the test keeps the same host stores throughout.

Prepared blocking also exercises both uncertain host-commit outcomes. A single durable host record
contains the contact blob and operation identifier. After the commit response is lost, recovery
reopens that record and the SecureStorage journal, finalizing an applied transaction or aborting an
unapplied one. The contact state and discovery-key epoch remain consistent.

## Evidence for #267 removals

| Removed item | Remaining evidence | Accepted gap |
| --- | --- | --- |
| ProtocolStateStore callback and binding-built conditions | Core host-store tests; Swift/Kotlin host snapshot and stale-commit checks | Hosts implement their own database transaction |
| Rust Event Stream, observers, cursors, and stream scenarios | Two-instance committed contact queries; typed changes; durable dead-session recovery | UI observation may coalesce changes; no Rust event delivery guarantee |
| Observer-based two-instance helpers | Protocol-state ordering, acknowledgment, retry and replay tests; host-store, rollback and recovery tests | No repeated event ordering scenario |
| Unbound messaging and key-only current-prekey lookup | Bound X3DH; distinct binary Message/acknowledgment binding and tamper tests; retained prekey selection and prepared acceptance tests | Hosts must preserve canonical routing bytes |
| Optional receive fields and reason-string classification | Rich enum conversion and native binding calls; typed error tests | Log wording is not a caller contract |
| Alternate session readers and contact v1 fallback | Canonical current blob fixtures; corruption, bounds, trailing-data and recovery tests | No obsolete prerelease state migration |

Broad generated-language and release-gate cleanup remains in #269 and later tickets. This change
ports their affected callers and removes only the deleted callback and observation paths.
