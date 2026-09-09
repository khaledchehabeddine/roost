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
The model validates the entire write set before applying any blob or outbox effect. Stale absent
and digest conditions reject without partial writes. Per-identity host serialization remains a
consumer obligation; the test helper does not add a second revision protocol.

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
| ProtocolStateStore callback and binding-built conditions | Core host-store tests; targeted foreign storage and prepared-operation checks | Hosts implement their own database transaction |
| Rust Event Stream, observers, cursors, and stream scenarios | Two-instance committed contact queries; typed changes; durable dead-session recovery | UI observation may coalesce changes; no Rust event delivery guarantee |
| Observer-based two-instance helpers | Protocol-state ordering, acknowledgment, retry and replay tests; host-store, rollback and recovery tests | No repeated event ordering scenario |
| Unbound messaging and key-only current-prekey lookup | Bound X3DH; distinct binary Message/acknowledgment binding and tamper tests; retained prekey selection and prepared acceptance tests | Hosts must preserve canonical routing bytes |
| Optional receive fields and reason-string classification | Rich enum conversion and native binding calls; typed error tests | Log wording is not a caller contract |
| Alternate session readers and contact v1 fallback | Canonical current blob fixtures; corruption, bounds, trailing-data and recovery tests | No obsolete prerelease state migration |

## Evidence for #269 cleanup

| Removed or simplified | Remaining evidence | Accepted gap |
| --- | --- | --- |
| Broad Swift/Kotlin protocol scenarios, replay exports and feature dependencies, inbox/signing/key-binding scenarios | Core protocol, contact, prekey and inbox tests; Crypto known-answer and handshake tests; Client adapter tests; targeted native evidence, fresh-signature verification and storage checks | No complete protocol run through each generated language |
| Binding-surface grep and method coverage matrix | Rust UniFFI declarations, generated compilation, targeted FFI checks, API review | Missing wrappers may be found during client validation |
| Full package protocol scenarios, copied fixtures, Gradle source staging, duplicated broken iOS package setup | Package installation and real binding calls; artifact integrity checks; manual full consumer validation for v0.16.0 and relevant changes | Full consumer failures may be detected later; release-specific tooling cleanup remains in #270 |
| Host revision tokens, repeated alternating-instance scenarios, repeated corruption/version setup, leaked and reverse-searched fixture keys | Core absent/digest conditions and atomic outbox checks; serialized interleaving, rollback, recovery, corruption, and all previous envelope-version rejection cases | No production contract removed; host database isolation remains consumer-owned |
| Copied native evidence literals and fixture-printing helpers | Canonical Rust JSON fixtures; active exact-byte evidence production and sealed-session replay tests; native signature verification | Future fixture updates require deliberate regeneration from the retained tests |
| Text fuzz-input parsers, repeated outer-frame parsing, AAD and digest probes, redundant empty-padding and oversized-Message seeds, certificate policy seed permutations | Raw decoder fuzz targets; Crypto sealed-frame tamper tests; Core deduplication and Message-size tests; Protocol padding, signature-length rejection and certificate fixtures | Fuzzing fixes certificate policy and signature length, and omits cryptographic calls without assertions |

The shared Rust setup now owns its signing and discovery keys. FFI recovery checks inject lost
foreign storage replies after a write and reopen the same storage before resuming. Line coverage
is report-only. Current canonical fixture bytes and v0.15.0 published records are unchanged.

The certificate generator remains to re-sign related cases after a certificate-format change. The
handshake generator preserves the transcript seed order, avoiding the manual fixture repairs
recorded in #171 and #174. Neither contributes to the normal test count.
