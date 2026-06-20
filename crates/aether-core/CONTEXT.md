# Core

The orchestration layer that exposes high-level entities — Sessions, Identities, Devices, Messages — and coordinates their lifecycle on top of the primitives in `aether-crypto`.

## Language

**Acknowledgment Artifact** (one per accepted inbound Message):
An encrypted Message with `PayloadKind::Acknowledgment` that proves the receiver accepted a prior
Message. Core returns it to the consumer for transport; Core never transmits it.
Avoid: receipt, delivery callback, network ack

**Caller-Owned Transport** (one host-selected route per send):
The host application's network and authentication boundary for sending encoded Messages,
Acknowledgment Artifacts, and Retry Instructions. Core produces or consumes opaque protocol bytes
and caller-supplied signing inputs, but it does not select transports, define transport headers,
perform network IO, or authenticate a transport envelope.
Avoid: Core network, transport session, library-owned routing

**Blocking** (one local verdict per Contact Identity):
An IK-keyed local suppression rule. Blocking is independent of Trust State and distinct from
sender-certificate revocation; it controls consumer-visible surfacing, not protocol acceptance. A
blocked Message's Acknowledgment Artifact follows the consumer-configured blocked-contact
acknowledgment policy: the default suppresses it, so a block is indistinguishable from an unreachable
recipient; an opt-in mode returns it while still hiding plaintext.
Avoid: revocation, distrust, remote blocklist

**Clock** (one per KeyStore):
The injected source of wall-clock time for caller-invoked prekey lifecycle checks, such as deciding
whether a superseded signed pre-key remains inside its grace window. `SystemClock` in production; a
virtual clock in tests makes lifecycle decisions reproducible.
Avoid: timer, time source

**Contact Identity** (one peer IK plus current DK):
The peer identity Core knows about for local contact, trust, and blocking state. The IK is
permanent and owns Trust State; the DK is current routing/discovery material and may rotate
without changing trust.
Avoid: account, profile, sender metadata

**Constrained Decryption Profile** (one release-gate budget):
The measured release profile for the real encrypted Message receive path under extension-class
execution constraints. The gate measures one decrypt operation at a time in an optimized test run,
with a 24 MiB tracked Rust heap allocation budget and a 250 ms wall-clock budget. It is release
evidence for the profiled path, not a guarantee for every host extension configuration or
compromised endpoint.
Avoid: production SLA, memory proof, endpoint guarantee

**Current State Snapshot** (one per Event Stream query):
A self-contained public view of the producer's current state, tagged with the last Event ID reflected by that view. Lagged Observers use it to replace their local view, then resume after the tagged Event ID without replaying already-reflected Events.
Avoid: cache, checkpoint

**Deduplication Digest** (one per received encrypted Message):
A keyed, truncated digest of the encoded sealed-sender frame bytes, computed before decryption and
used only to detect byte-identical receive retries for one local Identity. Decrypted Message IDs are
not part of the digest input.
Avoid: message hash, replay token

**Deduplication Set** (one per local Identity):
The bounded, ordered window of Deduplication Digests persisted as a Protocol State Blob. It is
loaded at receive start and advanced only after a unique Message decrypts and is accepted.
Avoid: cache, in-memory set

**Dead Session** (one terminal state per Session generation):
A Session persisted as unrecoverable after Core records an authenticated terminal condition. Core
does not attempt further decrypts under that Session and never surfaces plaintext from it; recovery
requires a fresh prekey bundle, a new X3DH exchange, and replacement Session state. Skipped-key cap
rejections from incoming ratchet headers are unauthenticated and do not create Dead Sessions.
Avoid: reset session, closed conversation, transient failure

**Device** (exactly one per Identity):
The app install that holds the private key material for an Identity. A new Device starts a new Identity unless the user restores an Identity backup onto it.
Avoid: client, installation, instance

**Discovery Key (DK)** (exactly one current per Identity):
A rotatable keypair — an Ed25519 signing key plus X25519 key-agreement key — signed by the Identity Key. Its X25519 key is the X3DH identity key for the current Epoch and its Ed25519 key signs the prekey bundle, so rotating it refreshes discovery without touching the Identity Key.
Avoid: prekey, ephemeral key

**Epoch** (one per Discovery Key generation):
The validity window of a Discovery Key and the prekey bundle bound to it. Rotating the Discovery Key advances the Epoch — a signed `u32` counter — and invalidates the prior Epoch's pre-keys. Epochs are monotonic only within one Device's storage lineage. Restoring an Identity backup preserves the backed-up Discovery Key and its Epoch, so use the signed `created_at` timestamp to compare freshness across restored lineages.
Avoid: window, generation

**Event** (many per Event Stream):
An immutable public value describing one committed state change. Each Event carries the complete public snapshot of what changed for its producer; future trust-change Events wait until trust state exists.
Avoid: notification, callback

**Event ID** (one per Event):
The monotonic identifier assigned when an Event is committed to an Event Stream. Event ID 0 is reserved for the initial Current State Snapshot; emitted Events start at 1 and form one total order per stream.
Avoid: sequence number, offset

**Event Stream** (one per library instance state surface):
The in-process, per-library-instance feed of committed public state changes. It serves Observers in one total order, but it is not a cross-instance delivery channel; changes from another library instance arrive through shared Protocol State Blobs.
Avoid: bus, broker, transport

**Hardening Limits** (one configured set per Protocol State Engine):
Consumer-selected ceilings that bound externally influenced Message, Sealed Sender Envelope,
Sender Certificate, Protocol State Blob, deduplication, and acknowledgment state work before
expensive cryptographic or state-mutating operations. Defaults target general mobile clients;
constrained hosts may lower them but cannot raise them beyond supported ceilings.
Avoid: rate limits, transport policy

**Identity** (exactly one Device):
A long-lived public-key persona held by a single Device, anchored by a permanent Identity Key and a rotatable Discovery Key. Identifies a participant across Sessions.
Avoid: user, account, profile

**Identity Key (IK)** (exactly one per Identity, permanent):
The permanent keypair — an Ed25519 signing key plus X25519 key-agreement key — that anchors an Identity. Safety numbers and sender certificates bind to it and its Ed25519 key signs the Discovery Key; it never rotates and takes no part in the X3DH key agreement.
Avoid: master key, root key

**Identity Backup** (one encrypted export of Identity material):
A passphrase-encrypted portable envelope containing the permanent Identity Key and current Discovery Key. Restoring it rewinds only Identity material; Protocol State Blobs, Sessions, and pending acknowledgments remain caller-owned and must be wiped or replaced before session recovery or re-handshake.
Avoid: account backup, protocol-state backup, session restore

**Identity Secret Blob** (one secure-storage entry per Identity):
The versioned local secure-storage payload that commits both permanent Identity Key secret halves together. It is the durable private form of the Identity Key and replaces the pre-release two-entry `identity/x25519` plus `identity/ed25519` encoding.
Avoid: key pair cache, backup blob

**Lag Signal** (one per Observer overrun):
An explicit Event Stream item reporting how many Events an Observer missed after its bounded buffer overflowed. Producers do not wait indefinitely for slow Observers; the Observer must recover through a Current State Snapshot.
Avoid: drop, overflow

**Library Instance** (one in-process Core object graph):
A live Core object graph in one process, such as one Event Stream and its producers. It is not a Device and does not define durable ownership; durable cross-instance coordination goes through the consumer-held Protocol State Blobs.
Avoid: Device, client

**Message** (many per Session):
A single sealed-sender frame exchanged within a Session. Before decrypt, a Message exposes only the
frame fields needed for recipient routing and authentication; MessageID, timestamp, payload kind,
ratchet header, sender identity material, and plaintext are recovered only after the frame and
ratchet ciphertext authenticate.
Avoid: payload, packet

**Message Transcript** (one per encrypted Message):
The canonical bytes signed by the sender IK and verified after decrypt before surfacing plaintext.
It binds the recipient IK, Session identifier, MessageID, timestamp, payload kind, and encrypted
payload input so a sealed signature cannot be transplanted to another recipient, Message, or
Session.
Avoid: associated data, transport metadata

**MessageID** (one per Message):
The UUID-shaped 16-byte identifier that addresses one Message within a Session.
Avoid: uuid, packet id

**Observer** (many per Event Stream):
A subscriber with its own bounded Event buffer and Observer Cursor. New Observers receive only Events committed after subscription.
Avoid: listener, subscriber

**Observer Cursor** (one per Observer):
The last Event ID reflected by that Observer. It advances when the Observer consumes an Event or resumes after a Current State Snapshot.
Avoid: bookmark, token

**Pending Acknowledgment** (one per unacknowledged outbound Message):
The persisted record of an outbound Message waiting for an Acknowledgment Artifact. It is stored in
the pending-acknowledgment Protocol State Blob with the original encoded Message bytes and retry
timestamps, then removed when a matching acknowledgment is processed.
Avoid: retry cache, outbox, in-memory pending state

**PreKey State** (one persisted lifecycle surface per local Identity):
The `prekey/*` secure-storage records managed by KeyStore: the current Discovery Key, current and
immediately superseded signed pre-key, and one-time pre-key pool for the current Epoch. Publication
uses caller-created material; rotating the Discovery Key advances the Epoch and immediately destroys
prior-Epoch signed and one-time prekey secrets. PreKey State is not a Protocol State Blob; malformed
prekey corpora exercise KeyStore secure-storage decoders.
Avoid: protocol state blob, in-memory prekey cache, automatic publication rotation

**Protocol State Blob** (many per Identity or Session):
An opaque byte value produced by Core and committed by the consumer's durable store. Core may load
and advance a Blob during one operation, but the consumer-held Blob is authoritative between
operations. Ratchet/session Blobs may also carry the expected peer Sender Identity Key used to
reject later sealed-sender swaps after decryption.
Avoid: cache, in-memory state, decoded state

**Protocol State Blob Version** (one per Protocol State Blob):
The Core-owned major/minor envelope version read before decoding a Blob's version-specific
payload. Only supported current-format envelopes and explicitly supported same-major body shapes are
accepted; unsupported envelope versions are faults, not reset or restore signals.
Avoid: schema version, ratchet version

**Protocol State Kind** (one per Protocol State Blob address):
The stable category for a Protocol State Blob address. Current blob decode surfaces are
ratchet/session state, deduplication set, pending acknowledgments, and contact state, including
trust and blocking. PreKey State remains KeyStore secure-storage state, and Sender Certificates are
validated caller inputs rather than persisted blob bodies.
Avoid: table, bucket, namespace

**Retry Instruction** (many per pending-acknowledgment query):
A consumer-visible instruction to retransmit a still-unacknowledged Message after the configured
retry window elapses. Core returns the instruction and updated pending-acknowledgment state; the
consumer decides whether and how to transmit.
Avoid: automatic retry, resend job, network task

**Retry Reference Time** (one per retry query):
The caller-supplied Unix timestamp in milliseconds used to evaluate retry windows. Retry checks do
not read the KeyStore Clock because retry scheduling is a consumer-visible transport boundary.
Avoid: Clock, timer, wall-clock read

**Safety Number** (one display value for two Identity Keys):
A deterministic grouped-decimal value derived from both parties' canonical IK encodings. Consumers
compare it out of band before recording a Verified Trust State.
Avoid: fingerprint, verification code, in-band confirmation

**Sealed Sender Envelope** (one per encrypted Message payload):
The encrypted/authenticated inner envelope that carries sender identity material alongside message
plaintext. It is decoded only after ciphertext authentication succeeds and, for established
Sessions, must match the peer sender identity bound to ratchet/session state.
Avoid: sender header, clear sender metadata

**Sealed Sender Frame** (one per Message or X3DH initial):
The transport-visible, versioned frame that wraps sealed-sender ciphertext. It carries the recipient
Discovery Key X25519 public key, an optional X3DH prekey reference, a per-message ephemeral public
key, and ciphertext; all sender and message metadata stays encrypted.
Avoid: transport envelope, sender-visible message

**Sealed Payload Padding** (one per sealed plaintext):
A 4-byte big-endian original length followed by plaintext and zero fill to a fixed Aether bucket.
Buckets are powers of two from 32 through 65536 bytes, and malformed zero fill is rejected after
decrypt.
Avoid: compression, random padding

**Sender Certificate** (one domain-signed binding for sender IK and DK):
A signed public statement from a trusted domain signing key binding a sender's IK, current DK,
signing-key identifier, and expiry. Validation is a caller-timed verdict over the current
trusted-key and revocation inputs. Sender Certificate malformed-input corpora exercise validation
inputs, not Protocol State Blob decoding.
Avoid: trust state, sender profile, discovery key signature

**Sender Identity Material** (one per Sealed Sender Envelope):
The sender's post-decryption identity material needed by later sender-certificate validation:
identity key, opaque sender certificate, and opaque sender signature. Certificate validation is a
future verdict over this material, not part of Message decode.
Avoid: sender IK, sender metadata

**Session** (between two Identities):
An ongoing encrypted channel between two Identities, advanced by the Double Ratchet, identified by `SessionID`.
Avoid: connection, conversation, chat

**Session-Unrecoverable Event** (at most one per Dead Session):
The public Event emitted when Core observes a persisted Dead Session marker that has not yet emitted
its event. Later Messages under the same dead Session return an unrecoverable outcome with no
plaintext and do not re-emit the Event; replacing the Session via X3DH allows a new Event if that
new Session later dies.
Avoid: warning, retry hint, decrypt error

**Trust State** (one local state per peer IK):
The consumer-recorded local trust verdict for a Contact Identity: Pending until accepted,
Unverified after acceptance, and Verified only after out-of-band Safety Number confirmation.
Avoid: certificate validity, blocking, remote reputation

## Example

**Dev:** If a user re-installs the app, do they keep their Identity?

**Domain expert:** No — Identity is bound to private key material held on the Device. A fresh installation starts a new Identity unless the user restores from an Identity backup, which re-creates the Identity on the new installation.

**Dev:** Then why distinguish Identity from Device at all in the MVP?

**Domain expert:** Identity is the addressing unit — Sessions pair two Identities and sender certificates bind to Identity keys. Device is the persistence unit — it owns the private material in platform secure storage. Even at one-to-one, separating them keeps Session establishment, sender certificates, and Identity backup independent of where the bytes physically live.

## Flagged Ambiguities

**Clock time** (maintenance) vs **reference time** (validation): Rotation reads "now" from an injected `Clock` because it is library-initiated maintenance. Validation verdicts (e.g., sender-certificate expiry, [ADR 0002](../../docs/adr/0002-sender-certificate-validation.md)) instead take a caller-supplied reference timestamp, so the verdict stays a reproducible pure function of its inputs. Reserve the `Clock` for maintenance scheduling; do not route validation through it.

**Session** (cryptographic) vs **session** (app login state): The cryptographic Session is the Double Ratchet state between two Identities; the lowercase host-app "session" is the user's logged-in state. Reserve capitalized `Session` for the cryptographic concept.
