# Core

Identity, messaging, contact, and storage coordination over Crypto and Protocol.

## Language

**Acknowledgment Artifact** (one per accepted inbound Message):
An encrypted Message with `PayloadKind::Acknowledgment` that proves the receiver accepted a prior
Message. Core returns it to the consumer for transport; Core never transmits it.
Avoid: receipt, delivery callback, network ack

**Caller-Owned Transport** (one host-selected path per send):
The host application's networking, authentication, and retry boundary. Roost returns opaque
messages and authenticates the exact Transport Binding the host supplies; the host owns its schema,
authorization policy, and delivery.
Avoid: Core network, transport session, library-owned routing

**Transport Binding** (one caller-supplied value per bound Message operation):
Non-empty public bytes, at most 1 KiB, authenticated as sealed-frame associated data and included
in pre-decryption deduplication. The host owns the encoding and retains the exact bytes for receive
and retransmission; Roost neither interprets nor stores them.
Avoid: transport envelope, route record, delivery capability

**Blocking** (one local verdict per Contact Identity):
IK-keyed suppression of plaintext, independent of Trust State and certificate revocation. Protocol
acceptance still advances receive state; Unreachable suppresses acknowledgments, while SilentReceipt
returns them and reveals delivery.
Avoid: revocation, distrust, remote blocklist

**Contact Identity** (one peer IK plus current DK):
The peer identity Core knows about for local contact, trust, and blocking state. The IK is
permanent and owns Trust State; the DK is current routing/discovery material and may rotate
without changing trust.
Avoid: account, profile, sender metadata

**Deduplication Digest** (one per received encrypted Message):
A keyed, truncated digest of the encoded sealed-sender frame and the exact
Transport Binding bytes. It is computed before decryption and used only to detect identical receive
retries for one local Identity. Decrypted Message IDs are not part of the digest input.
Avoid: message hash, replay token

**Deduplication Set** (one per local Identity):
The bounded, ordered window of Deduplication Digests persisted as a Protocol State Blob. It is
loaded at receive start and advanced only after a unique Message decrypts and is accepted.
Avoid: cache, in-memory set

**Dead Session** (one terminal state per Session generation):
A Session persisted as unrecoverable after an authenticated terminal condition; recovery requires
a fresh prekey bundle and X3DH exchange. Unauthenticated skipped-key cap pressure rejects a
Message without making the Session dead.
Avoid: reset session, closed conversation, transient failure

**Device** (exactly one per Identity):
The app install that holds the private key material for an Identity. A new Device starts a new Identity unless the user restores an Identity backup onto it.
Avoid: client, installation, instance

**Discovery Key (DK)** (exactly one current per Identity):
A rotatable keypair — an Ed25519 signing key plus X25519 key-agreement key — signed by the Identity Key. Its X25519 key is the X3DH identity key for the current Epoch and its Ed25519 key signs the prekey bundle, so rotating it refreshes discovery without touching the Identity Key.
Avoid: prekey, ephemeral key

**Epoch** (one per Discovery Key generation):
The Discovery Key's signed generation counter, also called Inbox Generation, starting at 1 for a
new Identity. It orders one storage lineage; peers compare signed `(created_at, epoch)` pairs to
order keys across restored lineages.
Avoid: independent inbox counter

**Event** (one optional change value per operation):
An immutable public value describing a state change. It remains provisional until the host commits
the associated updates. Hosts retain required recovery effects and observe their committed stores.
Avoid: notification, callback

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

**Library Instance** (one in-process Core object graph):
A live Core object graph in one process. It is not a Device and does not define durable ownership; durable cross-instance coordination goes through the consumer-held Protocol State Blobs.
Avoid: Device, client

**Message** (many per Session):
A single sealed-sender frame exchanged within a Session. Before decrypt, a Message exposes only the
frame fields needed for recipient routing and authentication; MessageID, timestamp, payload kind,
ratchet header, sender identity material, and plaintext are recovered only after the frame and
ratchet ciphertext authenticate.
Avoid: payload, packet

**MessageID** (one per Message):
The UUID-shaped 16-byte identifier that addresses one Message within a Session.
Avoid: uuid, packet id

**Pending Acknowledgment** (one per unacknowledged outbound Message):
The persisted record of an outbound Message waiting for an Acknowledgment Artifact. It is stored in
the pending-acknowledgment Protocol State Blob with the original encoded Message bytes and retry
timestamps, then removed when a matching acknowledgment is processed.
Avoid: retry cache, outbox, in-memory pending state

**Prepared KeyStore Operation** (one per prepared KeyStore mutation request):
A recoverable intent containing a stable identifier, SecureStorage preconditions, staged secrets,
and provisional output. The host serializes prepare, commit, its atomic state transaction, and
finalize or abort across all instances and processes sharing the identity namespace.
Avoid: database transaction, eager key mutation, deferred write

**PreKey State** (one persisted lifecycle surface per local Identity):
KeyStore-owned secure-storage records for the current Discovery Key and its signed and one-time
prekeys. Unlike Protocol State Blobs, these secrets follow the prepared-operation lifecycle;
backup restore blocks their use until inbox rotation.
Avoid: protocol state blob, in-memory prekey cache, automatic publication rotation

**PreKey Identifier** (one stable `u64` per prekey within one Epoch):
An unsigned 64-bit lookup value allocated by Core within one Epoch and prekey kind. Signed- and
one-time-prekey sequences are independent, so an identifier is not globally unique or automatically
authenticated transport metadata.
Avoid: database row ID, key fingerprint, global sequence

**PreKey Selection** (one caller-supplied value per bound X3DH receive):
The caller-selected signed- and optional one-time-prekey identifiers for an inbound X3DH initial.
Core uses them to locate retained secrets and match the authenticated Message, independently of
the host's Transport Binding encoding.
Avoid: route, prekey reference, transport metadata

**Protocol State Blob** (many per Identity or Session):
Opaque, secret-bearing bytes produced by Core and held authoritatively in the host's durable
store between operations. Core returns conditional updates that the host commits atomically
with their message, acknowledgment, or recovery effects.
Avoid: cache, in-memory state, decoded state

**Protocol State Blob Version** (one per Protocol State Blob):
The Core-owned major/minor envelope selecting a blob's body decoder. Unsupported or malformed
versions fault; they do not imply permission to reset or restore state.
Avoid: schema version, ratchet version

**Protocol State Kind** (one per Protocol State Blob address):
The category in a blob address, defined by the
[public enum](src/protocol_state.rs). It includes peer inbox authorization containing a bearer
capability and local inbox-distribution bookkeeping; PreKey State belongs to SecureStorage.
Avoid: table, bucket, namespace

**Retry Instruction** (many per pending-acknowledgment query):
A consumer-visible instruction to retransmit a still-unacknowledged Message after the configured
retry window elapses. Core returns the instruction and updated pending-acknowledgment state; the
consumer decides whether and how to transmit.
Avoid: automatic retry, resend job, network task

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
key, and ciphertext; all sender and message metadata stays encrypted. Bound operations also
authenticate caller-supplied Transport Binding bytes without encoding them into the frame.
Avoid: transport envelope, sender-visible message

**Sender Identity Material** (one per Sealed Sender Envelope):
The sender key, certificate, and signature recovered from a Sealed Sender Envelope. Established
message receive validates certificate trust; X3DH acceptance proves key possession and returns
certificate material for the caller to validate separately.
Avoid: sender IK, sender metadata

**Session** (between two Identities):
An encrypted channel between two Identities, advanced by the Double Ratchet and identified by
`SessionID`. Capitalized Session means this protocol state, not an app login.
Avoid: connection, conversation, chat

**Session-Unrecoverable Event** (at most one per Dead Session):
A recovery signal returned at most once for a persisted Dead Session. The host must commit it with
the state marking it reported; replacing the Session permits a new signal for a later failure.
Avoid: warning, retry hint, decrypt error

**Trust State** (one local state per peer IK):
The consumer-recorded local trust verdict for a Contact Identity: Pending until accepted,
Unverified after acceptance, and Verified only after out-of-band Safety Number confirmation.
Avoid: certificate validity, blocking, remote reputation
