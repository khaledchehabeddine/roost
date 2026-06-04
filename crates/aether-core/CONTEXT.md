# Core

The orchestration layer that exposes high-level entities — Sessions, Identities, Devices, Messages — and coordinates their lifecycle on top of the primitives in `aether-crypto`.

## Language

**Clock** (one per KeyStore):
The injected source of wall-clock time for autonomous maintenance scheduling — currently signed-pre-key rotation deciding when a stored key is stale. `SystemClock` in production; a virtual clock in tests makes rotation reproducible.
Avoid: timer, time source

**Device** (exactly one per Identity):
The app install that holds the private key material for an Identity. A new Device starts a new Identity unless the user restores an Identity backup onto it.
Avoid: client, installation, instance

**Discovery Key (DK)** (exactly one current per Identity):
A rotatable keypair — an Ed25519 signing key plus X25519 key-agreement key — signed by the Identity Key. Its X25519 key is the X3DH identity key for the current Epoch and its Ed25519 key signs the prekey bundle, so rotating it refreshes discovery without touching the Identity Key.
Avoid: prekey, ephemeral key

**Epoch** (one per Discovery Key generation):
The validity window of a Discovery Key and the prekey bundle bound to it. Rotating the Discovery Key advances the Epoch — a signed `u32` counter — and invalidates the prior Epoch's pre-keys. Epochs are monotonic only within one Device's storage lineage. Restoring an Identity backup creates a new Discovery Key at Epoch 0, so use the signed `created_at` timestamp to compare freshness across restored lineages.
Avoid: window, generation

**Identity** (exactly one Device):
A long-lived public-key persona held by a single Device, anchored by a permanent Identity Key and a rotatable Discovery Key. Identifies a participant across Sessions.
Avoid: user, account, profile

**Identity Key (IK)** (exactly one per Identity, permanent):
The permanent keypair — an Ed25519 signing key plus X25519 key-agreement key — that anchors an Identity. Safety numbers and sender certificates bind to it and its Ed25519 key signs the Discovery Key; it never rotates and takes no part in the X3DH key agreement.
Avoid: master key, root key

**Message** (many per Session):
A single encoded packet exchanged within a Session, addressed by `MessageID`. A Message may carry encrypted text, acknowledgment, key-exchange, or Ratchet-header bytes; those inner bytes are payload fields, not standalone domain Messages.
Avoid: payload, packet

**MessageID** (one per Message):
The UUID-shaped 16-byte identifier that addresses one Message within a Session.
Avoid: uuid, packet id

**Protocol State Blob** (many per Identity or Session):
An opaque byte value produced by Core and committed by the consumer's durable store. Core may load
and advance a Blob during one operation, but the consumer-held Blob is authoritative between
operations.
Avoid: cache, in-memory state, decoded state

**Protocol State Blob Version** (one per Protocol State Blob):
The Core-owned major/minor envelope version read before decoding a Blob's version-specific
payload. Supported older versions migrate through explicit fixtures only; unknown versions are
faults, not reset or restore signals.
Avoid: schema version, ratchet version

**Protocol State Kind** (one per Protocol State Blob address):
The stable category for a Protocol State Blob — ratchet/session state, prekey state, sender
certificate, deduplication set, or pending acknowledgments. The consumer combines the Kind with a
key such as a Session or Identity identifier to address one Blob.
Avoid: table, bucket, namespace

**Session** (between two Identities):
An ongoing encrypted channel between two Identities, advanced by the Double Ratchet, identified by `SessionID`.
Avoid: connection, conversation, chat

## Example

**Dev:** If a user re-installs the app, do they keep their Identity?

**Domain expert:** No — Identity is bound to private key material held on the Device. A fresh installation starts a new Identity unless the user restores from an Identity backup, which re-creates the Identity on the new installation.

**Dev:** Then why distinguish Identity from Device at all in the MVP?

**Domain expert:** Identity is the addressing unit — Sessions pair two Identities and sender certificates bind to Identity keys. Device is the persistence unit — it owns the private material in platform secure storage. Even at one-to-one, separating them keeps Session establishment, sender certificates, and Identity backup independent of where the bytes physically live.

## Flagged Ambiguities

**Clock time** (maintenance) vs **reference time** (validation): Rotation reads "now" from an injected `Clock` because it is library-initiated maintenance. Validation verdicts (e.g., sender-certificate expiry, [ADR 0002](../../docs/adr/0002-sender-certificate-validation.md)) instead take a caller-supplied reference timestamp, so the verdict stays a reproducible pure function of its inputs. Reserve the `Clock` for maintenance scheduling; do not route validation through it.

**Session** (cryptographic) vs **session** (app login state): The cryptographic Session is the Double Ratchet state between two Identities; the lowercase host-app "session" is the user's logged-in state. Reserve capitalized `Session` for the cryptographic concept.
