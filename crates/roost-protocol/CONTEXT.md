# Protocol

Shared encodings and stateless authenticity verdicts used by mobile clients and reporting backends.

## Language

**Evidence Bundle** (one per accepted established-session Message):
A versioned, opaque export of the authenticated Message Transcript fields, sender certificate and
certificate signature, and sender Identity Key transcript signature. A standalone verifier checks
it at the caller-supplied acceptance timestamp without Session state or current revocation policy;
persisting it creates a durable non-repudiation artifact containing plaintext.
Avoid: report payload, acknowledgment artifact, audit log

**Evidence Identity** (one per authenticated Message at one Relay):
A stable digest derived after Evidence Bundle verification from the sender Identity Key, Relay
domain, and every Message Transcript field. A Backend persists it to deduplicate repeated valid
reports without trusting the sender-chosen MessageID or the replaceable bundle encoding.
Avoid: report ID, MessageID, bundle hash, Deduplication Digest

**Message Transcript** (one per encrypted Message):
The canonical bytes signed by the sender IK and verified after decrypt before surfacing plaintext.
It binds the recipient IK, Session identifier, MessageID, timestamp, payload kind, padded payload,
and exact sender certificate so a sealed signature cannot be transplanted to another recipient,
Message, Session, or Relay certificate.
Avoid: associated data, transport metadata

**Sealed Payload Padding** (one per sealed plaintext):
A 4-byte big-endian original length followed by plaintext and zero fill to a fixed Roost bucket.
Buckets are powers of two from 32 through 65536 bytes, and malformed zero fill is rejected after
decrypt.
Avoid: compression, random padding

**Sender Certificate** (one domain-signed binding for a sender IK at a Relay):
A signed public statement from a trusted domain signing key binding a sender's IK, Relay domain,
signing-key identifier, and expiry. Validation is a caller-timed verdict over the current
trusted-key and revocation inputs. Sender Certificate malformed-input corpora exercise validation
inputs, not Protocol State Blob decoding.
Avoid: trust state, sender profile, discovery key signature
