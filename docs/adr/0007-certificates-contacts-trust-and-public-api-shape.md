# Certificates, Contacts, Trust, and Public API Shape

**Status:** Accepted

Sender-certificate validation is a pure verdict over caller inputs: certificate bytes, sender
signature bytes, a trusted domain-signing-key set, a typed revocation input, a caller-supplied
reference Unix timestamp in seconds, and a consumer-supplied grace window in seconds. The library does not
read the device clock for this verdict. A valid certificate proves only that one trusted domain
signing key signed the sender IK and current DK binding; local Trust State and Blocking remain
separate local decisions.

The canonical sender-certificate signed content is fixed bytes, not Postcard or JSON: ASCII domain
tag `AetherSenderCertificate-v1:`, one-byte version `1`, one-byte signing-key identifier length
`1..=64`, signing-key identifier bytes, IK X25519 public key, IK Ed25519 verifying key, DK X25519
public key, DK Ed25519 verifying key, DK epoch, and certificate expiry Unix timestamp in seconds.
The DK epoch is a `u32` and expiry is a `u64`; both are big-endian. The sender signature is a
separate 64-byte Ed25519 signature over exactly those certificate bytes, matching existing
`SenderIdentityMaterial` separation of opaque certificate and signature fields. Certificate bytes
and signature bytes reject malformed lengths and trailing bytes. Validation matches the
signing-key identifier to exactly one currently trusted Ed25519 domain signing key. Trusted-key
rotation overlap is represented by passing multiple trusted key identifiers. Unknown identifiers
reject without fallback probing across other trusted keys.

Revocation is evaluated against the current revocation input on every validation call, using the
canonical IK encoding as the revocation key. The input is typed as available-or-unavailable rather
than a bare list, so an empty set always means no IK is revoked and never stands in for a
revocation source that failed to load; an unavailable revocation source fails validation closed
before any verdict, after signature verification. A prior positive certificate result is not
reused after that IK appears in the revocation input. Expiry is computed only from certificate
expiry, reference timestamp, and grace window: a certificate is accepted when
`reference_timestamp <= expiry || reference_timestamp - expiry <= grace_window`. This avoids
overflow in `expiry + grace_window`. The grace window is consumer policy for clock skew and
delivery delay, not a library default. Grace bounds are wholly consumer-owned: the library imposes
no ceiling, and `u64::MAX` keeps every expired certificate acceptable forever, a trade-off the
consumer sets from its own product requirements.

Contact Identity is the peer IK plus its current DK. Trust State is keyed to the IK and survives DK
rotation. Contact updates must verify the IK signature over the DK bundle and reject stale DK
rollback by accepting a candidate DK only when its `(created_at, epoch)` pair is lexicographically
greater than the stored pair (implemented by `contact_discovery_key_is_newer`, locked by the
`contact_state` update tests). The signed `created_at` leads the comparison because the DK bundle
carries no storage-lineage discriminator and a restored device legitimately resets its epoch, so
only the IK-signed timestamp can order DKs across lineages; the epoch breaks ties within one
timestamp. The accepted trade-off is that a same-lineage rotation to a higher epoch is rejected
when the peer's clock has moved backward past its previous rotation, and stays rejected until a
later rotation carries a `created_at` past the stored one. New contacts begin Pending; consumer-recorded acceptance moves
Pending to Unverified. Only consumer-recorded out-of-band Safety Number confirmation moves
Unverified to Verified. In-band confirmation carried by protocol messages never raises trust to
Verified.

Safety Numbers are derived from both parties' canonical IK encodings. Each canonical IK encoding
is ASCII domain tag `AetherIK-v1:`, IK X25519 public key, and IK Ed25519 verifying key. The two
encodings are sorted lexicographically, then hashed with BLAKE3 over
`AetherSafetyNumber-v1:` plus both sorted encodings. Interpret the 32-byte hash as a big-endian
integer, reduce it modulo `10^60`, left-pad to 60 decimal digits, and display 12 groups of five
digits. Sorting makes both parties display the same value while still binding the number to both
permanent identity keys.

Blocking is IK-keyed, local, independent of Trust State, and distinct from certificate revocation.
For a unique inbound Message from a blocked IK, Core still performs normal protocol acceptance:
deduplicate, decrypt, validate sender identity binding, validate the sender certificate, advance
ratchet/session and deduplication Protocol State Blobs, and generate an Acknowledgment Artifact
subject to the consumer-configured blocked-contact acknowledgment policy. The certificate DK X25519
key, DK Ed25519 verifying key, and DK epoch must match the decrypted sender identity/session binding
before Core derives IK-keyed trust or blocking outcomes; revoked IKs reject before blocking is
consulted. The result is not surfaced to the consumer as plaintext. The acknowledgment policy is
consumer-configurable with a privacy trade-off: the default Unreachable mode suppresses the
Acknowledgment Artifact and does not advance the sending chain, so a blocked sender cannot
distinguish a block from an unreachable recipient and keeps retrying as if offline; the opt-in
SilentReceipt mode returns the Acknowledgment Artifact, revealing delivery, while still hiding
plaintext. Duplicate blocked Messages follow normal duplicate behavior and do not regenerate
acknowledgments.

Contact, trust, and blocking state persists as one IK-keyed Contact State Protocol State Blob per
local Identity and peer IK. Contact state is decoded alongside ratchet/session state,
deduplication set, and pending acknowledgments; PreKey State remains KeyStore storage and Sender
Certificates remain caller validation inputs. The blob stores the current DK material, Trust State,
and blocking flag so contact updates, trust transitions, and block/unblock operations return one
atomic ProtocolStateUpdate. Events follow the existing per-instance Event Stream model, but are
emitted only after the consumer confirms durable commit of the returned ProtocolStateUpdate. Each
committed contact, trust, or blocking change emits a self-contained public snapshot, observers
recover from lag through Current State Snapshots, and cross-instance visibility still comes from
the shared Protocol State Blob store rather than the in-process Event Stream.

The public Rust API review resolves to five future surfaces: certificate validation takes the full
input set above and returns a typed verdict; contact APIs create/update IK-keyed Contact Identity
records from certificate validation and DK rotation; trust APIs expose only the Pending to
Unverified and Unverified to Verified transitions; Safety Number APIs expose both raw derivation
bytes and grouped decimal display; blocking APIs expose block/unblock and receive outcomes that
distinguish surfaced plaintext from blocked protocol acceptance. Fixture coverage must lock the
fixed-byte certificate and Safety Number encodings before those APIs release.

## Scope Boundary

This record fixes certificate validation, contact identity, trust, safety number, and blocking
behavior. It does not require Rust implementation in the decision-record change.

## Considered Options

- Postcard certificate signed content. Rejected. It would be terse for Rust but would couple
  domain signers and auditors to an internal Rust serialization choice.
- Canonical JSON certificate signed content. Rejected. It is readable but adds cryptographic
  canonicalization risk.
- Separate contact, trust, and blocking blobs. Rejected because one IK-keyed blob keeps local
  contact state transitions atomic under the existing Protocol State Blob model.

## Verification Evidence

- `crates/aether-core/tests/fixtures/protocol_state_blobs_v1.md` pins Contact State blobs for
  Pending, Unverified, Verified, blocked, DK-rotated, and unblocked restored-state contacts.
- `crates/aether-core/tests/protocol_state.rs` covers blocked inbound unreachable and
  silent-receipt acknowledgment behavior, duplicate blocked Messages, DK rotation while blocked,
  and unblock-without-handshake recovery.
- `crates/aether-uniffi/docs/api-coverage.md` records binding coverage for contact trust,
  blocking, blocked-contact negative paths, and stale protocol-state commits.
