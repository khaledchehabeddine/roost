# Domain Separation Contexts

Versioned inventory of every domain-separation string Aether uses, and the exact bytes each one
covers. Satisfies AE-KEY-02.

This document exists because independent implementations — the Relay Cloud relay above all — must
reproduce these preimages byte for byte to verify Aether-produced signatures. A mismatch in a
context string or a field order fails every verification rather than degrading, so the values below
are normative for the listed library version and are read directly from the source, not restated
from the specification.

Applies to: **Aether v0.15.0**. Update on any change and note the affected release.

## How a context is applied

`SigningKeyPair::sign_with_context(context, message)` signs the plain concatenation
`context || message` — no separator byte, no length prefix
([`keys/signing.rs`](../crates/aether-crypto/src/keys/signing.rs)). `verify_with_context` recomputes
the same bytes. An empty context is rejected with `CryptoError::InvalidSignatureContext`.

Because composition is bare concatenation, **the set of signature contexts must be prefix-free**. If
one context were a proper prefix of another, a signature over `(context_a, message_x)` and one over
`(context_b, message_y)` could cover identical bytes whenever `a || x == b || y`, defeating the
separation the contexts exist to provide. Every value in this document satisfies that property.
Nothing in the code enforces it, so check any new context against this list before adding it.

The trailing `:` in each string is part of the constant, not a separator the code inserts.

## Ed25519 signature contexts

These are the values passed to `sign_with_context` / `verify_with_context`. Sizes are the payload
that follows the context, in order. All integers are big-endian.

### `AetherIKBinding-v1:`

Identity key self-binding — the IK's Ed25519 half signing its own X25519 half (AE-KEY-04).

| Field | Size | Notes |
|---|---|---|
| `ik_x25519` | 32 | IK key-agreement public half |
| `ik_ed25519` | 32 | IK verifying key |

Payload is exactly 64 bytes. Source:
[`keys/identity.rs`](../crates/aether-crypto/src/keys/identity.rs) `identity_key_binding_payload`.

Reachable from a binding as `verify_identity_key_binding`, which takes public material only. Prefer
it to reimplementing the preimage — the two identity contexts below cover identical bytes, so an
implementation that drops or swaps one accepts a signature made for the other purpose.

### `AetherDK-v1:`

Identity-to-discovery binding — the IK's Ed25519 half signing a discovery key (AE-IDN-01, AE-KEY-04,
IK→DK direction).

| Field | Size | Notes |
|---|---|---|
| `dk_x25519` | 32 | DK key-agreement public half |
| `dk_ed25519` | 32 | DK verifying key |
| `epoch` | 4 | `u32` big-endian |
| `created_at` | 8 | `u64` big-endian, Unix seconds |

Payload is exactly 76 bytes. Source:
[`discovery_key.rs`](../crates/aether-crypto/src/discovery_key.rs) `discovery_key_payload`. A
known-answer vector is in that file's test module (`discovery_key_signing_known_answer`).

The epoch and timestamp are present because the IK is permanent: without them the signature would
not say *which* discovery key generation the permanent key authorized.

### `AetherDKToIK-v1:`

Discovery-to-identity binding — a discovery key's Ed25519 half signing the identity key it vouches
for (AE-KEY-04, DK→IK direction). Populates
`relay.cloud.v1.KeyBindingSignatures.discovery_to_identity`.

| Field | Size | Notes |
|---|---|---|
| `ik_x25519` | 32 | IK key-agreement public half |
| `ik_ed25519` | 32 | IK verifying key |

Payload is exactly 64 bytes; the full preimage including the 16-byte context is 80 bytes. Source:
[`discovery_key.rs`](../crates/aether-crypto/src/discovery_key.rs)
`DiscoveryKey::sign_identity_binding`, verified by `verify_discovery_to_identity_binding` — which is
also the name of the UniFFI export, so a client checking a discovery-key lookup before any session
exists calls Aether rather than rebuilding this preimage.

**No epoch and no timestamp**, unlike the IK→DK direction above. A permanent identity key signs many
discovery keys over its lifetime and needs the epoch to disambiguate them; a discovery key is minted
fresh per inbox generation and so already identifies its own generation. Freshness is enforced by
the relay's inbox registry (Relay REL-RLY-72, REL-RLY-76), not by this signature. Rationale in
[ADR 0009](../crates/aether-crypto/docs/adr/0009-discovery-to-identity-binding.md).

Note this payload is byte-identical to `AetherIKBinding-v1:` above — **only the context distinguishes
them.** An implementation that drops or substitutes the context will silently accept a signature made
for the other purpose. Both directions in this codebase derive the payload from one shared function
so they cannot drift.

#### Cross-implementation vector

Derived from the RFC 8032 reference implementation, which shares no code with the `ed25519-dalek`
used in production, per
[ADR 0005](../crates/aether-crypto/docs/adr/0005-cryptographic-test-vector-derivation.md).

| Input | Value |
|---|---|
| `discovery_signing_secret` | `33` × 32 |
| `identity_signing_secret` | `11` × 32 |
| `ik_x25519` | `22` × 32 |

Derived public keys:

```
ik_ed25519  d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737
dk_ed25519  17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce
```

Expected signature:

```
17b0421ddf2d07445b3b94ce32df736dc2c96a2089bbbf136ec530f5fa3e2e3c
2c2118e144a8578dc7bed85b6b09ac136780ecd147d6e0473b00700933ef0000
```

Pinned in `discovery_to_identity_binding_known_answer`. Reproduce it with your own Ed25519
implementation rather than by calling Aether — a vector generated from the code it tests proves only
that the code agrees with itself.

### `AetherSPK-v1:`

Signed pre-key — signed by the *discovery* key's Ed25519 half, not the identity key.

| Field | Size | Notes |
|---|---|---|
| `spk_x25519` | 32 | Signed pre-key public |
| `epoch` | 4 | `u32` big-endian, the DK epoch it belongs to |
| `created_at` | 8 | `u64` big-endian, Unix seconds |

Payload is exactly 44 bytes. Source:
[`signed_prekey.rs`](../crates/aether-crypto/src/signed_prekey.rs) `signed_prekey_payload`.

Verification uses `DiscoveryKey::verifying_key()`. A signed pre-key does **not** verify under the
identity key — see `discovery_signed_prekey_verifies_under_discovery_key_only`.

### `AetherMessageTranscript-v1:`

Message transcript signature. Source:
[`protocol_state.rs`](../crates/aether-core/src/protocol_state.rs).

## Domain tags inside canonical encodings

These are **not** passed to `sign_with_context`. They are literal prefixes inside a byte encoding
that is then hashed or signed as a whole, so an implementation reproducing the encoding must include
them at the stated position.

### `AetherIK-v1:`

Prefix of the canonical identity-key encoding: `"AetherIK-v1:" || ik_x25519 || ik_ed25519`, 76 bytes
total. Consumed by the safety-number derivation and the sender certificate. Source:
[`keys/identity.rs`](../crates/aether-crypto/src/keys/identity.rs)
`IdentityKeyBundle::canonical_encoding`.

### `AetherSafetyNumber-v1:`

First input to the safety-number hash. Source:
[`safety_number.rs`](../crates/aether-core/src/safety_number.rs).

### `AetherSenderCertificate-v2:`

Prefix of the sender-certificate byte encoding, signed as a whole by a domain-signing key. Source:
[`sender_certificate.rs`](../crates/aether-core/src/sender_certificate.rs).

| Field | Size | Notes |
|---|---|---|
| domain tag | 27 | `AetherSenderCertificate-v2:` |
| version | 1 | `2` |
| `id_len` | 1 | signing-key identifier length, 1..=64 |
| `signing_key_identifier` | `id_len` | selects the domain-signing key |
| `domain_len` | 1 | relay domain length, 1..=255 |
| `relay_domain` | `domain_len` | the relay this certificate is valid at |
| `ik_x25519` | 32 | sender IK key-agreement half |
| `ik_ed25519` | 32 | sender IK verifying key |
| `expires_at` | 8 | `u64` big-endian, Unix seconds |

Version 2 replaced version 1, which carried no relay domain and bound the sender's discovery key and
epoch. Both were wrong against the specification: AE-CRT-01 and REL-RLY-23 require the domain, and
REL-RLY-24 and AE-IDN-05 forbid binding the DK, since certificate validity must survive discovery-key
rotation. Without the domain a certificate was replayable at any relay trusting the same signing key.

A validator must compare `relay_domain` against the domain it expects — the signed value alone stops
nothing. `validate_sender_certificate` requires `expected_relay_domain` for exactly that reason.

### `AetherProtocolStateCommit-v1:`

Digest context for the protocol-state commit. Source:
[`aether-uniffi/src/protocol.rs`](../crates/aether-uniffi/src/protocol.rs).

## Hash domain strings

### `AetherSecureStoragePrecondition-v1`

Prepared KeyStore operation precondition digest. This is the BLAKE3 `derive_key` context argument,
not a byte prefix concatenated with the value:

```
digest = BLAKE3-DeriveKey("AetherSecureStoragePrecondition-v1", secure_storage_value)
```

The 32-byte digest crosses in operation metadata; the SecureStorage value does not enter the host
protocol-state database. Secret values do cross into the trusted host-provided SecureStorage
implementation, including when Core stores its operation journal, and its transient buffers must
remain secret. Core compares the recomputed digest in constant time before committing. Source:
[`key_store/operation.rs`](../crates/aether-core/src/key_store/operation.rs). The known-answer test
`secure_storage_precondition_digest_known_answer` pins `b"fixture secure value"` to:

```
1057a0c66b56f08caa9cc9623796774f165575324362504f1626f534e4090c1a
```

### `aether-recipient-delivery-capability-v1`

Recipient delivery verifier derivation (AE-IDN-10). Added in v0.10.0. **Not** an Ed25519 signature context — this is a
SHA-256 preimage prefix.

```
verifier = SHA-256( "aether-recipient-delivery-capability-v1" || 0x00 || capability )
```

| Component | Size | Notes |
|---|---|---|
| domain string | 39 | ASCII, no trailing colon |
| separator | 1 | single `0x00` byte |
| capability | 32 | the bearer secret |

Preimage is exactly 72 bytes; the verifier is 32. Source:
[`delivery_capability.rs`](../crates/aether-crypto/src/delivery_capability.rs)
`RecipientDeliveryCapability::verifier`.

Note the convention differs from every signature context above: lowercase-kebab, no trailing colon,
and an explicit separator byte rather than a colon inside the string. That is not an inconsistency
to tidy up — the specification fixes these exact bytes, and Relay derives the same value to compare
against the stored verifier (REL-RLY-150). Reproduce it literally.

#### Cross-implementation vector

Derived with Python `hashlib`, which shares no code with the `sha2` crate used in production.

| Input | Value |
|---|---|
| `capability` | `42` × 32 |

```
verifier  fd5232054ffbf4ccc2ae026226ab9316cb1beb87f31833830235a70bd1686d1a
```

Pinned in `verifier_matches_the_specified_derivation`.

## HKDF info strings

Distinct `info` per call, as AE-KEY-02 and the crypto rules require.

| String | Use |
|---|---|
| `AetherSealedFrame-v1:key` | Sealed-frame AEAD key derivation |
| `AetherSealedFrame-v1:nonce` | Sealed-frame AEAD nonce derivation |

Source: [`sealed_frame.rs`](../crates/aether-crypto/src/sealed_frame.rs).

Note these two share the prefix `AetherSealedFrame-v1:`. That is safe here because HKDF `expand`
takes `info` as a bounded, separately-framed argument rather than concatenating it with a message —
the prefix-freedom requirement above applies to signature contexts, not to HKDF info strings.

## AEAD associated data

| String | Use |
|---|---|
| `AetherRatchetedPayload-v1:` | Prefix of the ratcheted-payload associated data |

Source: [`protocol_state.rs`](../crates/aether-core/src/protocol_state.rs).

## Excluded

`AetherTest-v1:first` and `AetherTest-v1:second` appear in
[`keys/signing.rs`](../crates/aether-crypto/src/keys/signing.rs) test modules only. They are not
protocol values and must not be implemented.
