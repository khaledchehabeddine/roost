# Secret Handling

This note records the issue 116 review scope. It is audit evidence, not a runtime contract; code
and tests remain authoritative.

## Posture

- Secret-bearing values do not derive `Debug`.
- Secret-owning public types avoid `Clone`; private clones are limited to rollback or decoded
  metadata paths whose fields zeroize on drop.
- Heap secrets, decrypted plaintext, persisted protocol-state bytes, and FFI-loaded secret bytes
  use `Zeroizing` before validation can return early.
- Secret comparisons use `ConstantTimeEq`. Public protocol fields such as versions, lengths,
  epochs, counters, and enum states use normal equality.
- Key generation draws each key half from the injected CSPRNG. Production callers use `OsRng`;
  tests may inject seeded RNGs for reproducibility.

## Inventory

| Type or value | Owner | Copying and formatting | Drop behavior | Boundary | Branch/comparison notes |
| --- | --- | --- | --- | --- | --- |
| `KeyPair` | `aether-crypto` | no public `Clone` or `Debug` | X25519 secret zeroizes | Rust public API | public key equality is public data |
| `SigningKeyPair` | `aether-crypto` | no public `Clone` or `Debug` | Ed25519 secret zeroizes | Rust public API | signing is deterministic; no secret comparison |
| `DiscoveryKey` | `aether-crypto` | no public `Clone` or `Debug` | X25519 and Ed25519 secrets zeroize | persisted by Core | generated with separate X25519 and Ed25519 draws |
| `SignedPreKey` | `aether-crypto` | no public `Clone` or `Debug` | X25519 secret zeroizes | persisted by Core | public-key reference checks use constant-time equality |
| `OneTimePreKey` | `aether-crypto` | no public `Clone` or `Debug` | X25519 secret zeroizes | persisted by Core | consumed by ID and epoch, which are public metadata |
| `RootKey`, `ChainKey`, `MessageKey` | `aether-crypto` | private; clone only for rollback/state advance | bytes zeroize | internal ratchet | message-key cache lookup branches on public header key and number |
| `RatchetState` and wire form | `aether-crypto` | no public `Clone` or `Debug`; private snapshot only | serialized secret fields zeroize | protocol-state blob | `was_contributory()` rejects low-order DH output |
| Decrypted frame/plaintext buffers | `aether-crypto` | returned as `Zeroizing<Vec<u8>>`, no enclosing `Debug` | heap bytes zeroize | Rust public API | validation happens after immediate wrapping |
| `SenderIdentityMaterial` | `aether-crypto` | cloneable for decoded metadata; no `Debug` | opaque certificate/signature bytes zeroize | sealed-sender output | identity-key equality uses constant-time checks where secret-adjacent |
| `Identity` | `aether-core` | no public `Clone` or `Debug` | key pairs zeroize through fields | Rust public API | identity halves are generated independently |
| Identity backup plaintext and key | `aether-core` | private `Zeroizing` buffers | heap bytes and KDF output zeroize | encrypted backup API | passphrase errors are redacted |
| `ProtocolStateBlob` | `aether-core` | no public `Clone` or `Debug` | blob bytes zeroize | caller-held persistence | blob address comparisons use public address fields |
| `InboundMessageResult::plaintext` | `aether-core` | enclosing result has no `Debug` or `Clone` | plaintext bytes zeroize | Rust public API | padding validation branches only after AEAD decrypt |
| Deduplication digest key | `aether-core` | private only | key bytes zeroize | protocol-state blob | digest comparison scans with `ConstantTimeEq` |
| `SecureStorage` loaded values | `aether-core` | `Zeroizing<Vec<u8>>` copies only | heap bytes zeroize | storage trait | storage key names are public labels |
| UniFFI `SecureStorage::store` values | `aether-uniffi` callers | bare `Vec<u8>` at FFI boundary | foreign implementations own scrubbing policy | Swift/Kotlin boundary | host apps must treat values as secret until overwritten |
| UniFFI `SecureStorage::load` values | `aether-uniffi` | bare `Vec<u8>` at FFI boundary | Rust wraps immediately after receipt | Swift/Kotlin boundary | storage key names are public labels |
| UniFFI backup passphrases | `aether-uniffi` | bare `String` at FFI boundary | Rust wraps immediately after receipt | Swift/Kotlin boundary | wrong-passphrase errors are redacted |

## Limits

- `Zeroizing<T>` protects drop, not all caller-created copies. Public APIs that return bytes still
  rely on callers to avoid logging or cloning them.
- No formal side-channel proof is claimed. This review covers implementation hygiene: no obvious
  secret-dependent branching in local code, constant-time equality on secret-adjacent comparisons,
  and audited crypto primitives for scalar arithmetic and AEAD operations.
