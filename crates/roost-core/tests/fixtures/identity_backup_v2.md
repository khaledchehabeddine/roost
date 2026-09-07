# Identity Backup v2 Fixtures

These fixtures pin the passphrase-encrypted identity backup envelope so backups round-trip across
library versions. Each fixture records the original and normalized passphrase, the canonical backup
bytes split into header and ciphertext, and the identity and discovery-key material that importing
those bytes must restore.

Fixture bytes are deterministic test-only material generated from a fixed RNG seed and a fixed
clock. They have no production origin.

The backup is a self-describing envelope at format version `2`:

- a cleartext header — version byte, Argon2id memory/time/parallelism costs, salt, and nonce —
  authenticated as the AEAD associated data, so neither the version nor a work-factor parameter can
  be altered without failing decryption;
- an XChaCha20-Poly1305 body over the identity key halves followed by the verbatim discovery-key
  blob.

Vector metadata pins the library's fixed Argon2id profile: 64 MiB memory, three iterations, one
lane, and a 64 MiB minimum memory-cost floor. Passphrases are normalized with Unicode NFC before
Argon2id derivation.

Importing a fixture restores the permanent identity key and the discovery key it carries, keeping
the discovery-epoch lineage rather than starting fresh. The decoded fields pin the restored
identity X25519 public key and Ed25519 verifying key, and the restored discovery key's epoch,
X25519 public key, and Ed25519 verifying key.

Supported version:

- `2` is the current envelope. The earlier versionless 120-byte layout is not produced or read.

## Regenerated for discovery-key blob version 2

The envelope format is unchanged, but the discovery-key blob it carries verbatim moved from version
1 to version 2: the blob gained a trailing 32-byte recipient delivery capability, and the inbox
generation was rebased to start at 1 instead of 0. See
[roost-core ADR 0013](../../docs/adr/0013-inbox-generation-and-delivery-capability.md).

The fixture bytes were therefore regenerated with the same recipe recorded in `provenance`. Two
consequences are visible in the vector and are expected:

- `discovery_epoch` moved from 2 to 3, because the same three rotations now start at 1.
- The discovery key material changed, because generating the capability draws from the same seeded
  RNG and shifts the stream. The identity key material is unchanged, since it is drawn first.

A version 1 blob is rejected on import by the length check. That is a deliberate break, taken while
no client has implemented backup export or restore and so no such backup exists outside this file.

Reads reject a backup whose Argon2id work factor falls below the normative floor (64 MiB memory,
three iterations, single lane), blocking work-factor downgrade from old or hostile files.
