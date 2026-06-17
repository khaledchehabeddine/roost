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

Reads reject a backup whose Argon2id work factor falls below the normative floor (64 MiB memory,
three iterations, single lane), blocking work-factor downgrade from old or hostile files.
