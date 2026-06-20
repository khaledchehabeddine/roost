# Encrypted Identity Backup Design

**Status:** Accepted

Identity backups are encrypted with XChaCha20-Poly1305 under a key derived from the user's
passphrase via Argon2id, chosen for memory-hard offline-guessing resistance at the documented
release cost. A backup carries both the permanent identity keypair and the current discovery
keypair, so importing it on another Device restores the same Identity and continues its
discovery-epoch lineage rather than starting fresh. The backup file is self-describing: the current
format version, Argon2id parameters, salt, and nonce travel in a cleartext header authenticated as
AEAD associated data, so version and KDF metadata cannot be downgraded without authentication
failure.

The library fixes the Argon2id cost used for export, refuses export or import below the normative
floor, and normalizes passphrases with Unicode NFC before derivation so canonically equivalent
inputs restore the same Identity material. Host applications own passphrase-strength policy before
calling export; the library enforces only format, KDF floor, authentication, and canonical key
encoding. Restore rewinds Identity material only: callers must wipe or replace Protocol State
Blobs, Sessions, pending acknowledgments, and related host state before session recovery or
re-handshake.

## Considered Options

- Back up only the permanent Identity Key. Rejected because restore would start a new Discovery Key
  lineage and make peers reason about a restored Identity as a fresh discovery epoch.
- Store KDF metadata outside AEAD authentication. Rejected because hostile or stale files could
  downgrade work factors or alter version interpretation.
- Let the library accept weak KDF parameters for compatibility. Rejected because backup files are
  offline-guessable artifacts and downgrade compatibility would weaken the release security model.
- Treat backup restore as Session restore. Rejected because Protocol State Blobs are caller-owned
  live key material with separate crash-consistency and recovery semantics.

## Consequences

- Unsupported backup major versions reject rather than being guessed or silently migrated.
- Backup import cannot prove host passphrase quality; consumers must apply product policy before
  invoking export.
- Restored Identities require explicit protocol-state cleanup and fresh session recovery paths.

## Verification Evidence

- `crates/aether-core/tests/fixtures/identity_backup_v2.md` pins backup version `2`, Argon2id
  parameters, NFC passphrase normalization, DK inclusion, restored public material, and
  below-floor rejection.
- `docs/security.md` records restore as a fresh compromise boundary and unsupported-major rejection.
- `docs/security/secret-handling.md` records backup plaintext/key zeroization and redacted
  passphrase-error handling.
