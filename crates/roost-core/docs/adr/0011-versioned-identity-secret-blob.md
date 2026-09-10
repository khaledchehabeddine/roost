# Versioned Identity Secret Blob

**Status:** Accepted

Identity secrets persist to platform secure storage as one versioned blob containing both permanent Identity Key secret halves. The secure-storage contract commits one key at a time and does not promise multi-key atomicity, so writing the X25519 and Ed25519 halves separately can splice halves from different Identities after a torn backup import. A single blob makes the Identity Key the storage commit unit, preserves a migration boundary for future identity-secret layouts, replacing the former versionless two-entry encoding.

## Consequences

- Current writes use only the blob; pre-release two-entry storage remains a read-only fallback.
- Restore commits the Identity Key with one `store`, removing the two-key window that could create a silent hybrid.
