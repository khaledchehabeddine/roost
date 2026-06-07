# Protocol State Blob v1 Fixtures

These fixtures pin the Core-owned Protocol State Blob envelope for ratchet/session,
deduplication-set, pending-acknowledgment, and contact state. Each JSON fixture records the Blob
version, Protocol State Kind, Protocol State Key, decoded expectations, and canonical encoded
bytes.

Fixture bytes are deterministic test-only material generated from a fixed RNG seed. They have no production origin.

Together with the Message wire fixtures, these blobs lock the sealed-sender session shape: sender identity material stays inside encrypted payloads, while blobs remain opaque consumer storage values.

The current ratchet/session body wraps Double Ratchet bytes and an optional expected peer sender
identity key. The unbound fixture leaves that binding empty because it pins outbound state; the
bound fixture pins key-only peer identity storage.

The current deduplication-set body wraps the configured capacity, the per-Identity keyed BLAKE3
secret, and the ordered digest window. The fixture pins an initialized empty window.

The current contact-state body wraps one Contact Identity — peer IK plus current DK — the IK-bound
Trust State, and the local blocking flag. Contact fixtures pin Pending, Unverified, Verified,
blocked Pending, blocked Unverified, blocked Verified, DK-rotated accepted, DK-rotated blocked,
and unblocked restored-state contacts. The contact Protocol State Key is the canonical IK
encoding; the DK X25519 public key is the lookup key consumers use for the contact's prekey
bundle.

Supported version:

- `1.0` is the current Core envelope. Wrapped session-state bodies are current.

Old pre-release blobs are not supported. Current-version blobs with stale body shapes fail as malformed current blobs, except contact-state body v1, which decodes as unblocked and rewrites to body v2 on the next contact update. Non-current envelope versions fail as unsupported versions.

The bytes are opaque consumer storage values. Fixture tests may decode them to verify current-format invariants, but consumers must persist and return them by kind/key without inspecting their contents.
