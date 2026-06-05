# Protocol State Blob v1 Fixtures

These fixtures pin the Core-owned Protocol State Blob envelope for ratchet/session state. Each JSON fixture records the Blob version, Protocol State Kind, Protocol State Key, decoded expectations, and canonical encoded bytes.

Fixture bytes are deterministic test-only material generated from a fixed RNG seed. They have no production origin.

Together with the Message wire fixtures, these blobs lock the sealed-sender session shape: sender identity material stays inside encrypted payloads, while blobs remain opaque consumer storage values.

The current ratchet/session body wraps Double Ratchet bytes and an optional expected peer sender identity key. The unbound fixture leaves that binding empty because it pins outbound state; the bound fixture pins key-only peer identity storage.

Supported version:

- `1.0` is the current Core envelope. Wrapped session-state bodies are current.

Old pre-release blobs are not supported. Current-version blobs with stale body shapes fail as malformed current blobs; non-current envelope versions fail as unsupported versions.

The bytes are opaque consumer storage values. Fixture tests may decode them to verify current-format invariants, but consumers must persist and return them by kind/key without inspecting their contents.
