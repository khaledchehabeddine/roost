# Protocol State Blob v1 Fixtures

These fixtures pin the Core-owned Protocol State Blob envelope for ratchet/session state. Each JSON fixture records the Blob version, Protocol State Kind, Protocol State Key, decoded expectations, and canonical encoded bytes.

Fixture bytes are deterministic test-only material generated from a fixed RNG seed. They have no production origin.

Together with the Message wire fixtures, these blobs lock the sealed-sender session shape: sender identity material stays inside encrypted payloads, while blobs remain opaque consumer storage values.

The current ratchet/session body wraps Double Ratchet bytes and an optional expected peer sender identity key. The unbound fixture leaves that binding empty because it pins outbound state and legacy migration writeback; the bound fixture pins key-only peer identity storage.

Supported versions:

- `1.0` is the current Core envelope. Wrapped session-state bodies are current; flat ratchet-state bodies migrate to the wrapped current bytes.
- `0.1` is a supported legacy migration fixture.

Old pre-release blobs are not implicitly supported. A prior format is supported only when represented here as an explicit fixture with expected current-version output bytes.

The `unsupported_pre_release_blobs` entries record old shapes that must fail rather than silently migrate.

The bytes are opaque consumer storage values. Fixture tests may decode them to verify migration and invariants, but consumers must persist and return them by kind/key without inspecting their contents.
