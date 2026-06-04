# Protocol State Blob v1 Fixtures

These fixtures pin the Core-owned Protocol State Blob envelope for ratchet/session state. Each JSON fixture records the Blob version, Protocol State Kind, Protocol State Key, decoded expectations, and canonical encoded bytes.

Fixture bytes are deterministic test-only material generated from a fixed RNG seed. They have no production origin.

Supported versions:

- `1.0` is the current Core envelope.
- `0.1` is a supported legacy migration fixture.

Old pre-release blobs are not implicitly supported. A prior format is supported only when represented here as an explicit fixture with expected current-version output bytes.

The `unsupported_pre_release_blobs` entries record old shapes that must fail rather than silently migrate.

The bytes are opaque consumer storage values. Fixture tests may decode them to verify migration and invariants, but consumers must persist and return them by kind/key without inspecting their contents.
