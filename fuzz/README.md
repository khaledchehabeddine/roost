# Malformed-Input Fuzzing

This package is excluded from the workspace and is built through `cargo-fuzz`.

Targets:

- `message_decode`
- `protocol_state_blob_decode`
- `prekey_store_decode`
- `sender_certificate_validate`
- `sealed_frame_envelope_decode`
- `sealed_payload_padding`

Run the bounded smoke suite:

```bash
scripts/ci/fuzz-smoke.sh
```

Run an extended campaign:

```bash
AETHER_FUZZ_SECONDS=900 scripts/ci/fuzz-smoke.sh
```

Seed files live under `fuzz/corpus/<target>/`. Prefer small, named seeds that either replay a
checked-in fixture or pin one malformed class: unsupported version, truncation, overlong field,
non-canonical key, tampered associated data, padding boundary, or replay/deduplication state.

Text seed forms:

- `hex:<hex>` decodes raw bytes.
- `repeat:<byte>:<count>` expands repeated raw bytes, capped at 256 KiB.
- Protocol-state seeds use `kind:`, `key:`, and `blob:` fields.
- PreKey seeds use `kind: discovery|signed|one_time` and `blob:`.
- Sender-certificate seeds use `certificate:`, `signature:`, `domain_id:`, `domain_key:`,
  `domain_status:`, `expected_relay_domain:`, `reference:`, and `grace:`.

When a new fixture is added, add one happy-path seed for it and one nearby rejection seed if the
wire shape exposes a new malformed class.
