# Decoder fuzzing

This package is excluded from the workspace and built through `cargo-fuzz`.
Run `scripts/ci/fuzz-smoke.sh` for a bounded smoke run, or set `AETHER_FUZZ_SECONDS=900` for an
extended campaign. The script uses a scratch corpus under `fuzz/target/` so mutations do not change
committed seeds.

| Target | Raw input |
| --- | --- |
| `message_decode` | Encoded outer Message frame, including X3DH prekey references |
| `protocol_state_blob_decode` | Kind index from `ProtocolStateKind::all()`, one-byte key length, key, blob |
| `prekey_store_decode` | Kind byte modulo 3, then discovery, signed-prekey, or one-time-prekey bytes |
| `sender_certificate_validate` | 64-byte signature followed by certificate; shorter inputs have a short signature and empty certificate |
| `sealed_sender_envelope_decode` | Decrypted inner sender envelope |
| `sealed_payload_padding` | Padded payload |

Keep small named seeds that reach a distinct decoder path. Certificate trust, revocation, and expiry
policy are asserted in Rust certificate fixtures; fuzzing uses their trusted primary key and fixed
validation inputs. The fixed signature prefix does not fuzz signature lengths independently of
certificate parsing; the Rust signature-rejection test covers malformed lengths. AEAD tampering and deduplication have Rust assertions instead of fuzz calls that
ignore their results. Outer-frame parsing runs through `message_decode` once.

The inner-envelope seed uses the canonical sealed-session fixture's sender material, an all-zero
64-byte transcript signature, and valid padding. This target checks decoding and key binding;
Message transcript authentication remains covered by receive tests. Unsupported-version and
truncated seeds derive from that valid envelope.
