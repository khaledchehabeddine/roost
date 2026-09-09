# Evidence Bundle v1 Fixtures

`evidence_bundles_v1.json` pins Evidence Bundle envelope version `1` and the
`MessageTranscriptV1` profile.

The canonical Postcard field order is:

1. envelope version (`u8`)
2. evidence profile (`u8`)
3. Session state key (length-prefixed bytes)
4. recipient Ed25519 Identity Key verifying half (32 bytes)
5. Message ID (16 bytes)
6. sender-observed timestamp (`u64`)
7. payload-kind tag (`u8`)
8. padded payload (length-prefixed bytes)
9. sender certificate (length-prefixed bytes)
10. domain signature over the sender certificate (length-prefixed bytes)
11. sender Identity Key signature over the Message transcript (length-prefixed bytes)

The Message transcript signature preimage is the ASCII context
`AetherMessageTranscript-v1:` followed by:

```text
u32be(session_key_len) || session_key
|| recipient_identity_verifying_key
|| message_id
|| u64be(timestamp_millis)
|| payload_kind
|| u32be(padded_payload_len) || padded_payload
|| u32be(sender_certificate_len) || sender_certificate
```

The padded payload contains a four-byte big-endian plaintext length, the plaintext, and zero fill
to the selected padding bucket. The exact sender certificate is transcript-bound, preventing a
valid certificate and domain-signature pair for the same Identity Key from being substituted at a
different Relay. A successful verdict also returns the Evidence Identity derived
over both sender Identity Key halves, the Relay domain, and this complete Message transcript under
the `AetherEvidenceIdentity-v1` BLAKE3 context. The valid vector comes from the deterministic Core
accepted-Message fixture; its expected Evidence Identity was independently reproduced with the
official BLAKE3 C 1.7.0 implementation. The generated Swift
harness verifies both Ed25519 signatures independently with CryptoKit; the generated Kotlin harness
does the same with the JDK Ed25519 provider. This makes the fixture an encoding/composition vector
with independent cryptographic counterparties, rather than an implementation self-check.

The rejection vectors pin malformed bytes, a mismatched profile, an unsupported envelope version,
a noncanonical recipient Identity Key, a tampered Message signature, an excessive certificate
grace window, and replay under a different expected relay domain. A Core regression also replaces
the certificate and domain signature with a valid pair for the same Identity Key at another Relay
and proves that the transcript signature rejects the substitution. Rust tests own these rejection verdicts. The generated binding checks use the valid vector for
native signature verification and FFI conversion.
