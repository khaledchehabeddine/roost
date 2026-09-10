# Message key and nonce derivation

**Status:** Accepted

One HKDF-SHA256 expansion derives the 32-byte encryption key and 24-byte nonce from each ratchet
message key. The receiver derives the same pair, avoiding nonce transmission. This relies on using
each message key once; replay rejection and durable ratchet-state commits preserve that condition.

The chain-derived input already supplies pseudorandom key material, so this expansion uses no salt.
Distinct, non-empty info strings separate derivation purposes; their bytes are fixed in
[domain separation](../../../../docs/domain-separation.md).
