# Standalone binding verification over UniFFI

**Status:** Accepted

`verify_identity_key_binding` and `verify_discovery_to_identity_binding` accept public material
without requiring a Session or contact. They let consumers validate discovery results using
Roost's implementation instead of duplicating Ed25519 verification in each app.

Each function fixes its context and constructs its payload. The two signatures cover identical
64-byte identity-key payloads, so accepting a caller-selected context would move their only
separation into client code. They stay separate because discovery-to-identity callers may have an
authenticated Identity Key without its self-binding signature. That API accepts only the two key
halves; it does not request a signature it would ignore.

Canonical key validation rejects noncanonical and small-order keys before verification. Typed
errors distinguish malformed inputs from authentication failure. Neither function signs data or
accepts arbitrary Ed25519 preimages. Exact contexts are in
[domain separation](../domain-separation.md).
