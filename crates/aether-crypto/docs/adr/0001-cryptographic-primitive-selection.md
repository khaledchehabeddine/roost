# Cryptographic Primitive Selection

**Status:** Accepted

X25519 (key exchange) and Ed25519 (signing) are Aether's cryptographic primitives, both built on Curve25519 because it offers constant-time arithmetic by design (no timing-attack countermeasures needed), compact 32-byte keys (which keep prekey bundles and message headers small), transparent parameter design free of unexplained NIST constants (resistance against undocumented weakening), and a shared audit surface across key exchange and signing — one curve audit covers both operations. The implementations come from independently audited Rust libraries that run in production at Signal and Tor scale, which exercises them against real adversaries.
