# Cryptographic Test Vector Derivation

**Status:** Accepted

Test vectors for primitives without canonical published values — including the Double Ratchet — are computed using external reference tools (pyca/cryptography, libsodium) that share no code with the RustCrypto crates used in production; the byte values are committed as constants next to each test, with a doc comment recording inputs, algorithm, and tool family. The derivation script itself is not committed — including it would create a path of least resistance for auditors, while omitting it forces each reviewer to bring their own derivation tool, and the resulting test passing means three independent implementations agree rather than the code agreeing with itself. Where canonical published vectors exist (RFC 7748 for X25519, RFC 8032 for Ed25519), the library uses those directly.
