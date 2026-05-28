# Cryptographic Test Vector Derivation

**Status:** Accepted

Double Ratchet test vectors are computed using external reference tools (pyca/cryptography, libsodium) that share no code with the RustCrypto crates used in production; the byte values are committed as constants next to each test, with a doc comment recording inputs, algorithm, and tool family. The derivation script itself is not committed — including it would create a path of least resistance for auditors, while omitting it forces each reviewer to bring their own derivation tool, and the resulting test passing means three independent implementations agree rather than the code agreeing with itself.
