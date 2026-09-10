# Cryptographic primitive selection

**Status:** Accepted

Use X25519 for key agreement and Ed25519 for signatures through the dalek libraries. Their compact
keys fit the mobile protocol, and established implementations avoid maintaining curve arithmetic
in this repository. Implementation review remains necessary; the curve choice alone does not
establish constant-time behavior or an audit of the composed protocol.
