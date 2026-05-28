# X3DH-lite Handshake

**Status:** Accepted

Initial Session establishment uses a three-DH handshake combining each peer's long-term identity key (IK), the responder's signed prekey (SPK), and the initiator's ephemeral key (EK) — `DH1 = IK_A·SPK_B`, `DH2 = EK_A·IK_B`, `DH3 = EK_A·SPK_B` — combined via HKDF-SHA256 with a protocol-specific info string and a fixed IKM prefix. No one-time prekeys are used, accepting reduced forward secrecy against SPK compromise in exchange for stateless responders; the fixed IKM prefix gives a forward-compatible kill-switch so incompatible peers derive different session keys and fail the handshake rather than silently misalign. Builds on the Curve25519 primitives in [DR 0001](0001-cryptographic-primitive-selection.md).
