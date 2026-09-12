# Deterministic protocol tests

**Status:** Accepted

Crypto operations and Core managers accept `RngCore + CryptoRng` so failing handshake
and ratchet tests can reproduce their inputs. The generic forwards the existing primitive interfaces without an adapter;
production uses `OsRng`. The KeyStore facade supplies randomness internally, keeping the generic
out of UniFFI.

KeyStore uses an injected `Clock` for caller-invoked prekey lifecycle operations. Certificate
validation takes an explicit reference timestamp because the caller owns that verdict's time.
Neither seam requires a background scheduler or a separate test framework.

A failed ratchet decrypt can consume RNG input while rolling state back. Rejection tests assert
state preservation rather than assuming that both state and RNG roll back.
