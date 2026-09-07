# Deterministic Test Infrastructure

**Status:** Accepted

Randomness and time are injected rather than read ambiently, so protocol tests can produce reproducible vectors, replay transcripts, and property-test state transitions. Randomness crosses the API as a generic bound (`R: RngCore + CryptoRng`) threaded through every randomness-bearing operation in `roost-crypto` — key generation, the handshake, and the Double Ratchet — and the `roost-core` managers; production passes `OsRng`, tests a seeded CSPRNG. The generic is chosen over a trait object because the underlying signing and DH primitives already take that bound, so it forwards with no adapter and no dynamic dispatch. The injection seam stops at the `KeyStore` facade, which keeps its public methods unchanged and supplies `OsRng` internally, so no generic leaks across the UniFFI boundary. Time is injected only for *autonomous maintenance scheduling* — signed-pre-key rotation reads "now" through a `Clock` trait — while consumer-facing *verdicts* such as sender-certificate validation keep their caller-supplied reference time (see [ADR 0002](0002-sender-certificate-validation.md)), because a verdict must stay a reproducible pure function of its inputs while maintenance needs a controllable clock. Both the seeded RNG and the virtual clock are constructed only in test code, honoring the rule that no seeded or non-cryptographic RNG appears in production paths.

## Considered Options

- Object-safe `SecureRandom` trait passed as `&mut dyn`. Rejected. Gives one named abstraction but needs a handwritten adapter to dalek's generic `RngCore + CryptoRng` bound and adds dynamic dispatch on every key-generation call.
- Ambient/thread-local RNG swapped in tests. Rejected. Avoids signature churn but hides a global dependency, is hard to reason about under concurrency, and conflicts with the project's auditable, explicit ethos.
- Threading the RNG only into leaf key-generation, leaving the handshake and ratchet on `OsRng`. Rejected. Would leave ratchet/handshake transitions nondeterministic — the exact surface the issue's "replay transcripts / property-test state transitions / fuzz" motivation targets — and forces a second key-generation entry point.
- Caller-supplied reference time for rotation (matching validation). Rejected for rotation specifically. Rotation is library-initiated maintenance with no caller in the loop, so an injected `Clock` fits better than threading a timestamp through every rotation call.

## Consequences

- A DH ratchet step draws from `rng` before the AEAD check inside ratchet decryption, so a failed decrypt that triggered a step still advances the RNG even though the session state rolls back. Deterministic transcript tests must use success paths.
