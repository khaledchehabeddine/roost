# Safety Number v1 Fixtures

These fixtures pin Safety Number derivation from permanent Identity Keys. Each fixture records two
canonical IKs, the 32-byte BLAKE3 derivation output, and the grouped 60-digit decimal display.

The DK-rotation fixture uses the same IK pair as `pair_alpha` with two different Discovery Key
X25519 values. Those DK values are included only to prove they are not derivation inputs; the
Safety Number is unchanged because it binds to IKs.

Fixture bytes are deterministic test-only material generated from a fixed RNG seed. They have no
production origin.
