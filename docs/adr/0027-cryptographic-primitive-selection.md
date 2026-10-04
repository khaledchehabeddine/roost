# Cryptographic Primitive Selection

Key agreement uses X25519 and signatures use Ed25519, both from the dalek libraries. Their keys are small enough for mobile, and mature libraries mean Roost doesn't maintain its own curve math. These curves don't by themselves make Roost constant-time or audited, so the implementation still needs review.
