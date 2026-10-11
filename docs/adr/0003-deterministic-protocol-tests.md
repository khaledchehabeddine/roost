# Deterministic Protocol Tests

Crypto functions take the random number generator as a parameter, so a failing handshake or ratchet test can replay the same random inputs. In production, Core and Client pass in the operating system's generator themselves, so the UniFFI API never exposes the parameter.
