# Deterministic Protocol Tests

Functions in Crypto and Core take the random number generator as a parameter, so a failing handshake or ratchet test can replay the same random inputs. In production, KeyStore passes in the operating system's generator itself, so the UniFFI API never exposes the parameter.
