# Skipped-Key Cap Rejection

When a message would overflow the Double Ratchet's skipped-key cache, the ratchet rejects it instead of evicting stored keys. Keeping every stored key means an attacker can't make delayed messages undecryptable, and the session state stays unchanged. A ratchet header isn't authenticated until decryption succeeds, so hitting the cap never ends a session (ADR 0043).
