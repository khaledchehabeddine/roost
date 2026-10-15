# Skipped-Key Cap Rejection

When a Message would overflow the Double Ratchet's skipped-key cache, the ratchet rejects it instead of evicting stored keys. Keeping every stored key means an attacker can't make delayed Messages undecryptable, and the Session state stays unchanged. A ratchet header isn't authenticated until decryption succeeds, so hitting the cap never ends a Session (ADR 0050).
