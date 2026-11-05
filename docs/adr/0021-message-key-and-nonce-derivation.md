# Message Key and Nonce Derivation

One HKDF-SHA256 step derives both the encryption key and the nonce from each ratchet message key, so the receiver computes the same pair and the nonce is never sent. This is safe only because each message key is used once, which replay rejection and durable ratchet commits ensure.
