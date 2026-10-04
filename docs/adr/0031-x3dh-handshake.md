# X3DH Handshake

A Session starts with X3DH against the recipient's current Discovery Key, signed prekey, and a one-time prekey when one is left. The sender's identity stays sealed inside the first message, so to decrypt it, the app must supply the possible sender Identity Keys.
