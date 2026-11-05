# Using a One-Time Prekey on Receive

Decrypting a First Message can use up a one-time prekey, which changes SecureStorage. That change travels as a Prepared KeyStore Operation in the result's state changes, so the app commits the Message and the prekey's use together.

## Alternatives

- Accept a First Message that uses a one-time prekey in its own call: the app would have to tell First Messages apart before decrypting them.
