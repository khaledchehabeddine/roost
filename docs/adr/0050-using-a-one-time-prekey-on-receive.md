# Using a One-Time Prekey on Receive

Decrypting a first message can use up a one-time prekey, which changes SecureStorage. That change travels as a prepared KeyStore operation in the result's state changes, so the app commits the message and the prekey's use together.

## Alternatives

- Accept a first message that uses a one-time prekey in its own call: the app would have to tell first messages apart before decrypting them.
