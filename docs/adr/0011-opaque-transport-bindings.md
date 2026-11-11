# Opaque Transport Bindings

The sealed sender frame authenticates the exact bytes of the transport binding the app attaches to each message. Roost never parses, sends, or stores them, so it guarantees they arrive unchanged but says nothing about their meaning.

## Alternatives

- Define the relay's routing format in Roost: Roost would depend on one transport.
- Have the app implement a transport callback: authenticating the bytes is all the cryptography needs.
