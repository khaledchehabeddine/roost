# Opaque Transport Bindings

Every message Roost seals or opens takes a transport binding, and the sealed sender frame authenticates the binding's exact bytes. The app owns those bytes, and Roost never parses, sends, or stores them. So Roost guarantees the bytes arrive unchanged but says nothing about their meaning.

## Alternatives

- Define the relay's routing format in Roost: Roost would be tied to one transport and its versions.
- Have the app implement a transport callback: authenticating the bytes is all the cryptography needs, and a callback across the language boundary adds complexity without adding security.
