# Opaque Transport Bindings

Every Message Roost seals or opens takes a Transport Binding, and the Sealed Sender Frame authenticates the binding's exact bytes. The app owns those bytes, and Roost never parses, sends, or stores them, so Roost guarantees they arrive unchanged but says nothing about their meaning. Roost finds a first Message's prekeys from the public keys its frame names, and reports their prekey IDs in its destination, so neither direction parses the app's transport format.

## Alternatives

- Define the Relay's routing format in Roost: Roost would be tied to one transport and its versions.
- A transport callback the app implements: authenticating the bytes is all the cryptography needs, and a callback adds FFI complexity for no extra security.
