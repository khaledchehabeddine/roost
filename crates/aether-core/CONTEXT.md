# Core

The orchestration layer that exposes high-level entities — Sessions, Identities, Devices, Messages — and coordinates their lifecycle on top of the primitives in `aether-crypto`.

## Language

**Device** (exactly one per Identity):
The app install that holds the private key material for an Identity. A new Device starts a new Identity unless the user restores an Identity backup onto it.
Avoid: client, installation, instance

**Identity** (exactly one Device):
A long-lived public-key persona held by a single Device. Identifies a participant across Sessions.
Avoid: user, account, profile

**Message** (many per Session):
A single ciphertext packet exchanged within a Session, addressed by `MessageID`.
Avoid: payload, packet

**Session** (between two Identities):
An ongoing encrypted channel between two Identities, advanced by the Double Ratchet, identified by `SessionID`.
Avoid: connection, conversation, chat

## Example

**Dev:** If a user reinstalls the app, do they keep their Identity?

**Domain expert:** No — Identity is bound to private key material held on the Device. A fresh install starts a new Identity unless the user restores from an Identity backup, which re-creates the Identity on the new install.

**Dev:** Then why distinguish Identity from Device at all in the MVP?

**Domain expert:** Identity is the addressing unit — Sessions pair two Identities and sender certificates bind to Identity keys. Device is the persistence unit — it owns the private material in platform secure storage. Even at one-to-one, separating them keeps Session establishment, sender certificates, and Identity backup independent of where the bytes physically live.

## Flagged Ambiguities

**Session** (cryptographic) vs **session** (app login state): The cryptographic Session is the Double Ratchet state between two Identities; the lowercase host-app "session" is the user's logged-in state. Reserve capitalized `Session` for the cryptographic concept.
