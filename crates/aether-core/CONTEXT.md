# Core

The orchestration layer that exposes high-level entities — Sessions, Identities, Devices, Messages — and coordinates their lifecycle on top of the primitives in `aether-crypto`.

## Language

{For each term: bold the name with optional cardinality in parentheses, write a one or two sentence definition of what it IS, list aliases to avoid.}

**Device** (one or more per Identity):
A specific installation that holds private key material for an Identity. Different Devices under one Identity may receive different copies of the same Session's Messages.
Avoid: client, installation, instance

**Identity** (one or more Devices):
A long-lived public-key persona that one or more Devices share. Identifies a participant across Sessions.
Avoid: user, account, profile

**Message** (many per Session):
A single ciphertext packet exchanged within a Session, addressed by `MessageID`.
Avoid: payload, packet

**Session** (between two Identities):
An ongoing encrypted channel between two Identities, advanced by the Double Ratchet, identified by `SessionID`.
Avoid: connection, conversation, chat

## Example

{A short dialogue between a dev and a domain expert that uses the terms naturally and surfaces boundaries between related concepts.}

**Dev:** When Alice adds her tablet, do we create a new Session?

**Domain expert:** No. The Session is anchored to the Identity pair, not the Devices. Alice's tablet is another Device under her Identity. The Session keeps going. The new Device picks up Messages from wherever it joined.

**Dev:** So all of Alice's Devices see the same Message stream?

**Domain expert:** Logically yes, but each Device decrypts independently. The Identity is the addressing unit; the Device is the decryption unit. Two Devices under one Identity can be at different positions in the ratchet.

## Flagged Ambiguities

{For each ambiguity: bold the conflicting term(s), state the conflict, give the resolution. Use "None currently." when empty.}

**Session** (cryptographic) vs **session** (app login state): The cryptographic Session is the Double Ratchet state between two Identities. A lowercase "session" in host-app context is the user's logged-in state in the surrounding application. These are unrelated. Reserve capitalized `Session` for the cryptographic concept.
