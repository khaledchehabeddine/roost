# Features

This list describes what Roost does today. Each feature gets one to three sentences.

## Identity

- **Create and delete an identity.** An identity has a permanent identity key and a discovery key that changes with each inbox rotation. Roost keeps their private keys and the prekeys in the app's SecureStorage, such as Keychain or Keystore. Deleting an identity removes its keys and prekeys from SecureStorage.
- **Check key signatures.** Roost checks the key signatures in every prekey bundle, inbox grant, and contact publication it receives. It also provides two standalone checks: that an identity key's signature ties its agreement key to its signing key, and that a discovery key signed an identity key.
- **Sign authentication transcripts.** Roost signs an authentication transcript with the identity key, so the app can prove it holds the key. It refuses any transcript that starts with the prefix Roost reserves for its own signatures.

## State and Commits

- **Share an identity across processes.** Roost keeps no protocol state or settings between calls, so the app and its extensions can each run Roost for the same identity. Roost needs them to share one identity lock.
- **Commit each operation as a whole.** Each attempt to send or receive a message is a message operation. Its result carries a commit condition for each record it read, which Roost checks during the app's commit. Nothing in the result takes effect until the app commits it.
- **Finish interrupted key changes.** Roost stages each key change in SecureStorage and applies it only when the app finalizes the change after committing its own state. After a crash or an unknown commit outcome, Roost lists every unfinished change for the app to finalize or abort. While a change the app reserved stays unfinished, Roost refuses every call that reads or changes the identity's keys.

## Inbox

- **Publish the inbox.** Roost returns the current discovery key, its signature over the identity key, and the signed prekey for the app to publish. It returns a public verifier for the delivery capability, never the capability itself.
- **Rotate signed prekeys.** When the app asks, Roost creates a signed prekey if there is none or the current one is a week old. A new identity has no signed prekey, so Roost returns no publication until the app finalizes the first one. Roost opens a first message sent to a replaced signed prekey only after the app confirms the relay admitted that message against that prekey.
- **Refill one-time prekeys.** When the app asks, Roost refills the one-time prekey pool once it runs low, or creates an exact number of prekeys. A first message that names a one-time prekey uses it up in the same commit. Roost refuses a different first message that names it later, and treats a repeat of the same one as a duplicate.
- **Rotate the inbox.** An inbox rotation replaces the discovery key, signed prekey, and delivery capability, and clears the one-time prekeys. Roost keeps recent previous discovery keys to open established messages sent to the old inbox. It can't open first messages sent there, which include a requester's messages until this side accepts them.
- **Share the inbox grant.** Roost attaches the current inbox grant to each message it sends a contact, until the contact acknowledges one that carried it. Roost attaches it again after the contact starts a new session, and once a recovery starts resending to the contact. It never sends the grant to a blocked contact or to a requester this side hasn't accepted.
- **Send grant updates.** A grant update carries only the current inbox grant, so Roost returns nothing to show when one arrives. Roost refuses one for a blocked contact or a requester this side hasn't accepted. It returns nothing to send for a contact that already acknowledged the grant.

## Contacts

- **Share contact links.** Roost encodes the contact publication a contact link carries, which holds no inbox grant, and decodes it with every signature checked and nothing recorded. It reports a newer format apart from damaged bytes, so the app can ask the user to update. It also tells whether a link's discovery key is newer than a contact's, so the app fetches a bundle only for a newer one.
- **Request and accept contacts.** Roost treats a contact as accepted only when both sides consent, either when one side accepts the other's contact request, when two requests cross, or when this side sends a requester a message through their newer prekey bundle. Before acceptance, Roost refuses to send a contact more than a few messages. It withholds the plaintext of any message it receives past that limit.
- **Read contacts.** Roost decodes a contact record into the contact's identity key, discovery key, trust state, and whether this side blocked them. A decoded record doesn't show which side sent the contact request.
- **Verify contacts.** A contact's trust state is pending, accepted but unverified, or verified. It stays the same through the contact's inbox rotations. Roost marks an accepted contact verified only when the safety number the app passes matches the one Roost derives from both identity keys.
- **Block contacts.** Blocking a contact, even a stranger, rotates the inbox but keeps their trust state and sessions. Roost then sends them nothing and hides the plaintext of their messages. It acknowledges those messages only when the app asks.
- **Unblock contacts.** After an unblock, the kept sessions work again. Because the block rotated the inbox, a requester reaches this side again only through a new session from this side's new prekey bundle. The first send after an unblock needs the contact's prekey bundle, which starts a new session if it shows a newer discovery key.

## Messages

- **Encrypt and decrypt messages.** X3DH starts a session from the peer's discovery key and prekeys. The Double Ratchet then gives every message its own key.
- **Choose sessions.** Roost picks the session each message goes out on. It keeps a few older sessions open for messages already on their way. It remembers recently deleted sessions, so a replayed first message can't revive them.
- **Ask for prekey bundles.** If Roost needs a peer's prekey bundle to send a message, it ends the attempt and asks the app for one. Roost uses the bundle on the next attempt with the same draft.
- **Bind messages to their route.** Before sealing a message, Roost returns its message destination and asks for a transport binding that reaches it. Roost authenticates the binding with the message but never stores or sends it. Opening the message needs the same binding.
- **Identify messages.** Roost creates a random message ID for each draft. A recovery resends a message under its original message ID. On receive, Roost returns a resent copy like any other message, with the original message ID.
- **Drop repeated deliveries.** Roost drops a recent repeat of a received message before it reaches the session.
- **Limit resource use.** A message holds up to about 64 KiB of content. Roost refuses oversized messages, protocol state blobs, and sender certificates, and refuses to keep more keys for out-of-order messages or more pending acknowledgments than its limits allow. Lists of recent items, such as the deduplication set and older sessions, drop their oldest entry instead.

## Sealed Sender

- **Hide the sender.** Every message, including acknowledgments, travels in the sealed sender frame, which shows only what routing needs. Roost pads the content to the next power-of-two size.
- **Authenticate the sender.** A first message proves its sender holds their identity key, with a proof only the recipient can check. Each established message carries the sender's signature over its message transcript.
- **Check sender certificates.** Roost checks the sender certificate of every message it opens against the trusted domain keys, relay domain, revoked identity keys, time, and expiry grace window of up to 5 minutes that the app passes. It refuses the certificate when the app reports its revocation data as unavailable. Roost also runs this check on any sender certificate the app passes.

## Delivery

- **Acknowledge messages.** Receiving a message can return an encrypted acknowledgment artifact for the sender. Before acceptance, only the asked side acknowledges, and only after it has replied. Without the sender's delivery capability, Roost returns the message with no acknowledgment.
- **Check delivery.** Roost tracks each message sent to an accepted contact until the contact acknowledges it. A delivery check takes the current time from the app and says whether the contact's unacknowledged messages need a recovery. It signals one when a message other than a grant update has waited a day, waits on a session older than one the contact has since delivered on, or went to an inbox older than the contact's latest inbox grant.
- **Resend unacknowledged messages.** A recovery encrypts the app's copy of each unacknowledged message other than a grant update again on a newer session. Each new copy replaces the old one and keeps its message ID and send time. When the recovery has to start that session, it returns the oldest message first as the probe and holds the rest until the contact acknowledges the probe or delivers on another session.
- **Report undelivered messages.** Roost reports a message as not delivered once 30 days pass after its first send without an acknowledgment, or once Roost deletes the session it waits on, unless a recovery moves it to a newer session. A restore leaves Roost no record of messages sent before it, and neither does losing a session's pending acknowledgments, so Roost never reports those messages.

## Backup and Restore

- **Back up and restore an identity.** A passphrase-encrypted identity backup moves the identity key and current discovery key to a new device. Contacts see the restored identity as the same one. After a restore, Roost works from the contact records alone, with their trust state and blocks.
- **Reconnect contacts after a restore.** Roost returns no publication and creates no prekeys for the restored identity until its next inbox rotation. After that rotation, a grant update or message to an accepted contact starts a new session. A contact this side asked that hasn't accepted needs a new contact request, which restarts the count of messages before acceptance.
- **Accept contact requests after a restore.** Accepting a request the backup kept sends a new contact request, which accepts both sides. Roost refuses it for a blocked contact or one that never wrote. Because a record doesn't show which side asked, Roost allows it for any other contact that wrote.

## Algorithms and Packages

- **Use standard algorithms.** Roost uses standard algorithms from established libraries, such as X25519, Ed25519, XChaCha20-Poly1305, HKDF, BLAKE3, and Argon2id.
- **Ship Swift and Kotlin packages.** Each release ships a Swift package and a Maven package for Android, both built for arm64 only. The Swift package pins its XCFramework by checksum.
