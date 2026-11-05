# Features

This list describes what Roost does today. Each feature gets one to three sentences.

## Identity

- **Create and delete an Identity.** An Identity has a permanent Identity Key and a Discovery Key that changes with each Inbox Rotation. Roost keeps their private keys and the prekeys in the app's SecureStorage, such as Keychain or Keystore. Deleting an Identity removes its keys and prekeys from SecureStorage.
- **Check key signatures.** Roost checks the key signatures in every prekey bundle, Inbox Grant, and Contact Publication it receives. It also provides two standalone checks: that an Identity Key's signature ties its agreement key to its signing key, and that a Discovery Key signed an Identity Key.
- **Sign authentication transcripts.** Roost signs an authentication transcript with the Identity Key, so the app can prove it holds the key. It refuses any transcript that starts with the prefix Roost reserves for its own signatures.

## State and Commits

- **Share an Identity across processes.** Roost keeps no protocol state or settings between calls, so the app and its extensions can each run Roost for the same Identity. Roost needs them to share one Identity Lock.
- **Commit each operation as a whole.** Each attempt to send or receive a Message is a Message Operation. Its result carries a Commit Condition for each record it read, which Roost checks during the app's commit. Nothing in the result takes effect until the app commits it.
- **Finish interrupted key changes.** Roost stages each key change in SecureStorage and applies it only when the app finalizes the change after committing its own state. After a crash or an unknown commit outcome, Roost lists every unfinished change for the app to finalize or abort. While a change the app reserved stays unfinished, Roost refuses every call that reads or changes the Identity's keys.

## Inbox

- **Publish the inbox.** Roost returns the current Discovery Key, its signature over the Identity Key, and the signed prekey for the app to publish. It returns a public verifier for the Delivery Capability, never the capability itself.
- **Rotate signed prekeys.** When the app asks, Roost creates a signed prekey if there is none or the current one is a week old. A new Identity has no signed prekey, so Roost returns no publication until the app finalizes the first one. Roost opens a First Message sent to a replaced signed prekey only after the app confirms the Relay admitted that Message against that prekey.
- **Refill one-time prekeys.** When the app asks, Roost refills the one-time prekey pool once it runs low, or creates an exact number of prekeys. A First Message that names a one-time prekey uses it up in the same commit. Roost refuses a different First Message that names it later, and treats a repeat of the same one as a duplicate.
- **Rotate the inbox.** An Inbox Rotation replaces the Discovery Key, signed prekey, and Delivery Capability, and clears the one-time prekeys. Roost keeps recent Previous Discovery Keys to open Established Messages sent to the old inbox. It can't open First Messages sent there, which include a Requester's Messages until this side accepts them.
- **Share the Inbox Grant.** Roost attaches the current Inbox Grant to each Message it sends a contact, until the contact acknowledges one that carried it. Roost attaches it again after the contact starts a new Session, and once a Recovery starts resending to the contact. It never sends the grant to a blocked contact or to a Requester this side hasn't accepted.
- **Send Grant Updates.** A Grant Update carries only the current Inbox Grant, so Roost returns nothing to show when one arrives. Roost refuses one for a blocked contact or a Requester this side hasn't accepted. It returns nothing to send for a contact that already acknowledged the grant.

## Contacts

- **Share contact links.** Roost encodes the Contact Publication a contact link carries, which holds no Inbox Grant, and decodes it with every signature checked and nothing recorded. It reports a newer format apart from damaged bytes, so the app can ask the user to update. It also tells whether a link's Discovery Key is newer than a contact's, so the app fetches a bundle only for a newer one.
- **Request and accept contacts.** Roost treats a contact as accepted only when both sides consent, either when one side accepts the other's Contact Request, when two requests cross, or when this side sends a Requester a Message through their newer prekey bundle. Before acceptance, Roost refuses to send a contact more than a few Messages. It withholds the plaintext of any Message it receives past that limit.
- **Read contacts.** Roost decodes a contact record into the contact's Identity Key, Discovery Key, Trust State, and whether this side blocked them. A decoded record doesn't show which side sent the Contact Request.
- **Verify contacts.** A contact's Trust State is pending, accepted but unverified, or verified. It stays the same through the contact's Inbox Rotations. Roost marks an accepted contact verified only when the Safety Number the app passes matches the one Roost derives from both Identity Keys.
- **Block contacts.** Blocking a contact, even a stranger, rotates the inbox but keeps their Trust State and Sessions. Roost then sends them nothing and hides the plaintext of their Messages. It acknowledges those Messages only when the app asks.
- **Unblock contacts.** After an unblock, the kept Sessions work again. Because the block rotated the inbox, a Requester reaches this side again only through a new Session from this side's new prekey bundle. The first send after an unblock needs the contact's prekey bundle, which starts a new Session if it shows a newer Discovery Key.

## Messages

- **Encrypt and decrypt Messages.** X3DH starts a Session from the peer's Discovery Key and prekeys. The Double Ratchet then gives every Message its own key.
- **Choose Sessions.** Roost picks the Session each Message goes out on. It keeps a few older Sessions open for Messages already on their way. It remembers recently deleted Sessions, so a replayed First Message can't revive them.
- **Ask for prekey bundles.** If Roost needs a peer's prekey bundle to send a Message, it ends the attempt and asks the app for one. Roost uses the bundle on the next attempt with the same draft.
- **Bind Messages to their route.** Before sealing a Message, Roost returns its Message Destination and asks for a Transport Binding that reaches it. Roost authenticates the binding with the Message but never stores or sends it. Opening the Message needs the same binding.
- **Identify Messages.** Roost creates a random MessageID for each draft. A Recovery resends a Message under its original MessageID. On receive, Roost returns a resent copy like any other Message, with the original MessageID.
- **Drop repeated deliveries.** Roost drops a recent repeat of a received Message before it reaches the Session.
- **Limit resource use.** A Message holds up to about 64 KiB of content. Roost refuses oversized Messages, Protocol State Blobs, and Sender Certificates, and refuses to keep more keys for out-of-order Messages or more Pending Acknowledgments than its limits allow. Lists of recent items, such as the Deduplication Set and older Sessions, drop their oldest entry instead.

## Sealed Sender

- **Hide the sender.** Every Message, including acknowledgments, travels in the Sealed Sender Frame, which shows only what routing needs. Roost pads the content to the next power-of-two size.
- **Authenticate the sender.** A First Message proves its sender holds their Identity Key, with a proof only the recipient can check. Each Established Message carries the sender's signature over its Message Transcript.
- **Check Sender Certificates.** Roost checks the Sender Certificate of every Message it opens against the trusted domain keys, Relay Domain, revoked Identity Keys, and time the app passes. It refuses the certificate when the app reports its revocation data as unavailable. Roost also runs this check on any Sender Certificate the app passes.

## Delivery

- **Acknowledge Messages.** Receiving a Message can return an encrypted Acknowledgment Artifact for the sender. Before acceptance, only the Asked Side acknowledges, and only after it has replied. Without the sender's Delivery Capability, Roost returns the Message with no acknowledgment.
- **Check delivery.** Roost tracks each Message sent to an accepted contact until the contact acknowledges it. A Delivery Check takes the current time from the app and says whether the contact's unacknowledged Messages need a Recovery. It signals one when a Message other than a Grant Update has waited a day, waits on a Session older than one the contact has since delivered on, or went to an inbox older than the contact's latest Inbox Grant.
- **Resend unacknowledged Messages.** A Recovery encrypts the app's copy of each unacknowledged Message other than a Grant Update again on a newer Session. Each new copy replaces the old one and keeps its MessageID and send time. When the Recovery has to start that Session, it returns the oldest Message first as the Probe and holds the rest until the contact acknowledges the Probe.
- **Report undelivered Messages.** Roost reports a Message as not delivered once 30 days pass without an acknowledgment, or once Roost deletes the Session it waits on, unless a Recovery moves it to a newer Session. A restore leaves Roost no record of Messages sent before it, so Roost never reports them.

## Backup and Restore

- **Back up and restore an Identity.** A passphrase-encrypted Identity Backup moves the Identity Key and current Discovery Key to a new Device. Contacts see the restored Identity as the same one. After a restore, Roost works from the contact records alone, with their Trust State and blocks.
- **Reconnect contacts after a restore.** Roost returns no publication and creates no prekeys for the restored Identity until its next Inbox Rotation. After that rotation, a Grant Update or Message to an accepted contact starts a new Session. A contact this side asked that hasn't accepted needs a new Contact Request, which restarts the count of Messages before acceptance.
- **Accept Contact Requests after a restore.** Accepting a request the backup kept sends a new Contact Request, which accepts both sides. Roost refuses it for a blocked contact or one that never wrote. Because a record doesn't show which side asked, Roost allows it for any other contact that wrote.

## Algorithms and Packages

- **Use standard algorithms.** Roost uses standard algorithms from established libraries, such as X25519, Ed25519, XChaCha20-Poly1305, HKDF, BLAKE3, and Argon2id.
- **Ship Swift and Kotlin packages.** Each release ships a Swift package and a Maven package for Android, both built for arm64 only. The Swift package pins its XCFramework by checksum.
