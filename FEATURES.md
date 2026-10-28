# Features

This list describes what Roost does today. Each feature gets one to three sentences.

## Roost and the App

- **No networking or logging.** Roost does no networking and logs nothing. The app sends the Messages Roost returns over its own transport.
- **Key storage.** Roost keeps the Identity's private keys and prekeys in the app's SecureStorage, such as Keychain or Keystore.
- **Protocol state.** The app stores all other protocol state as Protocol State Blobs, which hold secrets and need the same protection as keys. Roost keeps no copy between operations and never resets a blob it can't decode.
- **Operations and commits.** Each attempt to send or receive a Message is a Message Operation, which reads the records it needs from the app. The app commits the result in one transaction, only if none of those records changed. Until then, the result is provisional, so the app shows and sends nothing.
- **Interrupted key changes.** Roost stages each key change in SecureStorage until the app commits its own state. After a crash or an unknown commit outcome, the app finalizes each change it committed and aborts the rest. Until it does, Roost refuses every call that uses the Identity's keys.
- **One Identity Lock.** The app and its extensions can each run Roost for the same Identity. The app holds one Identity Lock across all of them, from an operation's first call until its commit resolves.
- **Settings.** Roost stores no settings. The app passes them each time it receives a Message: the Deduplication Set's size, whether blocked contacts get acknowledgments, and the certificate grace window.
- **Time.** Roost reads the system clock only to manage its own keys, such as checking prekey age. Certificate checks and Delivery Checks use the time the app passes.
- **Size limits.** A Message holds up to about 64 KiB of content. Roost refuses oversized Messages, Protocol State Blobs, and Sender Certificates, and refuses to grow skipped Message keys or Pending Acknowledgments past their limits. Lists of recent items, such as the Deduplication Set and older Sessions, drop their oldest entry instead.

## Identity

- **Create and delete an Identity.** An Identity has a permanent Identity Key and a Discovery Key that changes with each Inbox Rotation. Deleting one removes Roost's keys, and the app deletes its protocol state in the same transaction.
- **Check key signatures.** Roost checks the key signatures in every prekey bundle and Inbox Grant it receives. It also exports the check that a Discovery Key signed an Identity Key, for the app to run when it adds a contact by Discovery Key. Roost can't run that check itself, because it never sees the key the user entered.
- **Sign authentication transcripts.** Roost signs the app's authentication transcript with the Identity Key. It refuses any transcript that starts with the prefix Roost reserves for its own signatures.

## Inbox

- **Publish the inbox.** Roost returns the current Discovery Key, its signature over the Identity Key, and the signed prekey for the app to publish. It also returns a verifier for the Delivery Capability, so the app never publishes the capability itself.
- **Rotate signed prekeys.** At each launch, the app asks Roost to create a signed prekey if there is none or the current one is stale. A new Identity can't publish until this first call. Roost opens a First Message sent to a replaced signed prekey only after the app confirms the Message arrived before the rotation.
- **Refill one-time prekeys.** When the app asks, Roost refills the one-time prekey pool once it runs low. A First Message that names a one-time prekey uses it up in the same commit. Roost refuses any later First Message that names it.
- **Rotate the inbox.** An Inbox Rotation replaces the Discovery Key, signed prekey, and Delivery Capability, and clears the one-time prekeys. Roost keeps recent Previous Discovery Keys to open Established Messages sent to the old inbox. It can't open First Messages sent there, which include a requester's Messages until this side accepts them.
- **Share the Inbox Grant.** Roost attaches the current Inbox Grant to each Message it sends a contact, until the contact acknowledges one that carried it. It never sends the grant to a blocked contact or to a Requester the app hasn't accepted.
- **Send Grant Updates.** After an Inbox Rotation, the app sends each contact a Grant Update with the new Inbox Grant. Roost refuses one for a blocked contact or a Requester the app hasn't accepted. It returns nothing to send for a contact that already acknowledged the grant.

## Contacts

- **Request and accept contacts.** Roost treats a contact as accepted only when both sides consent: one sends a Contact Request and the other accepts it, or two requests cross. Before acceptance, each side can send only a few Messages, and Roost withholds the plaintext of any past that limit.
- **Read contacts.** Roost decodes the contact records the app finds by their Protocol State Kind. It has no subscriptions, so the app watches its own database for changes. A record doesn't show who sent a Contact Request, so the app remembers incoming requests itself.
- **Verify contacts.** A contact's Trust State is pending, accepted but unverified, or verified. It stays the same through the contact's Inbox Rotations. Roost marks a contact verified only when the Safety Number the app passes matches the one Roost derives from both Identity Keys.
- **Block contacts.** The app can block any contact, even a stranger, without losing their Trust State or Sessions. Roost then refuses to send them anything and hides the plaintext of their Messages that arrive during the block. Blocking also rotates the inbox, which replaces the Delivery Capability they hold.
- **Unblock contacts.** After an unblock, the kept Sessions work again. Because the block rotated the inbox, a requester reaches this side again only after this side accepts them. The first Message needs the contact's prekey bundle, and if it shows a newer Discovery Key, Roost starts a new Session from it.
- **Delete requests and contacts.** Roost has no delete call. The app hides the request or contact but keeps its record, so any block stays in place.

## Messages

- **Encrypt and decrypt Messages.** X3DH starts a Session from the peer's Discovery Key and prekeys. The Double Ratchet then gives every Message its own key.
- **Fetch prekey bundles.** If Roost needs a peer's prekey bundle to send a Message, it ends the attempt and asks the app for one. The app fetches the bundle outside the Identity Lock and starts a new attempt with the same draft.
- **Choose Sessions.** Roost picks the Session each Message goes out on. It keeps a few older Sessions open for Messages already on their way. It remembers recently deleted Sessions, so a replayed First Message can't revive them.
- **Hide the sender.** Every Message, including acknowledgments, travels in the Sealed Sender Frame, which shows only what routing needs. Roost pads the content to the next power-of-two size.
- **Authenticate the sender.** A First Message proves its sender holds their Identity Key, with a proof only the recipient can check. Each Established Message carries the sender's signature over its Message Transcript.
- **Check Sender Certificates.** Roost checks the Sender Certificate of every Message it opens against the trusted domain keys, Relay Domain, revoked Identity Keys, and time the app passes. It refuses the certificate when the app reports its revocation data as unavailable.
- **Route Messages.** Before sealing a Message, Roost returns its Message Destination. The app then supplies a Transport Binding that reaches it. Roost authenticates the binding but leaves it outside the Message, so the recipient's app passes the same bytes when it receives the Message.
- **Identify Messages.** Roost gives each draft a random MessageID that stays the same on every attempt, including a Recovery. Roost returns each resent copy, so the recipient's app shows one Message per sender and MessageID.
- **Drop repeated deliveries.** Roost drops a recent repeat of a received Message before it reaches the Session.

## Delivery

- **Acknowledge Messages.** Receiving a Message can return an encrypted Acknowledgment Artifact, which the app sends back to the sender. Before acceptance, only the Asked Side acknowledges, and only after it has replied.
- **Check delivery.** Roost tracks each Message sent to an accepted contact until the contact acknowledges it. The app runs a Delivery Check for each contact instead of resending on a timer. The check signals a Recovery when a Message other than a Grant Update goes a day without an acknowledgment, or when the contact sends a newer Inbox Grant or delivers on a newer Session.
- **Resend unacknowledged Messages.** A Recovery encrypts the app's copy of each unacknowledged Message again, except Grant Updates, on a newer Session. The app sends the new copy in place of the old one. When the Recovery has to start that Session, it returns the oldest Message first as the Probe and holds the rest until the contact acknowledges the Probe.
- **Report undelivered Messages.** Roost reports a Message as not delivered once 30 days pass without an acknowledgment, or once Roost deletes the Session it waits on.

## Backup and Restore

- **Back up and restore an Identity.** A passphrase-encrypted Identity Backup moves the Identity Key and current Discovery Key to a new Device. Contacts see the restored Identity as the same one. The app restores only the contact records from its own database backup, with their Trust State and blocks.
- **Reconnect contacts after a restore.** The restored Identity publishes no prekeys until its next Inbox Rotation. After that rotation, the app sends each accepted contact a Grant Update, which starts a new Session with them.
- **Accept requests after a restore.** Accepting a request the backup kept sends a new Contact Request, which accepts both sides. Roost refuses it for a blocked contact or one that never wrote. The app accepts only a request it knows the contact sent.

## Algorithms and Packages

- **Standard algorithms.** Roost uses standard algorithms from established libraries, such as X25519, Ed25519, XChaCha20-Poly1305, HKDF, BLAKE3, and Argon2id. Its own protocol code, including X3DH, the Double Ratchet, and the Sealed Sender Frame, hasn't had an independent review.
- **Swift and Kotlin packages.** Pushing a version tag publishes a Swift package and a Maven AAR. Neither carries a signature, but the Swift package pins its XCFramework by checksum. Both run only on arm64, so Intel simulators and x86 emulators can't load them.

## What Roost Doesn't Protect

- **A compromised Device.** Malware or a compromised operating system can read the keys and plaintext on a Device.
- **Message metadata.** Each frame shows the recipient's Discovery Key and the Message's padded size, and a First Message's frame also shows which prekeys it uses. Roost doesn't hide when Messages are sent, or anything the app's transport adds, such as IP addresses.
- **A leaked Discovery Key.** Anyone with a Discovery Key's private key can read the SessionID, MessageID, send time, kind, and ratchet counters of recorded Messages sealed to it, but not their sender or content. They can also sign fake prekeys, which a peer accepts until it learns a newer Discovery Key. Whoever gets a peer to use those prekeys could read Messages on the Sessions started from them.
- **Deniability.** Each Established Message carries the sender's signature, so a recipient running modified code could keep proof of who wrote it. Roost doesn't return the signature to the app.
