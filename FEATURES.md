# Features

What Roost does today. Planned work is in the [milestones](https://github.com/chirp-org/roost/milestones).

Each feature gets one or two sentences. When a feature needs more, the plan goes in an issue, the decision in an ADR, and the exact behavior in a test or doc comment.

## Identity

- **Create and delete an Identity.** An Identity has a permanent Identity Key and a Discovery Key that changes with each Inbox Rotation. Roost keeps their secret halves in the app's SecureStorage, such as Keychain or Keystore.
- **Back up and restore.** A passphrase-encrypted Identity Backup carries the Identity Key and current Discovery Key to a new Device, so contacts keep seeing the same Identity. The restored Identity publishes no prekeys until its next Inbox Rotation.
- **Reconnect after a restore.** A restore keeps the contact records the app's own backup brings back, with their Trust State and blocks, and drops all other protocol state. A Grant Update to each accepted contact then starts a new Session, so they reach the Identity again without a new contact link.
- **Check key bindings.** Roost checks the signature that ties an Identity Key's two halves together, and a Discovery Key's signature over an Identity Key. Adding a contact by Discovery Key is only as safe as the second check.
- **Sign for the Relay.** Roost signs the app's own authentication transcript with the Identity Key, exactly as given. It refuses any transcript that starts with the prefix Roost reserves for its own signatures.
- **Finish interrupted key changes.** Roost stages each key change in SecureStorage until the app has committed its own state. After a crash, the app finalizes or aborts each unfinished change, so keys and app state stay in step.
- **Share an Identity across processes.** The app and its extensions can each run Roost for the same Identity. They share one Identity Lock, which each process holds from an operation's first call until its commit resolves, and while it finishes or aborts interrupted key changes.

## Prekeys and inbox

- **Publish the inbox.** Roost returns the current Discovery Key and signed prekey for the app to publish together. It also returns a verifier for the inbox's Delivery Capability, which the app registers with the Relay instead of the capability itself.
- **Rotate signed prekeys.** At each launch, the app asks Roost to replace a stale signed prekey and delete Previous Discovery Keys the Relay can no longer hold Messages for. Roost keeps a few old signed prekeys, but opens a First Message sent to one only after the app confirms the Relay admitted that Message before the rotation.
- **Refill one-time prekeys.** When the app asks, Roost tops up the one-time prekey pool if it runs low, or makes a given number. A First Message that names one uses it up in the same commit, and Roost refuses it after that.
- **Rotate the inbox.** An Inbox Rotation replaces the Discovery Key, signed prekey, and Delivery Capability, and clears the one-time prekeys. Roost keeps Previous Discovery Keys for a while to open Messages already queued for them, but can't open a First Message queued for the old inbox, such as a Contact Request.
- **Share the Inbox Grant.** Roost attaches the current Inbox Grant to what it sends a contact until the contact acknowledges a Message that carried it. It never sends the grant to a blocked contact or a Requester the app hasn't accepted, and takes a contact's grant only from an authenticated Message.
- **Send Grant Updates.** After an Inbox Rotation, a Grant Update brings the new Inbox Grant to a contact that would otherwise get no Message. Roost refuses one to a blocked contact or a Requester the app hasn't accepted, and sends nothing to a contact that already acknowledged the current grant.

## Contacts

- **Request and accept.** A contact becomes accepted only when both sides consent, and crossing Contact Requests count as both consents. Before that, each side may send a few Messages, and Roost withholds the plaintext of any it receives past that limit.
- **Accept after a restore.** Accepting a request the backup kept sends a new Contact Request that accepts both sides. Roost can then check only that the contact wrote at all, so the app must accept only requests the contact sent.
- **Verify with Safety Numbers.** A contact's Trust State is pending, accepted but unverified, or verified, and it stays with their Identity Key through their Inbox Rotations. Roost marks an accepted contact verified only when the Safety Number the app passes matches the one Roost derives from both Identity Keys.
- **Read contacts.** The app finds its contact records by their Protocol State Kind and asks Roost to decode them. Roost has no subscriptions, so the app watches its own database for changes.
- **Block.** Blocking works at any Trust State, even for a stranger, and keeps the contact's Trust State and Sessions. Roost then refuses new Messages to the contact, never returns the plaintext of Messages they send while blocked, and rotates the inbox so the capability they hold stops working at the Relay.
- **Unblock and reconnect.** After an unblock, the first send checks that the contact's Discovery Key is still current, then continues on the kept Sessions. If the contact rotated their inbox without the new Inbox Grant arriving, only a fresh contact link reconnects them, on a new Session that keeps any acceptance or verification.
- **Delete a request or contact.** Roost has no delete call. The app hides the request or contact and keeps its record, so any block stays in place.

## Messages

- **Encrypt and decrypt.** Each attempt to send or receive a Message is a Message Operation that asks the app for the stored records it needs. It returns its result once, and the app commits that result in one transaction only if every record the operation read is unchanged.
- **Fetch prekey bundles on demand.** A send that needs a peer's prekey bundle ends and asks for one. The app fetches it outside the Identity Lock and starts the send again with the same draft.
- **Keep protocol state in the app.** The app stores all protocol state as Protocol State Blobs, which hold secrets and need the same protection as keys. Roost keeps no protocol state between operations, and treats a blob it can't decode as an error instead of resetting it.
- **Identify Messages.** Each draft gets a random MessageID that the app reuses on every attempt. The recipient's app shows one Message per sender and MessageID, so a repeated attempt or a resend after a Recovery appears once.
- **Start and choose Sessions.** X3DH starts a Session from the peer's Discovery Key and prekeys, and the Double Ratchet then gives every Message its own key. Roost picks which Session to send on, keeps a few older ones so Messages already on their way still open, and refuses to revive a deleted one.
- **Hide the sender.** Every Message, including acknowledgments, travels in the Sealed Sender Frame, which shows only what routing needs. The sender and content stay encrypted, and Roost pads the content to one of a few fixed sizes.
- **Authenticate the sender.** A First Message proves its sender holds their Identity Key, with a proof only the recipient can check. Each Established Message carries the sender's signature over its Message Transcript, so the sender can't later deny writing it.
- **Route with Transport Bindings.** Before sealing a Message, Roost names its Message Destination, so the app can supply a Transport Binding that reaches it. Roost authenticates the binding's exact bytes and never reads or stores them.
- **Drop repeated deliveries.** Roost recognizes a recent repeat of a received Message before decrypting it, so the repeat doesn't touch the Session. The app stores the Deduplication Set with its other protocol state and chooses its size.

## Delivery

- **Acknowledge.** Receiving a Message returns an encrypted Acknowledgment Artifact for the app to send back when the sender is due one. Before acceptance, only the Asked Side acknowledges, and only after it has replied.
- **Check delivery.** The Relay redelivers a Message until the contact saves it, so the app doesn't resend on a timer. Instead, a Delivery Check for each contact signals a Recovery when the contact stays quiet too long, sends a newer Inbox Grant, or delivers on a newer Session.
- **Recover.** A Recovery encrypts the app's copy of each unacknowledged Message again, on a Session newer than the one it went out on, and keeps its MessageID. When it has to start that Session, Roost resends the Probe first and the rest once the contact acknowledges the Probe.
- **Report undelivered Messages.** Roost reports a Message as not delivered once the Relay would have dropped it, or once its Session is deleted, so the app never waits forever.

## Certificates and limits

- **Validate Sender Certificates.** Roost checks the Sender Certificate of every received Message against what the app passes: trusted domain keys, the expected Relay Domain, revoked Identity Keys, the current time, and a short grace window. It refuses the certificate when the app marks its revocation data unavailable.
- **Cap resource use.** Roost refuses Messages, Protocol State Blobs, and Sender Certificates over a size cap, and refuses to grow skipped Message keys or Pending Acknowledgments past their limits. Lists of recent items, such as the Deduplication Set and older Sessions, drop their oldest entry instead.

## Boundaries

- **No networking or logging.** Roost does no networking and logs nothing. The app sends the Messages Roost returns over its own transport, with its own retries and authentication.
- **No stored settings.** Roost holds no settings, so none can go stale inside it. Each receive passes the Deduplication Set's size, whether blocked contacts get acknowledgments, and the certificate grace window.
- **Clock use.** Roost reads the device clock only to manage its own keys, such as aging prekeys and dating each new Discovery Key. Certificate checks and Delivery Checks use the time the app passes.
- **Standard algorithms.** Roost uses standard algorithms from established libraries, such as X25519, Ed25519, XChaCha20-Poly1305, HKDF, BLAKE3, and Argon2id. Its own protocol code, including X3DH, the Double Ratchet, and the Sealed Sender Frame, still needs an independent review.
- **Swift and Kotlin packages.** A version tag publishes a Swift package and a Maven AAR. Neither carries a signature, and the Swift package pins its XCFramework by checksum.

## What Roost doesn't protect

- **A compromised Device.** Malware or a compromised operating system can read the keys and plaintext on a Device.
- **Relay metadata.** The Relay sees when Messages arrive, their padded size, which inbox each goes to, and which prekeys each First Message uses. The app's transport decides what else it reveals, such as IP addresses.
- **A leaked Discovery Key.** Anyone with a Discovery Key's private key can read the SessionID, MessageID, send time, and kind of recorded Messages sealed to it, but not their sender or content. Until the next Inbox Rotation, they can also sign fake prekeys, and a Relay that serves those could read new Sessions started against them.
