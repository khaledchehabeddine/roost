# Features

This list describes what Roost does today. Each feature gets one to three sentences.

## Identity

- **Create and delete an Identity.** An Identity has a permanent Identity Key and a Discovery Key that changes with each Inbox Rotation. Roost keeps their private keys in the app's SecureStorage, such as Keychain or Keystore.
- **Back up and restore.** A passphrase-encrypted Identity Backup restores the Identity Key and current Discovery Key onto a new Device. Contacts see the restored Identity as the same one. It publishes no prekeys until its next Inbox Rotation.
- **Reconnect contacts after a restore.** When the app restores its database from a backup, only the contact records remain, with their Trust State and blocks. The app then sends each contact a Grant Update, which starts a new Session. Neither side needs a new contact link.
- **Check key signatures.** Roost checks the signature that ties an Identity Key's two public keys together. It also checks a Discovery Key's signature over an Identity Key. When the app adds a contact by Discovery Key, this second check is its only protection against a Relay that answers with the wrong Identity.
- **Prove the Identity to the Relay.** Roost signs the app's own authentication transcript with the Identity Key, exactly as given. It refuses any transcript that starts with the prefix Roost reserves for its own signatures.
- **Finish interrupted key changes.** Roost stages each key change in SecureStorage until the app has committed its own state. After a crash, the app finalizes each unfinished change it committed and aborts the rest.
- **Share an Identity across processes.** The app and its extensions can each run Roost for the same Identity. They share one Identity Lock. A process holds it from an operation's first call until that operation's commit resolves, and while it finishes interrupted key changes.

## Prekeys and Inbox

- **Publish the inbox.** Roost returns the current Discovery Key and signed prekey for the app to publish together. It also returns a verifier for the inbox's Delivery Capability, which the app registers with the Relay in place of the capability itself.
- **Rotate signed prekeys.** At each launch, the app asks Roost to replace a stale signed prekey. Roost keeps a few old signed prekeys. It opens a First Message sent to an old one only after the app confirms that the Relay admitted the Message before the rotation.
- **Refill one-time prekeys.** Roost refills the one-time prekey pool when it runs low, or makes as many as the app asks for. A First Message that names a one-time prekey uses it up in the same commit. Roost refuses any later First Message that names it.
- **Rotate the inbox.** An Inbox Rotation replaces the Discovery Key, signed prekey, and Delivery Capability, and clears the one-time prekeys. Roost keeps each Previous Discovery Key to open Messages queued for it, until the Relay can no longer hold them. It still can't open a First Message queued for the old inbox, such as a Contact Request.
- **Share the Inbox Grant.** Roost attaches the current Inbox Grant to each Message it sends a contact, until the contact acknowledges one that carried it. It never sends the grant to a blocked contact or to a Requester the app hasn't accepted. It takes a contact's grant only from an authenticated Message.
- **Send Grant Updates.** After an Inbox Rotation, the app sends every contact a Grant Update with the new Inbox Grant. Roost refuses one for any contact it withholds the grant from. It returns nothing to send for a contact that already acknowledged the current grant.

## Contacts

- **Request and accept contacts.** Roost treats a contact as accepted only when both sides consent. Two Contact Requests that cross count as consent from both. Before acceptance, Roost limits each side to a few Messages and withholds the plaintext of any past that limit.
- **Accept requests after a restore.** Accepting a request that the backup kept sends a new Contact Request, which accepts both sides. Roost refuses the acceptance only for a contact that never wrote. The app must accept only a request that the contact sent.
- **Verify contacts.** A contact's Trust State is pending, accepted but unverified, or verified. It stays with the contact's Identity Key through their Inbox Rotations. Roost marks an accepted contact verified only when the Safety Number the app passes matches the one Roost derives from both Identity Keys.
- **Read contacts.** Roost decodes the contact records that the app finds by their Protocol State Kind. Roost has no subscriptions. The app watches its own database for changes instead.
- **Block contacts.** The app can block any contact, even a stranger, without losing their Trust State or Sessions. Roost then refuses to send them new Messages and never returns the plaintext of Messages they send while blocked. Blocking also rotates the inbox, which stops the Delivery Capability they hold from working at the Relay.
- **Unblock contacts.** After an unblock, the kept Sessions work again. The first Message after an unblock needs the contact's prekey bundle, which shows whether their Discovery Key is still current. If the contact rotated their inbox during the block, only a fresh contact link reconnects them.
- **Delete requests and contacts.** Roost has no delete call. The app hides the request or contact but keeps its record. Any block then stays in place.

## Messages

- **Encrypt and decrypt Messages.** Each attempt to send or receive a Message is a Message Operation, which asks the app for the stored records it needs. The app commits the operation's result in one transaction only if no record the operation read has changed.
- **Fetch prekey bundles.** If Roost needs a peer's prekey bundle to send a Message, it ends the attempt and asks the app for one. The app fetches the bundle outside the Identity Lock and starts a new attempt with the same draft.
- **Identify Messages.** Roost gives each draft a random MessageID, which the app reuses on every attempt. The recipient's app shows one Message per sender and MessageID, even when a repeated attempt or a Recovery sends it again.
- **Start Sessions.** X3DH starts a Session from the peer's Discovery Key and prekeys. The Double Ratchet then gives every Message its own key.
- **Choose Sessions.** Roost picks the Session each Message goes out on. It keeps a few older Sessions open for Messages already on their way. It never revives a deleted Session.
- **Hide the sender.** Every Message, including acknowledgments, travels in the Sealed Sender Frame, which shows only what routing needs. The sender and content stay encrypted. Roost pads the content to one of a few fixed sizes.
- **Authenticate the sender.** A First Message proves its sender holds their Identity Key, with a proof only the recipient can check. Each Established Message carries the sender's signature over its Message Transcript. The sender can't later deny writing it.
- **Route Messages.** Before sealing a Message, Roost returns its Message Destination. The app then supplies a Transport Binding that reaches that destination. Roost authenticates the binding's exact bytes but never reads or stores them.
- **Drop repeated deliveries.** Roost checks each received Message against the Deduplication Set before decrypting it. A recent repeat never reaches the Session.

## Delivery

- **Acknowledge Messages.** Receiving a Message can return an encrypted Acknowledgment Artifact, which the app sends back to the sender. Before acceptance, only the Asked Side acknowledges, and only after it has replied.
- **Check delivery.** The Relay holds each Message until the contact saves it. The app runs a Delivery Check for each contact instead of resending on a timer. The check signals a Recovery when a Message goes a day without an acknowledgment, or when the contact sends a newer Inbox Grant or delivers on a newer Session.
- **Resend unacknowledged Messages.** A Recovery encrypts the app's copy of each unacknowledged Message again, on a Session newer than the one it went out on. When the Recovery has to start that Session, it sends the oldest Message first as the Probe and holds the rest until the contact acknowledges the Probe.
- **Report undelivered Messages.** Roost reports a Message as not delivered once the Relay would have dropped it, or once Roost deletes its Session.

## Certificates and Limits

- **Check Sender Certificates.** Roost checks the Sender Certificate of every received Message against what the app passes: trusted domain keys, the expected Relay Domain, revoked Identity Keys, the current time, and a grace window. It refuses the certificate when the app reports its revocation data as unavailable.
- **Limit resource use.** Roost refuses Messages, Protocol State Blobs, and Sender Certificates over a size limit. It also refuses to grow skipped Message keys or Pending Acknowledgments past their limits. Lists of recent items, such as the Deduplication Set and older Sessions, drop their oldest entry instead.

## What Roost Leaves to the App

- **Networking and logging.** Roost does no networking and logs nothing. The app sends the Messages Roost returns over its own transport, with its own retries and authentication.
- **Protocol state.** Roost keeps no protocol state between operations. The app stores it all as Protocol State Blobs, which hold secrets and need the same protection as keys. Roost treats a blob it can't decode as an error and never resets it.
- **Settings.** Roost holds no settings. The app passes them each time it receives a Message: the Deduplication Set's size, whether blocked contacts get acknowledgments, and the certificate grace window.
- **Time.** Roost reads the system clock only to manage its own keys, such as checking prekey age and dating each new Discovery Key. Certificate checks and Delivery Checks use the time the app passes.

## Algorithms and Packages

- **Standard algorithms.** Roost uses standard algorithms from established libraries, such as X25519, Ed25519, XChaCha20-Poly1305, HKDF, BLAKE3, and Argon2id. Its own protocol code, including X3DH, the Double Ratchet, and the Sealed Sender Frame, still needs an independent review.
- **Swift and Kotlin packages.** Pushing a version tag publishes a Swift package and a Maven AAR. Neither carries a signature. The Swift package pins its XCFramework by checksum.

## What Roost Doesn't Protect

- **A compromised Device.** Malware or a compromised operating system can read the keys and plaintext on a Device.
- **Relay metadata.** The Relay sees when Messages arrive, their padded size, which inbox each goes to, and which prekeys each First Message uses. The app's transport decides what else the Relay learns, such as IP addresses.
- **A leaked Discovery Key.** Anyone with a Discovery Key's private key can read the SessionID, MessageID, send time, and kind of recorded Messages sealed to it, but not their sender or content. Until the next Inbox Rotation, they can also sign fake prekeys. A Relay that serves those prekeys could read Messages on new Sessions started against them.
