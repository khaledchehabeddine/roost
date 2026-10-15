# Restarting After a Prekey Fetch

Starting a Session needs the peer's prekey bundle from the network, and the app must not hold its identity lock during a fetch, so an attempt that needs a bundle, including a send to an accepted contact whose Session records are missing, ends by asking for one, and the app restarts with the same draft and the bundle. The restart reads fresh state and checks the bundle against the contact, so a stale bundle asks again, a request from the peer that arrived meanwhile turns the attempt into an acceptance, and an acceptance from the peer turns it into an ordinary Message. The app's draft keeps one MessageID across attempts and keeps the fetched bundle until a Session uses it, so a crash neither changes the Message's identity nor claims a second one-time prekey.

## Alternatives

- Keep the attempt open while the app fetches: it would hold plaintext and stale reads across a network call.
- Have the app always fetch before a request: recovery also needs Roost to ask for a bundle, so apps would handle two patterns.
- Fail a send whose Session records are missing: the contact would stay unreachable until someone repaired the data, and the commit already fails if the records exist after all.
