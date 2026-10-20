# Restarting After a Prekey Fetch

Starting a Session needs the peer's prekey bundle, and the app must not hold its Identity Lock while fetching it, so an attempt that needs one ends by asking for it. The app then restarts on fresh state, so a stale bundle asks again, and a request or acceptance the peer sent meanwhile turns the attempt into an acceptance or an ordinary Message. The draft keeps one MessageID and the fetched bundle until a Session uses it, so a crash neither changes the Message's identity nor claims a second one-time prekey.

## Alternatives

- Keep the attempt open while the app fetches: it would hold plaintext and stale reads across a network call.
- Have the app always fetch before a request: recovery also needs Roost to ask for a bundle, so apps would handle two patterns.
