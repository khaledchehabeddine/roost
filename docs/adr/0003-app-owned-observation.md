# App-Owned Observation

Roost has no subscriptions or change feeds. Apps watch their own database with their platform's tools and ask Roost to decode contact state from the stored blobs. Platform observers can merge several changes into one update, so work that must not be missed, such as sending an acknowledgment, runs from an operation's results instead.

## Alternatives

- An event stream per library instance: it adds work to keep each stream alive and in sync, and makes commits no safer.
