# Settings Passed With Each Receive

The app and its extensions each create their own Identity Context, so a setting held in a context goes stale when the app changes it. An extension could then acknowledge a blocked contact's Message after the user turned those acknowledgments off. So Roost holds no settings, and the app passes the Deduplication Set's size, the blocked-contact acknowledgment choice, and the certificate grace window with each receive, within limits Roost enforces.

## Alternatives

- Keep settings in the Identity Context and check a settings revision at commit: every result would carry a number whose only job is catching stale contexts, and the app would rebuild contexts to clear it.
