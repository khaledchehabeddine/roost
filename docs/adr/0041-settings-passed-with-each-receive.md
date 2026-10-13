# Settings Passed With Each Receive

The app and its extensions each create their own Identity Context, so a setting held in a context goes stale when the app changes it, and an extension could send a receipt to a blocked contact after the user turned receipts off. So Roost holds no settings, and the app passes the Deduplication Set's size, the blocked-contact receipt choice, and the certificate grace window with each receive, while Roost enforces their limits. The app decides where each value comes from, such as its own settings or its Relay.

## Alternatives

- Keep settings in the Identity Context and check a settings revision at commit: every result would carry a number whose only job is catching stale contexts, and the app would rebuild contexts to clear it.
