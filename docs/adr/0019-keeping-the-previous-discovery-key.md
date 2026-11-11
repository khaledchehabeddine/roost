# Keeping the Previous Discovery Key

Roost keeps a few previous discovery keys, only to open established messages the relay still holds from before an inbox rotation. Blocks still hold, because the relay stops admitting messages sent with the old delivery capability. The cost is that a stolen previous key exposes the outer layer of those messages, but not their sender or content.

## Alternatives

- Delete the old key and rely on recovery: every contact with queued messages would need a new session to resend them.
- Also keep the old prekeys: the relay deletes queued first messages when the inbox rotates.
