# Keeping the Previous Discovery Key

The relay keeps queued established messages through an inbox rotation, so Roost keeps a few previous discovery keys while the relay may hold messages sealed to them, and uses them only to open those. A block still holds, because the relay drops messages sent with the old delivery capability once the new inbox is registered, and Roost hides a blocked contact's queued messages. The cost is that a stolen previous key exposes the outer layer of those messages, but not their sender or content.

## Alternatives

- Delete the old key and rely on recovery: every contact with messages queued for the old key would need a new session to resend them.
- Also keep the old prekeys, so queued contact requests survive: the relay deletes queued first messages when the inbox rotates.
