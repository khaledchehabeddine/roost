# Keeping the Previous Discovery Key

The Relay keeps queued Messages through a rotation, so Roost keeps a few previous Discovery Keys while the Relay may hold Messages sealed to them, and uses them only to open those. A block still holds, because the Relay refuses the old capability once the new inbox is registered, and Roost hides a blocked contact's queued Messages. The cost is that a stolen Device exposes the outer layer of those Messages, but not their sender or content.

## Alternatives

- Delete the old key and rely on retries: a retry resends the same bytes, still sealed to the old key.
- Keep only the latest previous key: blocks close together would lose the Messages queued for the earlier keys.
- Also keep the old prekeys, so queued Contact Requests survive: the Relay deletes queued first Messages when it replaces the prekeys.
