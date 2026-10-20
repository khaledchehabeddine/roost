# Commit Conditions

Operations from the app and its extensions can run at once on the same records. So each result lists a Commit Condition for every record the operation read, including one it found absent, and the app commits only if Roost's check finds them all unchanged. A stale operation then can't overwrite another's work, and a send can't commit after its contact was blocked.

## Alternatives

- Check only the records an operation writes: a send could still commit after another operation blocked its contact.
