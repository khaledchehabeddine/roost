# Commit Conditions

Each result lists a commit condition for every record its operation read, including one it found absent, and the app commits only if Roost finds them all unchanged. So an operation can't overwrite another's work or commit after a record it relied on changed, such as a send after its contact was blocked.

## Alternatives

- Check only the records an operation writes: a send could still commit after another operation blocked its contact.
