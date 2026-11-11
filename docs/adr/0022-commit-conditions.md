# Commit Conditions

Each result carries a commit condition for every record its operation read, including absent ones, and the commit succeeds only if all are unchanged. So an operation can't commit after a record it relied on changed, such as a send after the app blocked its contact.

## Alternatives

- Check only the records an operation writes: a send could still commit after the app blocked its contact.
