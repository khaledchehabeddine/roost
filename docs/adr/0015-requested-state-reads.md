# Requested State Reads

Roost learns which records a message needs only as it reads them, so it asks the app for each record, round by round. The operation keeps what it read and its work until it returns, so the app never resubmits a record and Roost never repeats cryptography.

## Alternatives

- Pass every record the app holds: the app would load state the message doesn't need, and Roost couldn't tell an absent record from a forgotten one.
- Repeat a stateless call with more records each time: the app would resubmit everything, and Roost would decrypt again each round.
