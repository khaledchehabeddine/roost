# Requested State Reads

Roost learns which records a message needs only as it reads them, such as a session it finds through its contact's list of sessions, so it asks the app for exact records, round by round. A message operation keeps what it has read and its provisional work until it returns its result, so the app never resubmits a record and Roost never repeats cryptography.

## Alternatives

- Pass every record the app holds: the app would load state the message doesn't need, and Roost couldn't tell an absent record from one the app forgot to load.
- Repeat a stateless call with more records each time: the app would resubmit everything, and Roost would decrypt again each round.
