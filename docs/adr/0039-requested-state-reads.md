# Requested State Reads

Roost learns which records a Message needs only as it reads them, such as a Session found through its contact's record, so it asks the app for exact records over as many rounds as it needs, and the app returns each record's bytes or reports it absent. Each key shows its record's Protocol State Kind, so the app can find its contact records to list or watch them without decoding anything. A Message Operation keeps what it has read and its provisional work until it returns its result, so the app never resubmits a record and Roost never repeats cryptography.

## Alternatives

- Pass every record the app holds: the app loads state the Message doesn't need, and Roost can't tell an absent record from one the app forgot to load.
- One opaque key per record: the app couldn't find its contact records without decoding them.
- A token on each read: an operation waits on one read at a time, so checking the returned keys against it catches the same mistakes.
- Repeat a stateless call with more records each time: the app would resubmit everything, and Roost would decrypt again when the acknowledgment's Transport Binding arrives.
