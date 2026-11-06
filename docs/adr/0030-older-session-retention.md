# Older Session Retention

A peer keeps sessions it no longer sends on, so messages already on their way to them still decrypt. It keeps only a fixed number per contact and deletes the oldest beyond that, so a contact who keeps starting sessions can't grow storage.

## Alternatives

- Delete older sessions after a set time without a message: a contact who keeps starting sessions could grow storage without limit.
