# Older Session Retention

A peer keeps Sessions it no longer sends on, so Messages already on their way to them still decrypt. It keeps only a fixed number per contact and deletes the oldest beyond that, so a contact who keeps starting Sessions can't grow storage.

## Alternatives

- Delete older Sessions after a set time without a Message: a contact who keeps starting Sessions could grow storage without limit.
