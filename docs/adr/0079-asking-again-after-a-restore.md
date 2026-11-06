# Asking Again After a Restore

A restore brings back how many messages this side sent a contact before acceptance, but drops the sessions that show which of them arrived (ADR 0074). So a contact request to a contact with no session left counts from zero, since the recipient holds each sender to the limit anyway (ADR 0037). Otherwise a requester that used up the limit before its backup couldn't send the new request that a lost acceptance needs (ADR 0076).

## Alternatives

- Keep the count: the requester couldn't write to an asked side that had accepted, and would wait until that side wrote and its recovery resent.
- Let only the new request past the limit: a backup older than the last sends already restores too low a count, so after a restore the count is a guess either way.
