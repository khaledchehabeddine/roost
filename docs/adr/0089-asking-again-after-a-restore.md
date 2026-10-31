# Asking Again After a Restore

A restore brings back how many Messages this side sent a contact before acceptance, but drops the Sessions that show which of them arrived (ADR 0084). So a Contact Request to a contact with no Session left counts from zero, since the recipient holds each sender to the limit anyway (ADR 0044). Otherwise a requester that used up the limit before its backup couldn't send the new request that a lost acceptance needs (ADR 0086).

## Alternatives

- Keep the count: the requester couldn't write to an asked side that had accepted, and would wait until that side wrote and its recovery resent a day later.
- Let only the new request past the limit: a backup older than the last sends already restores too low a count, so after a restore the count is a guess either way.
