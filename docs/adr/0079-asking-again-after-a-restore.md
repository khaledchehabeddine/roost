# Asking Again After a Restore

A restore brings back how many Messages this side sent a contact before acceptance, but drops the Sessions that show which of them arrived (ADR 0074). So a Contact Request to a contact with no Session left counts from zero, since the recipient holds each sender to the limit anyway (ADR 0037). Otherwise a Requester that used up the limit before its backup couldn't send the new request that a lost acceptance needs (ADR 0076).

## Alternatives

- Keep the count: the Requester couldn't write to an Asked Side that had accepted, and would wait until that side wrote and its Recovery resent.
- Let only the new request past the limit: a backup older than the last sends already restores too low a count, so after a restore the count is a guess either way.
