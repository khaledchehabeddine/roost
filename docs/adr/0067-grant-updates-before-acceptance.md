# Grant Updates Before Acceptance

A requester may send the asked side grant updates before acceptance, outside the limit on messages before acceptance (ADR 0037). They carry no content, and without them the asked side's acceptance would go to a dead delivery capability.

## Alternatives

- Count grant updates toward the limit before acceptance: each rotation would cost the requester one of its messages.
