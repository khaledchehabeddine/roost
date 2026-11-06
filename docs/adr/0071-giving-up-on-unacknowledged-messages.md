# Giving Up on Unacknowledged Messages

A probe that stays unacknowledged can signal another recovery after a longer wait. Messages still unacknowledged once the relay would have dropped their first copy show as not delivered, even if a later copy can still arrive, and so do those whose session is deleted unless a recovery moved them (ADR 0044), so nothing waits forever.

## Alternatives

- Recover only once until the contact writes: a probe lost to another rotation would stay stuck until the contact wrote.
- Keep recovering until the contact answers: a contact who left for good would hold unacknowledged messages forever, and enough of them would block sending to that contact.
