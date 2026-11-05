# Giving Up on Unacknowledged Messages

A Probe that stays unacknowledged can signal another Recovery after a longer wait. Messages still unacknowledged once the Relay would have dropped their first copy show as not delivered, even if a later copy can still arrive, and so do those whose Session is deleted unless a Recovery moved them (ADR 0044), so nothing waits forever.

## Alternatives

- Recover only once until the contact writes: a Probe lost to another rotation would stay stuck until the contact wrote.
- Keep recovering until the contact answers: a contact who left for good would hold unacknowledged Messages forever, and enough of them would block sending to that contact.
