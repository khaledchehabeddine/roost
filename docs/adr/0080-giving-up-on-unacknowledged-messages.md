# Giving Up on Unacknowledged Messages

A probe that stays unacknowledged gets the recovery check again after a longer wait. Messages still unacknowledged once the Relay would have dropped them, or once their Session is deleted, show as not delivered, so nothing waits forever and the app always knows what didn't arrive.

## Alternatives

- Recover only once until the contact writes: a probe lost to another rotation would stay stuck until the contact wrote.
- Keep recovering until the contact answers: a contact who left for good would hold unacknowledged Messages forever, and enough of them would block sending to that contact.
