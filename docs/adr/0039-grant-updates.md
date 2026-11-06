# Grant Updates

After an inbox rotation, a contact the user doesn't write to keeps a dead delivery capability, so the app may send any contact a grant update, choosing who and when. Roost still refuses a grant update to a blocked contact or to a requester the app hasn't accepted, so an app bug can't hand a blocked contact the new capability. It sends nothing to a contact that already acknowledged the current grant.

## Alternatives

- Send grants only on ordinary messages: each rotation would cut off every contact the user doesn't write to.
- Let the app pick recipients and trust its list: an app bug that included a blocked contact would undo the block.
- Have Roost send to every contact after a rotation: Roost can't list contacts, and one operation would have to read every contact's state.
