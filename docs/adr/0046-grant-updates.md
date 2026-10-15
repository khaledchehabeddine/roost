# Grant Updates

After an inbox rotation, a contact the user doesn't write to keeps a dead Delivery Capability and can't reach the inbox, so the app may send any contact a Grant Update and chooses who gets one and when. Roost still decides who may hold the grant: it refuses a Grant Update to a blocked contact or to a requester the app hasn't accepted, and sends nothing to a contact that already acknowledged the current grant, so an app bug can't hand a blocked contact the new capability. A requester may send the asked side Grant Updates before acceptance, outside the limit on Messages before acceptance, because they carry no content and the asked side's acceptance would otherwise go to a dead capability.

## Alternatives

- Send grants only on ordinary Messages: each rotation would cut off every contact the user doesn't write to.
- Let the app pick recipients and trust its list: an app bug that included a blocked contact would undo the block.
- Have Roost send to every contact after a rotation: Roost can't list contacts, and one operation would have to read every contact's state.
- Count Grant Updates toward the limit before acceptance: each rotation would cost the requester one of its Messages.
