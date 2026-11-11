# Sharing the Inbox Grant on Acceptance

The asked side shares its inbox grant only when it accepts, so a requester it turns down can never deliver to it. The grant therefore also counts as acceptance on the requester's session, which lets a requester that lost the acceptance in a restore become accepted again.

## Alternatives

- Share the grant with the first reply: a requester turned down later would keep delivering until the next inbox rotation.
- Leave a lost acceptance to recovery: recovery resends only unacknowledged messages, so an acceptance the requester acknowledged before restoring an older backup never comes back.
