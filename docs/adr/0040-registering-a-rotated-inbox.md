# Registering a Rotated Inbox

The app registers a rotated inbox with the relay after it finalizes the rotation and before it sends anything, so the relay never points at keys from a rotation whose commit failed. Roost attaches the new grant from finalization on without waiting for the registration. A message sent before the registration only leaves the contact's reply waiting for a recovery, while a confirmation the app forgot would keep the new grant from every contact.

## Alternatives

- Register between the app's commit and finalizing: the app would hold its identity lock across a network call, and nothing could be sent or received until the relay answered.
- Hold back the new grant until the app confirms the registration: it adds a call and stored state to prevent a delay that fixes itself.
