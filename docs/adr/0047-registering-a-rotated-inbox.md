# Registering a Rotated Inbox

The app registers a rotated inbox with the Relay after it finalizes the rotation and before it sends anything, so the Relay never points at keys from a rotation whose commit failed. Roost attaches the new grant from finalization on without waiting for the registration. A Message sent before the registration only leaves the contact's reply waiting for a recovery, while a confirmation the app forgot would keep the new grant from every contact.

## Alternatives

- Register between the app's commit and finalizing: the app would hold its Identity Lock across a network call, and nothing could be sent or received until the Relay answered.
- Hold back the new grant until the app confirms the registration: it adds a call and stored state to prevent a delay that fixes itself.
