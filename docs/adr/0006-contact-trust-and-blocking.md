# Contact Trust and Blocking

A valid sender certificate ties an identity key to a relay, but grants no local trust. Trust state and blocking live in one contact record keyed by the identity key, so they change together and survive discovery key rotation. Only comparing safety numbers outside the app makes a contact verified, and no message can do that.
