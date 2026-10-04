# Contact Trust and Blocking

A valid Sender Certificate ties an Identity Key to a Relay, but grants no local trust. Trust State and Blocking live in one contact record keyed by the Identity Key, so they change together and survive Discovery Key rotation. Only comparing Safety Numbers outside the app makes a contact verified, and no Message can raise trust.
