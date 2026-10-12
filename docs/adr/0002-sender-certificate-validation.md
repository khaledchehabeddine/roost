# Sender Certificate Validation

Roost checks a Sender Certificate using only the certificate and inputs the app passes in, such as the domain keys it trusts to sign certificates, revoked Identity Keys, and the current time, and reads no clock of its own, because key rotation, revocation, and clock policy belong to the app. The app passes the grace window for recently expired certificates with each receive, because a window held in each Identity Context could differ between the app and its extensions, and Roost caps it so an app can't keep an expired certificate valid indefinitely. The app can trust several domain keys at once, so a domain can rotate its signing key without invalidating certificates already in use.

## Alternatives

- Pick the grace window once, when the app creates the Identity Context: the app and each extension hold their own context, so their windows can differ and go stale when the app changes the setting.
