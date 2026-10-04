# Sender Certificate Validation

Roost checks a Sender Certificate using only the certificate and inputs the app passes in, such as the domain keys it trusts to sign certificates, revoked Identity Keys, and the current time, and reads no clock of its own, because key rotation, revocation, and clock policy belong to the app. The app picks the grace window for recently expired certificates once, when it creates the Identity Context, so every check for that Identity uses the same window, and Roost caps it so an app can't keep an expired certificate valid indefinitely. The app can trust several domain keys at once, so a domain can rotate its signing key without invalidating certificates already in use.

## Alternatives

- Pass the grace window with each check: one call with a larger window would weaken every other check for that Identity.
