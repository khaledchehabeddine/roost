# Sender Certificate Validation

Roost checks a sender certificate only against what the app passes in, such as trusted domain keys, revoked identity keys, the current time, and a grace window for recently expired certificates. It reads no clock for this check, because key rotation, revocation, and clock policy belong to the app. The app can trust several domain keys at once, so a domain can rotate its signing key without invalidating certificates in use.
