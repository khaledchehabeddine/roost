# Sender Certificate Validation

Roost checks a Sender Certificate using only the certificate and inputs the app passes in, such as the domain keys it trusts to sign certificates, revoked Identity Keys, and the current time. Roost reads no clock of its own, because key rotation, revocation, and clock policy belong to the app, and a check with no hidden inputs is easier to audit and test. The app can trust several domain keys at once, so a domain can rotate its signing key without invalidating certificates already in use.
