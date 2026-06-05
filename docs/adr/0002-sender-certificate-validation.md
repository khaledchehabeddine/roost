# Sender Certificate Validation

**Status:** Proposed

Sender certificate validation runs three checks — signature against a consumer-supplied set of trusted domain signing keys, revocation against a consumer-supplied set of banned identity keys, and expiry against a caller-supplied reference timestamp with a consumer-supplied grace window. The library reads no device clock and accepts the reference time from the caller because rotation, revocation, and clock policy properly belong to the consumer that integrates with the broader identity infrastructure; this keeps validation a pure function of certificate + trusted inputs, which keeps the library auditable and testable without time-source mocking. Accepting more than one trusted signing key concurrently spans rotation overlap windows, so a key rotation does not invalidate certificates already in flight.

Validation consumes sender certificate material only after Message or X3DH first-message ciphertext authentication/decryption exposes the sealed-sender envelope. The current wire format deliberately does not carry sender identity key, sender certificate, or sender signature in clear transport-visible fields. X3DH still verifies a private sender key-possession proof before returning first-message sender material; that proof is not certificate trust, revocation, or expiry validation.
