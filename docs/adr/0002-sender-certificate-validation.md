# Sender Certificate Validation

**Status:** Accepted

Sender certificate validation runs three checks — signature against a consumer-supplied set of trusted domain signing keys, revocation against a consumer-supplied set of banned identity keys, and expiry against a caller-supplied reference timestamp with a consumer-supplied grace window. The library reads no device clock and accepts the reference time from the caller because rotation, revocation, and clock policy properly belong to the consumer that integrates with the broader identity infrastructure; this keeps validation a pure function of certificate + trusted inputs, which keeps the library auditable and testable without time-source mocking. Accepting more than one trusted signing key concurrently spans rotation overlap windows, so a key rotation does not invalidate certificates already in flight.
