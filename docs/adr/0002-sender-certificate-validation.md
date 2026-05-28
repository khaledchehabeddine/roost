# Sender Certificate Validation Model

**Status:** Accepted

Sender certificate validation is a three-check function — signature (against a consumer-supplied set of trusted domain signing keys, accepting more than one concurrently to span rotation overlap), revocation (against a consumer-supplied set of banned identity keys), and expiry (against a caller-supplied reference timestamp with a consumer-supplied grace window). The library reads no device clock and applies no clock-offset estimate; the consumer normalizes time before calling, so validation stays a pure function of certificate + reference time + grace window + trusted inputs. Supplying the trust and time inputs from outside means rotation, revocation, and clock policy are owned where they belong — in the consumer that integrates with the broader identity infrastructure — without compromising the library's auditability.
