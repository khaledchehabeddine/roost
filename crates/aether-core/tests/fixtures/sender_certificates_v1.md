# Sender Certificate Fixtures v1

These fixtures pin the fixed-byte sender certificate encoding and validation verdicts exposed by
the public Core sender-certificate API.

Each case supplies certificate bytes, detached signature bytes, caller-supplied domain-signing
keys, caller-supplied revocation input, and the expected verdict for a fixed reference timestamp
and grace window. Valid cases also pin the decoded certificate fields returned by the validator.

The set covers a valid certificate, signing-key rotation overlap, untrusted signing-key identifier,
revoked Identity Key, expired certificate outside grace, malformed certificate bytes, and a
non-canonical certificate key encoding.
