# Sending Without Session Records

A send to an accepted contact whose Session records are missing asks for the contact's prekey bundle, as a first send does (ADR 0038), so the contact stays reachable. If the records exist after all, the commit fails, because the send read them as absent (ADR 0046).

## Alternatives

- Fail a send whose Session records are missing: the contact would stay unreachable until someone repaired the data.
