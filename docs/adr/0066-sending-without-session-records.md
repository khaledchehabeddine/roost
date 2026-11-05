# Sending Without Session Records

A send to an accepted contact whose Session or list of Sessions is missing asks for the contact's prekey bundle, as a first send does (ADR 0038), so the contact stays reachable. If they exist after all, the commit fails, because the send read them as absent (ADR 0046). A Session that lost only its Pending Acknowledgments keeps working, because its keys are intact, and the Messages that waited on it are no longer tracked.

## Alternatives

- Fail a send whose Session records are missing: the contact would stay unreachable until someone repaired the data.
- Start a new Session when only the Pending Acknowledgments are lost: a late Message on the old Session would move sending back to it and start more Sessions.
