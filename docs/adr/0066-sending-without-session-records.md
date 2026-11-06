# Sending Without Session Records

A send to an accepted contact whose session or list of sessions is missing asks for the contact's prekey bundle, as a first send does (ADR 0038), so the contact stays reachable. If they exist after all, the commit fails, because the send read them as absent (ADR 0046). A session that lost only its pending acknowledgments keeps working, because its keys are intact, and the messages that waited on it are no longer tracked.

## Alternatives

- Fail a send whose session records are missing: the contact would stay unreachable until someone repaired the data.
- Start a new session when only the pending acknowledgments are lost: a late message on the old session would move sending back to it and start more sessions.
