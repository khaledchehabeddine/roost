# Protocol DoS Limits

Core keeps its denial-of-service defaults and ceilings in one public settings object, so the trade-offs for low-end devices can be reviewed in one place. Apps choose only the Deduplication Set's size, which they pass with each receive, and get fixed defaults for the rest. Transport limits, such as rate limits, stay with the app.

## Alternatives

- Constants only: apps couldn't lower limits for low-end devices.
- One setter per limit: related limits would be documented and reviewed in many places.
