# Protocol DoS Limits

Core reads its adjustable denial-of-service limits from one public settings object, so defaults, ceilings, and the trade-offs for low-end devices can be reviewed in one place. Apps can change only the size of the Deduplication Set and get fixed defaults for the rest. Transport limits, such as rate limits, stay with the app.

## Alternatives

- Constants only: apps couldn't lower limits for low-end devices.
- One setter per limit: related limits would be documented and reviewed in many places.
