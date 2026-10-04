# Protocol DoS Limits

All denial-of-service limits live in one public settings object that Core reads. Defaults, ceilings, and the trade-offs for low-end devices can then be reviewed in one place. Apps that don't change the settings get fixed defaults, and transport limits, such as rate limits, stay with the app.

## Alternatives

- Constants only: apps couldn't lower limits for low-end devices.
- One setter per limit: related limits would be documented and reviewed in many places.
