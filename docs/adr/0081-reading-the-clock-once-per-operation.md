# Reading the Clock Once per Operation

KeyStore reads the clock once per operation and passes that time to everything the operation calls, so every check in one operation sees the same time.

## Alternatives

- Inject a clock into KeyStore: a trait that only unit tests use costs more than passing the time in.
