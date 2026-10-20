# Time Values

Signed and stored times keep a fixed unit, so they stay integers whose names say the unit, such as milliseconds, while Rust logic uses the standard time and duration types. The UniFFI API uses Unix milliseconds for every time value, so an app can't pass a grace window 1,000 times too large by mixing units.

## Alternatives

- Use one integer unit for all times in Rust: each signed format would need a lossy conversion.
- Use UniFFI's timestamp types: floating-point platform dates may not keep signed millisecond values exact.
