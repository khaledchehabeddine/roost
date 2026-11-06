# Discovery-to-Identity Binding

The identity key and the discovery key sign each other, but only the identity key's signature includes the epoch and creation time. The identity key signs many discovery keys over time, so its signature must say which one it approved, while each discovery key already belongs to a single epoch. Because the discovery key's signature carries no time, a leaked old discovery key could still make one, and the relay stops that by refusing to serve rotated discovery keys.

## Alternatives

- Add the epoch and a timestamp to the discovery key's signature: each discovery key already belongs to one epoch, so the fields would repeat what the identity key's signature says.
