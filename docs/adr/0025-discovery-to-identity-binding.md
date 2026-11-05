# Discovery-to-Identity Binding

The Identity Key and the Discovery Key sign each other, but only the Identity Key's signature includes the Epoch and creation time. The Identity Key signs many Discovery Keys over time, so its signature must say which one it approved, while each Discovery Key already belongs to a single Epoch. Because the Discovery Key's signature carries no time, a leaked old Discovery Key could still make one, and the Relay stops that by refusing to serve rotated Discovery Keys.

## Alternatives

- Add the Epoch and a timestamp to the Discovery Key's signature: each Discovery Key already belongs to one Epoch, so the fields would repeat what the Identity Key's signature says.
