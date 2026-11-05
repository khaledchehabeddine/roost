# Acknowledgment Destinations

The route an incoming Message arrived on may not reach its sender, so Core picks where its acknowledgment goes only after it authenticates the sender and applies block policy. It then asks the app for that destination's Transport Binding.

## Alternatives

- Let the app pick the acknowledgment's destination up front: it would choose before Roost knows who sent the Message or whether they're blocked.
