# Changing Prekeys Only When the App Asks

Roost rotates signed prekeys and refills one-time prekeys only when the app asks, because the app decides when new bundles appear and when to publish them.

## Alternatives

- Rotate signed prekeys while publishing: publishing should only read.
- Refill one-time prekeys while receiving: receiving should only use up the prekey the Message names.
