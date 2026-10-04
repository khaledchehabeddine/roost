# Structure

Roost does many separate things, such as handshake and backups, so grouping code by kind scatters them.

## Modules and Files

- Group code into modules by what it does, such as `handshake` or `time`, not into catch-alls such as `types` or `utils`.
- Keep each function beside its types and errors, not grouped by kind of item.
