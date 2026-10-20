# Releasing From a Version Tag

Pushing a version tag on main runs one workflow that generates the bindings, then builds and publishes both mobile packages, so the published bindings always match the tagged Rust code.

## Alternatives

- Commit generated bindings and native libraries to the package repositories' main branches: they add review noise and duplicate the Rust code.
- Run the package checks in the release workflow: simulator and emulator runs make every release slower and flakier.
