# Cargo

Every dependency ships inside the app, so each new one is more code to trust and keep updated.

## Dependencies

- For new functionality, use the first of these that provides it:
  - The standard library.
  - An existing dependency.
  - An implementation of our own that's easy to write correctly and maintain.
  - A new crate from an established, actively maintained project.
- Declare every external dependency in the workspace `Cargo.toml`, and inherit it in each crate that uses it.
- Group dependencies that must be updated together under a comment naming what they share, such as `# These share rand_core 0.6`.
- Remove a dependency from a crate when the crate stops using it, and from the workspace when no crate uses it.
- Use Cargo's default version requirements, and pin an exact version only when a newer release breaks the build, with a comment naming that release.

## Crate Settings

- Put a crate setting, such as the edition, in the workspace `Cargo.toml` only when every crate uses the same value, and inherit it in each crate.
- Make every crate inherit the workspace lints.

## Builds

- Leave `CARGO_TARGET_DIR` unset.
