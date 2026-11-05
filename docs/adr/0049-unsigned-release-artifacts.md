# Unsigned Release Artifacts

While one maintainer releases, the mobile artifacts carry no signatures, and the Swift package pins its XCFramework by checksum.

## Alternatives

- Sign each artifact: the signing key, the handoff between three repositories, and the provenance checks cost more than they protect while one maintainer releases.
