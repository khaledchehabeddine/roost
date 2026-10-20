# Unsigned Release Artifacts

While one maintainer releases, the mobile artifacts carry no signatures, and consumers rely on checksum pins.

## Alternatives

- Sign each artifact and publish only the exact files the package checks tested: the signing key, the handoff between three repositories, and the provenance checks cost more than they protect while one maintainer releases.
