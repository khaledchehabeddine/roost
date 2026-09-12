# Development Certificate Android Artifact

**Status:** Accepted

The production Android coordinate, `io.github.relaynet:roost`, is built without
development certificate issuance. Local peer simulations consume a separate,
version-matched `io.github.relaynet:roost-development` coordinate built with the
`development-certificates` feature.

Keeping distinct coordinates makes Gradle variant selection explicit and lets
packaging fail if the production artifact contains the certificate authority or
the development artifact omits it. Development certificates still use the
production encoding and validation path, and are trusted only when the caller
supplies the process-local development authority.

## Considered Options

- Put the development authority in the production AAR and bind it only in debug
  builds. Rejected because the production binary would unnecessarily expose
  certificate issuance.
- Rebuild and overwrite the same Maven coordinate locally. Rejected because an
  identical coordinate could then represent different APIs, undermining cache
  correctness and reproducibility.

## Consequences

- Consumers that need local peer simulation select the development coordinate
  only in debug variants; release variants select the production coordinate.
- The development coordinate is built on demand for local peer simulations. Production checks
  build only the default coordinate; no second release build is required.
