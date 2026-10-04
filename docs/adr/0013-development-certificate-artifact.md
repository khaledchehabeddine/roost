# Development Certificate Artifact

The production Android artifact can't issue development certificates, so local tests that simulate peers use a separate Maven artifact, at the same version, that can. Separate artifact names make it explicit in Gradle which one a build uses. Development certificates go through production validation and are trusted only when the app passes in the local development certificate authority.

## Alternatives

- Put the development certificate authority in the production AAR, enabled only in debug builds: release builds would still ship the code that issues certificates.
- Publish both under one name: the same name would mean two different APIs, which breaks build caches.
