# Android AAR Distribution

**Status:** Accepted

The Android binding release is a generated AAR published under Maven coordinates from the exact
release-candidate source, containing UniFFI-generated Kotlin and ABI-specific `libaether.so`
libraries. Keeping the artifact generated preserves the existing source-of-truth boundary for
bindings, while Maven metadata gives Android consumers a standard dependency shape before final
release signing and pinned checksums are applied.

## Considered Options

- Check generated Kotlin and native libraries into the repository. Rejected because generated
  bindings would add review noise and duplicate the Rust UniFFI surface.
- Publish loose Kotlin sources and shared libraries. Rejected because Android consumers expect a
  single dependency that carries classes, native libraries, and transitive runtime metadata.
