# Binding checks

`scripts/test/bindings.sh` generates and compiles the production Swift and Kotlin bindings, then
runs the checks Rust cannot perform alone:

- `SecureStorageUnexpectedError.*` checks foreign exception conversion and subsequent lock use.
- `PreparedOperations.*` checks foreign SecureStorage staging, orphan discovery, stale preconditions,
  lost write replies, restart recovery, and idempotent finalization.
- `TransportBindingBindings.*` checks sliced byte containers, NUL and high-bit bytes, and rejection
  after an authenticated byte changes.
- `EvidenceBundleVectors.*` reads the canonical Rust evidence fixture through the runner. CryptoKit
  and the JDK verify its certificate signature and the Message signature over fields returned by FFI.
  They also verify a fresh authentication signature returned by the generated signer binding.

The runner needs Rust, Python 3, Swift, Kotlin, and a JDK with Ed25519 support. It verifies the pinned
JNA checksum. Set `ROOST_BINDING_LANGS=swift` or `kotlin` to run one language; `JNA_JAR` can name a
cached copy of the pinned JAR.

`PackageConsumerTests.swift` and Android's `AndroidAarConsumerTest` only verify package installation,
native loading, and a real Client call. The complete consumer workflow is validated manually for
v0.16.0 and after changes to packaging, release scripts, toolchains, ABI lists, package layout,
bindings, or consumer repositories.

Rust owns protocol scenarios and exact-byte fixtures. See the
[coverage notes](../../../../docs/protocol-state-invariant-tests.md) for retained evidence and gaps.
