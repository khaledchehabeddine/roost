# Publishing mobile packages

Roost owns generation, packaging, signing and publication commands. The private `roost-swift`
and `roost-kotlin` repositories own native checks, manual workflows and consumer metadata.
One workspace version and source commit govern both distributions. Generated Swift and Kotlin
implementation sources remain build outputs. The v0.15.0 record, tags and artifacts stay unchanged.

## Release ordering

Finish the remaining Rust cleanup, repository agent fixes and documentation in
[#271](https://github.com/RelayNet/roost/issues/271) before selecting the official source revision.
The publication implementation is merged, but
[#270](https://github.com/RelayNet/roost/issues/270) defers access setup, plan changes, candidate
preparation and publication until that cleanup is complete. Earlier local checks do not verify the
final signed candidates.

After cleanup, #270 owns exact-candidate installation and publication. Then
[#268](https://github.com/RelayNet/roost/issues/268) owns published-package resolution and full Relay
validation. Keep [#264](https://github.com/RelayNet/roost/issues/264) open until those results are recorded.

## Configuration

Khaled configures access before running the workflows. These secret names describe required
configuration, not proof that it exists. Keep both distribution repositories private.

- `ROOST_READ_TOKEN` in all three repositories needs Contents and Actions read access to all three.
  It must have no publication rights. The existing broad maintainer token cannot serve this role.
- Roost's `signing` environment needs the existing key as `ROOST_RELEASE_PRIVATE_KEY` and its
  passphrase as `ROOST_RELEASE_PASSPHRASE`. The approved fingerprint is
  `8C936E5EE86B909B53B607EA0EEDE342BC541851`. Do not generate another release key.
- Roost's `release` environment needs the existing maintainer credential as `ROOST_PUBLISH_TOKEN`,
  with repository, package publication, administrative read and `project` scope. It must belong
  to `KhaledChehabeddine`. Keep it out of repository-level and signing-environment secrets.
- Restrict both environments to `main`. Keep immutable releases enabled and active `v*` tag rules
  prohibiting updates and deletion without bypass actors in all three repositories. Publication
  checks those settings and fails if it cannot read them. GitHub Team's private environments do
  not supply an independent reviewer; owner-only manual dispatch is the approved policy.
  Both initial and rerun actors are checked.

Credential copying and permission changes require maintainer authorization. Use read-only access
for checkout and candidate verification. GitHub's job-level `permissions` cannot narrow a personal
access token. See [GitHub token permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions).

## Check and sign

1. Merge the source and package workflow changes. Select a full Roost `main` commit and wait for
   its `Rust / check` result. Dispatch **Package consumption** in both distribution repositories
   with that SHA. Each builds once, tests on one simulator or emulator, and uploads the exact
   checked files for 30 days. Android checks every shipped ABI and excludes development certificate
   issuance. Run these workflows before publication and whenever bindings, packaging, release
   commands, toolchains, ABI lists, package layout or consumer repositories change.
2. Review the native job results and SHA-256 hashes. Create a JSON object mapping
   `Roost-v<version>.xcframework.zip`, `roost-<version>.aar` and `roost-<version>.pom` to those exact
   lowercase hashes. Keep these independent pins; do not substitute a downloaded checksum sidecar.
3. Dispatch **Prepare signed mobile candidates** on that source commit with both native run IDs
   and the reviewed pins. It verifies trusted successful runs, source/version, GitHub's artifact
   archive digest and the individual hashes, then signs and verifies the three files. It uploads
   those files, their sidecars, the public key and release description.

Nothing is rebuilt or published during preparation. The release description records the source,
workspace/toolchain versions, hashes and CI results. Ordinary job results remain the verification
record. There is no custom signed evidence packet or reproducibility gate.

## Install the signed candidates

Download and reverify a specific successful preparation attempt from a trusted Roost checkout:

```bash
export ROOST_SOURCE_REVISION='<full source SHA>'
export ROOST_SWIFT_RUN='<Swift run ID>'
export ROOST_KOTLIN_RUN='<Kotlin run ID>'
export ROOST_SHA256_JSON='<reviewed filename-to-SHA256 JSON>'
python3 scripts/release/mobile.py fetch target/verified-mobile --run '<preparation run ID>/<attempt>'
```

Use a new output directory. With those variables still set, run each package repository's
`./check.sh <roost-checkout> <absolute-signed-candidate-directory>`. This mode verifies the pins and
signatures and runs real native calls against the downloaded ZIP or AAR/POM without rebuilding.
Record the results before publication. Local package paths here are test inputs, not production
dependency overrides.

## Publish or resume

After installation and binding calls pass, Khaled dispatches **Publish verified mobile candidates**
with the same source, native run IDs and pins, plus the preparation's `run-id/attempt`. A read-only
job verifies provenance, signatures and hashes before the `release` job receives publication
credentials. That job rechecks the same bytes and inspects every destination before writing.

The source tag points to the verified Roost commit. Swift's tag adds the generated `Package.swift`
to the checked distribution commit without changing `main`. Its versioned binary URL uses the
authenticated GitHub asset API and the completed draft upload's stable asset ID. Its checksum names
the verified ZIP. Kotlin's tag points to its checked distribution commit. Draft GitHub Releases
receive and verify every asset before tag creation and finalization. A failed draft is reused;
completed asset IDs never change. The exact AAR, generated POM and
sidecars go to `https://maven.pkg.github.com/relaynet/roost-kotlin`. Exact-version resolution needs
no moving Maven version selector. The POM carries JNA. Maven Central is not involved.

For a partial failure, rerun publication with the original preparation attempt and pins.
Matching destinations stay untouched; only missing files or destinations are uploaded. Retain
that signed Actions artifact until publication finishes. Changed bytes require a new version.
A new `main` commit does not invalidate a retry if the checked commits remain in trusted history.
Administrators can delete GitHub Maven versions, an accepted MVP risk; replacement remains forbidden.

Published-package resolution and complete Relay app, extension and device validation belong to
#268. Consumers need exact versions, SHA-256 and signer pins, reviewed upgrades, and no local
overrides in CI or release consumption. The separate `roost-development` coordinate remains an
on-demand local tool. Keep the parent cleanup open until Relay validation is recorded.
