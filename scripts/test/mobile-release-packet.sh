#!/usr/bin/env bash
#
# Exercise the mobile release packet contract without rebuilding platform artifacts.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
ASSEMBLE="$ROOT/scripts/release/assemble-mobile-release-packet.sh"
VERIFY="$ROOT/scripts/release/verify-mobile-release-packet.sh"
WRITE_EVIDENCE="$ROOT/scripts/release/write-mobile-gate-evidence.sh"
VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
REVISION="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct HEAD)"
TMP="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

expect_failure() {
    local label="$1"
    shift

    if "$@"; then
        echo "$label unexpectedly passed" >&2
        exit 1
    fi
}

write_packet_manifest() {
    local packet="$1"
    local manifest

    manifest="$(mktemp)"

    (
        cd "$packet"
        find . -maxdepth 1 -type f \
            ! -name SHA256SUMS \
            ! -name SHA256SUMS.asc |
            LC_ALL=C sort |
            while IFS= read -r file; do
                shasum -a 256 "$file"
            done > "$manifest"

        mv "$manifest" SHA256SUMS

        gpg --batch --yes --armor --detach-sign \
            --local-user "$AETHER_RELEASE_GPG_FINGERPRINT" \
            --output SHA256SUMS.asc \
            SHA256SUMS
    )
}

rewrite_zip_member() {
    local source="$1"
    local output="$2"
    local old_name="$3"
    local new_name="$4"

    python3 - "$source" "$output" "$old_name" "$new_name" <<'PY'
import sys
import zipfile

source, output, old_name, new_name = sys.argv[1:]
found = False
with zipfile.ZipFile(source, "r") as source_zip:
    with zipfile.ZipFile(output, "w") as output_zip:
        for info in source_zip.infolist():
            data = source_zip.read(info)
            if info.filename == old_name:
                info.filename = new_name
                found = True
            output_zip.writestr(info, data)
if not found:
    raise SystemExit(f"missing ZIP member: {old_name}")
PY
}

add_zip_symlink() {
    local archive="$1"
    local member="$2"
    local target="$3"

    python3 - "$archive" "$member" "$target" <<'PY'
import stat
import sys
import zipfile

archive, member, target = sys.argv[1:]
info = zipfile.ZipInfo(member)
info.create_system = 3
info.external_attr = (stat.S_IFLNK | 0o777) << 16
with zipfile.ZipFile(archive, "a") as output_zip:
    output_zip.writestr(info, target)
PY
}

add_duplicate_zip_member() {
    local archive="$1"
    local member="$2"

    python3 - "$archive" "$member" <<'PY'
import sys
import warnings
import zipfile

archive, member = sys.argv[1:]
with warnings.catch_warnings():
    warnings.simplefilter("ignore", UserWarning)
    with zipfile.ZipFile(archive, "a") as output_zip:
        output_zip.writestr(member, b"duplicate\n")
PY
}

mkdir -m 700 "$TMP/gnupg"
export GNUPGHOME="$TMP/gnupg"
if command -v gpgconf >/dev/null 2>&1; then
    gpgconf --launch gpg-agent >/dev/null 2>&1 || true
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "missing required tool: python3" >&2
    exit 2
fi

cat > "$TMP/key.conf" <<'KEY'
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: Aether Mobile Release Packet Test
Name-Email: release-packet@example.invalid
Expire-Date: 1d
%no-protection
%commit
KEY

gpg --batch --generate-key "$TMP/key.conf" >/dev/null
AETHER_RELEASE_GPG_FINGERPRINT="$(
    gpg --batch --list-secret-keys --with-colons |
        awk -F: '/^fpr:/ { print $10; exit }'
)"
export AETHER_RELEASE_GPG_FINGERPRINT

PACKET="$TMP/packet"
IOS_FRAMEWORK="$TMP/ios/Aether.xcframework"
IOS_PACKAGE="$TMP/ios/aether-ios-v$VERSION"
ANDROID_STAGE="$TMP/android/com/aurelion/aether/$VERSION"

mkdir -p \
    "$PACKET" \
    "$IOS_FRAMEWORK/ios-arm64/Aether.framework" \
    "$IOS_PACKAGE/Artifacts" \
    "$IOS_PACKAGE/Sources/Aether" \
    "$ANDROID_STAGE"

printf 'synthetic xcframework binary\n' > "$IOS_FRAMEWORK/ios-arm64/Aether.framework/Aether"
cp -R "$IOS_FRAMEWORK" "$IOS_PACKAGE/Artifacts/Aether.xcframework"
printf 'public enum AetherPackageFixture {}\n' > "$IOS_PACKAGE/Sources/Aether/Aether.swift"

cat > "$IOS_PACKAGE/Package.swift" <<'PACKAGE'
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AetherIOS",
    products: [.library(name: "Aether", targets: ["Aether"])],
    targets: [
        .target(name: "Aether", dependencies: ["AetherFFI"], path: "Sources/Aether"),
        .binaryTarget(name: "AetherFFI", path: "Artifacts/Aether.xcframework"),
    ]
)
PACKAGE

(
    cd "$TMP/ios"
    find Aether.xcframework -type f | LC_ALL=C sort |
        zip -X -q "$PACKET/Aether-v$VERSION.xcframework.zip" -@
    find "aether-ios-v$VERSION" -type f | LC_ALL=C sort |
        zip -X -q "$PACKET/Aether-v$VERSION.swift-package.zip" -@
)

printf 'synthetic aar\n' > "$PACKET/aether-$VERSION.aar"
cat > "$PACKET/aether-$VERSION.pom" <<POM
<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.aurelion</groupId>
  <artifactId>aether</artifactId>
  <version>$VERSION</version>
</project>
POM

cp "$PACKET/aether-$VERSION.aar" "$ANDROID_STAGE/"
cp "$PACKET/aether-$VERSION.pom" "$ANDROID_STAGE/"
(
    cd "$TMP/android"
    find com -type f | LC_ALL=C sort |
        zip -X -q "$PACKET/aether-$VERSION-maven-central-unsigned.zip" -@
)

cat > "$PACKET/roost-client-v$VERSION-sbom.json" <<SBOM
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "component": {
      "type": "application",
      "name": "roost-client",
      "version": "$VERSION"
    },
    "properties": [
      {"name": "aether:source:revision", "value": "$REVISION"}
    ]
  },
  "components": [
    {"type": "library", "name": "roost-core", "version": "$VERSION"},
    {"type": "library", "name": "roost-crypto", "version": "$VERSION"}
  ]
}
SBOM

cat > "$PACKET/SOURCE" <<SOURCE
version=$VERSION
source_revision=$REVISION
source_date_epoch=$SOURCE_DATE_EPOCH
SOURCE

for gate in \
    android-package-consumer \
    android-reproducibility \
    ios-package-consumer \
    ios-reproducibility \
    mobile-release-packet \
    sbom-reproducibility; do
    AETHER_GATE_EVIDENCE_PROVIDER=local \
    AETHER_RELEASE_SOURCE_REVISION="$REVISION" \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        "$WRITE_EVIDENCE" "$PACKET/$gate.evidence" "$gate"
done

gpg --batch --armor --export "$AETHER_RELEASE_GPG_FINGERPRINT" \
    > "$PACKET/aether-v$VERSION-release-key.asc"

"$ROOT/scripts/release/sign-artifact.sh" "$PACKET/Aether-v$VERSION.xcframework.zip"
"$ROOT/scripts/release/sign-artifact.sh" "$PACKET/aether-$VERSION.aar"
"$ROOT/scripts/test/release-artifact-verification.sh" \
    "$PACKET/Aether-v$VERSION.xcframework.zip" \
    "$PACKET/aether-$VERSION.aar" \
    "$PACKET/aether-v$VERSION-release-key.asc"
write_packet_manifest "$PACKET"

AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$PACKET"
expect_failure "local evidence rejected for a final packet" \
    env \
    AETHER_RELEASE_SOURCE_REVISION="$REVISION" \
    AETHER_REQUIRE_GITHUB_GATE_EVIDENCE=true \
    "$VERIFY" "$PACKET"

GITHUB_EVIDENCE_PACKET="$TMP/github-evidence-packet"
cp -R "$PACKET" "$GITHUB_EVIDENCE_PACKET"
for gate_job in \
    android-package-consumer:android-aar-distribution \
    android-reproducibility:android-reproducible \
    ios-package-consumer:ios-reproducible \
    ios-reproducibility:ios-reproducible \
    mobile-release-packet:release-candidate-artifact-verification \
    sbom-reproducibility:sbom; do
    gate="${gate_job%%:*}"
    job="${gate_job#*:}"
    env \
        AETHER_GATE_EVIDENCE_PROVIDER=github-actions \
        AETHER_RELEASE_SOURCE_REVISION="$REVISION" \
        SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        GITHUB_REPOSITORY=RelayNet/aether \
        GITHUB_RUN_ID=123456789 \
        GITHUB_RUN_ATTEMPT=1 \
        GITHUB_JOB="$job" \
        "$WRITE_EVIDENCE" "$GITHUB_EVIDENCE_PACKET/$gate.evidence" "$gate"
done
write_packet_manifest "$GITHUB_EVIDENCE_PACKET"
env \
    AETHER_RELEASE_SOURCE_REVISION="$REVISION" \
    AETHER_REQUIRE_GITHUB_GATE_EVIDENCE=true \
    "$VERIFY" "$GITHUB_EVIDENCE_PACKET"

expect_failure "unsigned final Maven Central bundle" \
    env \
    AETHER_RELEASE_SOURCE_REVISION="$REVISION" \
    AETHER_REQUIRE_SIGNED_MAVEN_PUBLICATION=true \
    "$VERIFY" "$PACKET"

RENAMED_SIGNED="$TMP/renamed-signed"
cp -R "$PACKET" "$RENAMED_SIGNED"
mv \
    "$RENAMED_SIGNED/aether-$VERSION-maven-central-unsigned.zip" \
    "$RENAMED_SIGNED/aether-$VERSION-maven-central-signed.zip"
write_packet_manifest "$RENAMED_SIGNED"
expect_failure "renamed unsigned Maven Central bundle" \
    env AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$RENAMED_SIGNED"

SIGNED_PACKET="$TMP/signed-packet"
SIGNED_CENTRAL_ROOT="$TMP/signed-central"
SIGNED_CENTRAL_DIR="$SIGNED_CENTRAL_ROOT/com/aurelion/aether/$VERSION"
cp -R "$PACKET" "$SIGNED_PACKET"
rm "$SIGNED_PACKET/aether-$VERSION-maven-central-unsigned.zip"
mkdir -p "$SIGNED_CENTRAL_DIR"
cp "$PACKET/aether-$VERSION.aar" "$SIGNED_CENTRAL_DIR/"
cp "$PACKET/aether-$VERSION.pom" "$SIGNED_CENTRAL_DIR/"
for file in "$SIGNED_CENTRAL_DIR"/*; do
    gpg --batch --yes --armor --detach-sign \
        --local-user "$AETHER_RELEASE_GPG_FINGERPRINT" \
        --output "$file.asc" \
        "$file"
done
(
    cd "$SIGNED_CENTRAL_ROOT"
    find com -type f | LC_ALL=C sort |
        zip -X -q "$SIGNED_PACKET/aether-$VERSION-maven-central-signed.zip" -@
)
write_packet_manifest "$SIGNED_PACKET"
AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$SIGNED_PACKET"
AETHER_RELEASE_SOURCE_REVISION="$REVISION" \
AETHER_REQUIRE_SIGNED_MAVEN_PUBLICATION=true \
AETHER_REQUIRE_GITHUB_GATE_EVIDENCE=false \
    "$VERIFY" "$SIGNED_PACKET"

TRAVERSAL_PACKET="$TMP/traversal-packet"
TRAVERSAL_BUNDLE="$TMP/traversal-bundle.zip"
cp -R "$PACKET" "$TRAVERSAL_PACKET"
rewrite_zip_member \
    "$PACKET/aether-$VERSION-maven-central-unsigned.zip" \
    "$TRAVERSAL_BUNDLE" \
    "com/aurelion/aether/$VERSION/aether-$VERSION.aar" \
    "../../escape.aar"
mv "$TRAVERSAL_BUNDLE" \
    "$TRAVERSAL_PACKET/aether-$VERSION-maven-central-unsigned.zip"
write_packet_manifest "$TRAVERSAL_PACKET"
expect_failure "Maven ZIP path traversal" \
    env AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$TRAVERSAL_PACKET"

SYMLINK_PACKET="$TMP/symlink-packet"
cp -R "$PACKET" "$SYMLINK_PACKET"
add_zip_symlink \
    "$SYMLINK_PACKET/aether-$VERSION-maven-central-unsigned.zip" \
    "com/aurelion/aether/$VERSION/linked-artifact" \
    "aether-$VERSION.aar"
write_packet_manifest "$SYMLINK_PACKET"
expect_failure "Maven ZIP symlink" \
    env AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$SYMLINK_PACKET"

DUPLICATE_PACKET="$TMP/duplicate-packet"
cp -R "$PACKET" "$DUPLICATE_PACKET"
add_duplicate_zip_member \
    "$DUPLICATE_PACKET/aether-$VERSION-maven-central-unsigned.zip" \
    "com/aurelion/aether/$VERSION/aether-$VERSION.aar"
write_packet_manifest "$DUPLICATE_PACKET"
expect_failure "Maven ZIP duplicate member" \
    env AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$DUPLICATE_PACKET"

TAMPERED_PAYLOAD="$TMP/tampered-payload"
cp -R "$PACKET" "$TAMPERED_PAYLOAD"
printf 'tamper\n' >> "$TAMPERED_PAYLOAD/aether-$VERSION.pom"
expect_failure "packet payload tamper" \
    env AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$TAMPERED_PAYLOAD"

BAD_MANIFEST_SIGNATURE="$TMP/bad-manifest-signature"
cp -R "$PACKET" "$BAD_MANIFEST_SIGNATURE"
printf 'invalid signature\n' > "$BAD_MANIFEST_SIGNATURE/SHA256SUMS.asc"
expect_failure "packet manifest signature mismatch" \
    env AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$BAD_MANIFEST_SIGNATURE"

NESTED_EXTRA="$TMP/nested-extra"
cp -R "$PACKET" "$NESTED_EXTRA"
mkdir "$NESTED_EXTRA/unexpected"
printf 'unexpected\n' > "$NESTED_EXTRA/unexpected/file"
expect_failure "nested packet entry" \
    env AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$NESTED_EXTRA"

INCOMPLETE="$TMP/incomplete"
cp -R "$PACKET" "$INCOMPLETE"
rm "$INCOMPLETE/aether-$VERSION.pom"
expect_failure "missing Android package metadata" \
    env AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$INCOMPLETE"

WRONG_SBOM="$TMP/wrong-sbom"
WRONG_SBOM_TEMP="$TMP/wrong-sbom.json"
cp -R "$PACKET" "$WRONG_SBOM"
jq '
    .metadata.properties = [
        {"name": "aether:source:revision", "value": "0000000000000000000000000000000000000000"}
    ]
' "$WRONG_SBOM/roost-client-v$VERSION-sbom.json" > "$WRONG_SBOM_TEMP"
mv "$WRONG_SBOM_TEMP" "$WRONG_SBOM/roost-client-v$VERSION-sbom.json"
write_packet_manifest "$WRONG_SBOM"
expect_failure "SBOM source revision mismatch" \
    env AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$WRONG_SBOM"

WRONG_EVIDENCE="$TMP/wrong-evidence"
WRONG_EVIDENCE_TEMP="$TMP/wrong-evidence.txt"
cp -R "$PACKET" "$WRONG_EVIDENCE"
sed \
    's/^source_revision=.*/source_revision=0000000000000000000000000000000000000000/' \
    "$WRONG_EVIDENCE/ios-package-consumer.evidence" > "$WRONG_EVIDENCE_TEMP"
mv "$WRONG_EVIDENCE_TEMP" "$WRONG_EVIDENCE/ios-package-consumer.evidence"
write_packet_manifest "$WRONG_EVIDENCE"
expect_failure "gate evidence source revision mismatch" \
    env AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$WRONG_EVIDENCE"

MISSING_EVIDENCE="$TMP/missing-evidence"
cp -R "$PACKET" "$MISSING_EVIDENCE"
rm "$MISSING_EVIDENCE/android-package-consumer.evidence"
expect_failure "missing gate evidence" \
    env AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$MISSING_EVIDENCE"

MISMATCHED_IOS="$TMP/mismatched-ios"
MISMATCHED_PACKAGE_ROOT="$TMP/mismatched-package"
cp -R "$PACKET" "$MISMATCHED_IOS"
mkdir -p "$MISMATCHED_PACKAGE_ROOT"
cp -R "$IOS_PACKAGE" "$MISMATCHED_PACKAGE_ROOT/"
printf 'different xcframework binary\n' >> \
    "$MISMATCHED_PACKAGE_ROOT/aether-ios-v$VERSION/Artifacts/Aether.xcframework/ios-arm64/Aether.framework/Aether"
rm "$MISMATCHED_IOS/Aether-v$VERSION.swift-package.zip"
(
    cd "$MISMATCHED_PACKAGE_ROOT"
    find "aether-ios-v$VERSION" -type f | LC_ALL=C sort |
        zip -X -q "$MISMATCHED_IOS/Aether-v$VERSION.swift-package.zip" -@
)
write_packet_manifest "$MISMATCHED_IOS"
expect_failure "mismatched iOS Distribution Package" \
    env AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$MISMATCHED_IOS"

IOS_INPUT="$TMP/input/ios"
ANDROID_INPUT="$TMP/input/android"
ANDROID_DISTRIBUTION_INPUT="$TMP/input/android-distribution"
SBOM_INPUT="$TMP/input/sbom"
EVIDENCE_INPUT="$TMP/input/evidence"
ASSEMBLED="$TMP/assembled"

mkdir -p \
    "$IOS_INPUT" \
    "$ANDROID_INPUT" \
    "$ANDROID_DISTRIBUTION_INPUT" \
    "$SBOM_INPUT" \
    "$EVIDENCE_INPUT"
cp "$PACKET/Aether-v$VERSION.xcframework.zip" "$IOS_INPUT/"
cp "$PACKET/Aether-v$VERSION.swift-package.zip" "$IOS_INPUT/"
cp "$PACKET/SOURCE" "$IOS_INPUT/SOURCE"
cp "$PACKET/aether-$VERSION.aar" "$ANDROID_INPUT/"
cp "$PACKET/aether-$VERSION.pom" "$ANDROID_INPUT/"
cp "$PACKET/SOURCE" "$ANDROID_INPUT/SOURCE"
cp "$PACKET/aether-$VERSION-maven-central-unsigned.zip" "$ANDROID_DISTRIBUTION_INPUT/"
cp "$PACKET/SOURCE" \
    "$ANDROID_DISTRIBUTION_INPUT/aether-$VERSION-maven-central.source"
cp "$PACKET/roost-client-v$VERSION-sbom.json" "$SBOM_INPUT/"
cp "$PACKET/SOURCE" "$SBOM_INPUT/roost-client-v$VERSION-sbom.source"
cp "$PACKET"/*.evidence "$EVIDENCE_INPUT/"

mkdir -p "$ASSEMBLED"
printf 'stale packet\n' > "$ASSEMBLED/stale"

AETHER_RELEASE_SOURCE_REVISION="$REVISION" \
AETHER_RELEASE_OUTPUT_ROOT="$TMP" \
    "$ASSEMBLE" \
    "$IOS_INPUT" \
    "$ANDROID_INPUT" \
    "$ANDROID_DISTRIBUTION_INPUT" \
    "$SBOM_INPUT" \
    "$EVIDENCE_INPUT" \
    "$ASSEMBLED"

AETHER_RELEASE_SOURCE_REVISION="$REVISION" "$VERIFY" "$ASSEMBLED"

MIXED_SBOM_INPUT="$TMP/input/mixed-sbom"
mkdir -p "$MIXED_SBOM_INPUT"
cp "$SBOM_INPUT/roost-client-v$VERSION-sbom.json" "$MIXED_SBOM_INPUT/"
printf 'version=%s\nsource_revision=%040d\nsource_date_epoch=%s\n' \
    "$VERSION" 0 "$SOURCE_DATE_EPOCH" \
    > "$MIXED_SBOM_INPUT/roost-client-v$VERSION-sbom.source"
expect_failure "mixed source revisions" \
    env \
    AETHER_RELEASE_SOURCE_REVISION="$REVISION" \
    AETHER_RELEASE_OUTPUT_ROOT="$TMP" \
    "$ASSEMBLE" \
    "$IOS_INPUT" \
    "$ANDROID_INPUT" \
    "$ANDROID_DISTRIBUTION_INPUT" \
    "$MIXED_SBOM_INPUT" \
    "$EVIDENCE_INPUT" \
    "$TMP/mixed-source-output"

UNSAFE_OUTPUT_ROOT="$TMP/unsafe-output"
mkdir -p "$UNSAFE_OUTPUT_ROOT/child"
printf 'keep\n' > "$UNSAFE_OUTPUT_ROOT/sentinel"
expect_failure "normalized parent output" \
    env \
    AETHER_RELEASE_SOURCE_REVISION="$REVISION" \
    AETHER_RELEASE_OUTPUT_ROOT="$UNSAFE_OUTPUT_ROOT" \
    "$ASSEMBLE" \
    "$IOS_INPUT" \
    "$ANDROID_INPUT" \
    "$ANDROID_DISTRIBUTION_INPUT" \
    "$SBOM_INPUT" \
    "$EVIDENCE_INPUT" \
    "$UNSAFE_OUTPUT_ROOT/child/.."
if [[ ! -f "$UNSAFE_OUTPUT_ROOT/sentinel" ]]; then
    echo "unsafe output handling removed its parent" >&2
    exit 1
fi

echo "mobile release packet verification passed"
