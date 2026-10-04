#!/usr/bin/env bash
# Build the generated Kotlin API and native libraries into a local Maven AAR.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT"
VERSION="$(awk -F '"' '/^version = / { print $2; exit }' Cargo.toml)"
ARTIFACT="roost"
case "${ROOST_CARGO_FEATURES:-}" in
    "") ;;
    development-certificates) ARTIFACT="roost-development" ;;
    *) echo "unsupported ROOST_CARGO_FEATURES" >&2; exit 2 ;;
esac
scripts/build/android.sh
"${GRADLE_BIN:-gradle}" --no-daemon -p packaging/android \
    -ProostVersion="$VERSION" -ProostArtifactId="$ARTIFACT" \
    :roost:publishReleasePublicationToLocalRepository
AAR="$ROOT/target/android/maven/io/github/relaynet/$ARTIFACT/$VERSION/$ARTIFACT-$VERSION.aar"
CLASSES="$(unzip -p "$AAR" classes.jar | jar --list)"
[[ "$CLASSES" == *io/github/relaynet/roost/IdentityContext.class* ]]
if [[ "$ARTIFACT" == roost ]]; then
    [[ "$CLASSES" != *io/github/relaynet/roost/DevelopmentCertificateAuthority.class* ]]
else
    [[ "$CLASSES" == *io/github/relaynet/roost/DevelopmentCertificateAuthority.class* ]]
fi
# Every shipped ABI must be present, even though the consumer runs on one emulator.
for abi in arm64-v8a armeabi-v7a x86_64; do
    unzip -p "$AAR" "jni/$abi/libroost_client.so" | cmp - "target/android/jniLibs/$abi/libroost_client.so"
done
printf 'Android Maven package: %s\n' "$AAR"
