#!/usr/bin/env bash
# Build the generated Kotlin API and native libraries into a local Maven AAR.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT"
VERSION="$(awk -F '"' '/^version = / { print $2; exit }' Cargo.toml)"
scripts/build/android.sh
"${GRADLE_BIN:-gradle}" --no-daemon -p packaging/android -ProostVersion="$VERSION" \
    :roost:publishReleasePublicationToLocalRepository
PACKAGE="$ROOT/target/android/maven/com/chirp/roost/$VERSION"
AAR="$PACKAGE/roost-$VERSION.aar"
CLASSES="$(unzip -p "$AAR" classes.jar | jar --list)"
[[ "$CLASSES" == *com/chirp/roost/IdentityContext.class* ]]
# Every shipped ABI must be present, and no other.
[[ "$(zipinfo -1 "$AAR" 'jni/*.so' | wc -l)" -eq 2 ]]
for abi in arm64-v8a x86_64; do
    unzip -p "$AAR" "jni/$abi/libroost_client.so" | cmp - "target/android/jniLibs/$abi/libroost_client.so"
done
# Gradle resolves the module metadata, and IDEs read the sources jar.
[[ -f "$PACKAGE/roost-$VERSION.module" && -f "$PACKAGE/roost-$VERSION-sources.jar" ]]
printf 'Android Maven package: %s\n' "$AAR"
