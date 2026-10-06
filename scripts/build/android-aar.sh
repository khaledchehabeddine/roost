#!/usr/bin/env bash
# Build the Rust library and its generated Kotlin API into a local Maven AAR.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
OUT="$ROOT/target/android"
VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
TARGETS=(aarch64-linux-android:arm64-v8a x86_64-linux-android:x86_64)
cd "$ROOT"

rm -rf "$OUT/kotlin" "$OUT/jniLibs"
for pair in "${TARGETS[@]}"; do
    target="${pair%%:*}"
    abi="${pair##*:}"
    rustup target add "$target"
    cargo ndk --target "$target" build --locked --release -p roost-client
    mkdir -p "$OUT/jniLibs/$abi"
    cp "target/$target/release/libroost_client.so" "$OUT/jniLibs/$abi/"
done
cargo run --locked -p roost-client --bin uniffi-bindgen -- generate \
    target/aarch64-linux-android/release/libroost_client.so --language kotlin --out-dir "$OUT/kotlin"
find "$OUT/kotlin" -name '*.kt' -exec python3 scripts/build/host_docs.py kotlin {} \;

"${GRADLE_BIN:-gradle}" --no-daemon -p android -ProostVersion="$VERSION" publishReleasePublicationToLocalRepository

PACKAGE="$OUT/maven/com/chirp/roost/$VERSION"
AAR="$PACKAGE/roost-$VERSION.aar"
CLASSES="$(unzip -p "$AAR" classes.jar | jar --list)"
[[ "$CLASSES" == *com/chirp/roost/IdentityContext.class* ]]
# Every shipped ABI must be present, and no other.
[[ "$(zipinfo -1 "$AAR" 'jni/*.so' | wc -l)" -eq "${#TARGETS[@]}" ]]
for pair in "${TARGETS[@]}"; do
    abi="${pair##*:}"
    unzip -p "$AAR" "jni/$abi/libroost_client.so" | cmp - "$OUT/jniLibs/$abi/libroost_client.so"
done
# Gradle resolves the module metadata, and IDEs read the sources jar.
[[ -f "$PACKAGE/roost-$VERSION.module" && -f "$PACKAGE/roost-$VERSION-sources.jar" ]]
printf 'Android Maven package: %s\n' "$AAR"
