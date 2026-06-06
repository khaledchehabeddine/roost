#!/usr/bin/env bash
#
# Replay canonical fixtures through generated Swift and Kotlin UniFFI bindings.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/target/bindings/fixture-replay"
HARNESS="$ROOT/crates/aether-uniffi/tests/bindings"
JNA_VERSION="5.18.1"

case "$(uname -s)" in
    Darwin)
        LIB_NAME="libaether.dylib"
        export DYLD_LIBRARY_PATH="$ROOT/target/debug:${DYLD_LIBRARY_PATH:-}"
        ;;
    Linux)
        LIB_NAME="libaether.so"
        export LD_LIBRARY_PATH="$ROOT/target/debug:${LD_LIBRARY_PATH:-}"
        ;;
    *)
        echo "unsupported host OS for binding fixture replay: $(uname -s)" >&2
        exit 2
        ;;
esac

LIB_PATH="$ROOT/target/debug/$LIB_NAME"

need_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}

run_swift() {
    need_tool swiftc

    local swift_out="$OUT/swift"
    mkdir -p "$swift_out"

    cargo run --features fixture-replay --bin uniffi-bindgen-swift -- \
        "$LIB_PATH" \
        "$swift_out" \
        --swift-sources --headers
    cargo run --features fixture-replay --bin uniffi-bindgen-swift -- \
        "$LIB_PATH" \
        "$swift_out" \
        --modulemap --module-name AetherFFI --modulemap-filename module.modulemap

    mkdir -p "$swift_out/module-cache"
    swiftc \
        -module-cache-path "$swift_out/module-cache" \
        -I "$swift_out" \
        -L "$ROOT/target/debug" \
        -Xlinker -rpath \
        -Xlinker "$ROOT/target/debug" \
        -laether \
        "$swift_out/Aether.swift" \
        "$HARNESS/FixtureReplay.swift" \
        -o "$swift_out/fixture-replay"
    "$swift_out/fixture-replay"
}

jna_jar() {
    if [[ -n "${JNA_JAR:-}" ]]; then
        echo "$JNA_JAR"
        return
    fi

    local jar_dir="$OUT/jna"
    local jar="$jar_dir/jna-$JNA_VERSION.jar"
    if [[ ! -s "$jar" ]]; then
        need_tool curl
        mkdir -p "$jar_dir"
        curl --fail --location --silent --show-error \
            "https://repo1.maven.org/maven2/net/java/dev/jna/jna/$JNA_VERSION/jna-$JNA_VERSION.jar" \
            --output "$jar"
    fi
    echo "$jar"
}

run_kotlin() {
    need_tool java
    need_tool kotlinc

    local kotlin_out="$OUT/kotlin"
    mkdir -p "$kotlin_out"

    cargo run --features fixture-replay --bin uniffi-bindgen -- generate \
        "$LIB_PATH" \
        --language kotlin \
        --out-dir "$kotlin_out"

    local jna
    jna="$(jna_jar)"
    kotlinc \
        "$kotlin_out/com/aurelion/aether/aether.kt" \
        "$HARNESS/FixtureReplay.kt" \
        -cp "$jna" \
        -include-runtime \
        -d "$kotlin_out/fixture-replay.jar"
    java \
        -Djava.library.path="$ROOT/target/debug" \
        -cp "$kotlin_out/fixture-replay.jar:$jna" \
        com.aurelion.aether.FixtureReplayKt
}

need_tool cargo
cargo build -p aether-uniffi --features fixture-replay

case "${AETHER_BINDING_REPLAY_LANGS:-swift,kotlin}" in
    swift)
        run_swift
        ;;
    kotlin)
        run_kotlin
        ;;
    swift,kotlin | kotlin,swift)
        run_swift
        run_kotlin
        ;;
    *)
        echo "unsupported AETHER_BINDING_REPLAY_LANGS value: ${AETHER_BINDING_REPLAY_LANGS:-swift,kotlin}" >&2
        exit 2
        ;;
esac
