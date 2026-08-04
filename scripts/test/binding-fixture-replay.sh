#!/usr/bin/env bash
#
# Replay binding checks through generated Swift and Kotlin UniFFI bindings.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/target/bindings/fixture-replay"
HARNESS="$ROOT/crates/aether-uniffi/tests/bindings"
JNA_VERSION="5.18.1"
JNA_SHA256="260c4b1e22b1db9e110ee441c4f13ce115f841fa48c41d78750986214b395557"

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

run_swift_harness() {
    local source="$1"
    local name="$2"
    local swift_out="$3"

    swiftc \
        -module-cache-path "$swift_out/module-cache" \
        -I "$swift_out" \
        -L "$ROOT/target/debug" \
        -Xlinker -rpath \
        -Xlinker "$ROOT/target/debug" \
        -laether \
        "$swift_out/Aether.swift" \
        "$HARNESS/$source" \
        -o "$swift_out/$name"
    "$swift_out/$name"
}

run_swift() {
    need_tool swiftc

    local swift_out="$OUT/swift"
    rm -rf "$swift_out"
    mkdir -p "$swift_out"

    cargo run --locked --features fixture-replay --bin uniffi-bindgen-swift -- \
        "$LIB_PATH" \
        "$swift_out" \
        --swift-sources --headers
    cargo run --locked --features fixture-replay --bin uniffi-bindgen-swift -- \
        "$LIB_PATH" \
        "$swift_out" \
        --modulemap --module-name AetherFFI --modulemap-filename module.modulemap

    mkdir -p "$swift_out/module-cache"
    run_swift_harness "FixtureReplay.swift" "fixture-replay" "$swift_out"
    run_swift_harness "Issue122Coverage.swift" "issue-122-coverage" "$swift_out"
    run_swift_harness "SecureStorageUnexpectedError.swift" "secure-storage-unexpected-error" "$swift_out"
}

sha256_file() {
    local file="$1"
    local output
    if command -v shasum >/dev/null 2>&1; then
        output="$(shasum -a 256 -- "$file")"
    elif command -v sha256sum >/dev/null 2>&1; then
        output="$(sha256sum -- "$file")"
    else
        echo "missing required tool: shasum or sha256sum" >&2
        return 2
    fi
    printf '%s\n' "${output%% *}"
}

verify_sha256() {
    local file="$1"
    local expected="$2"
    [[ -s "$file" ]] || {
        echo "JNA artifact is missing or empty: $file" >&2
        return 1
    }

    local actual
    actual="$(sha256_file "$file")"
    [[ "$actual" == "$expected" ]] || {
        echo "JNA checksum mismatch for $file: expected $expected, got $actual" >&2
        return 1
    }
}

jna_jar() {
    local jar
    if [[ -n "${JNA_JAR:-}" ]]; then
        jar="$JNA_JAR"
    else
        local jar_dir="$OUT/jna"
        jar="$jar_dir/jna-$JNA_VERSION.jar"
        if [[ ! -s "$jar" ]]; then
            need_tool curl
            mkdir -p "$jar_dir"
            local download
            download="$(mktemp "$jar_dir/.jna-$JNA_VERSION.XXXXXX")"
            if ! curl --fail --location --silent --show-error \
                --proto '=https' \
                --proto-redir '=https' \
                "https://repo1.maven.org/maven2/net/java/dev/jna/jna/$JNA_VERSION/jna-$JNA_VERSION.jar" \
                --output "$download"; then
                rm -f "$download"
                return 1
            fi
            if ! verify_sha256 "$download" "$JNA_SHA256"; then
                rm -f "$download"
                return 1
            fi
            mv "$download" "$jar"
        fi
    fi

    verify_sha256 "$jar" "$JNA_SHA256" || return
    printf '%s\n' "$jar"
}

run_kotlin_harness() {
    local source="$1"
    local name="$2"
    local kotlin_out="$3"
    local jna="$4"

    kotlinc \
        "$kotlin_out/com/aurelion/aether/aether.kt" \
        "$HARNESS/$source" \
        -cp "$jna" \
        -include-runtime \
        -d "$kotlin_out/$name.jar"
    run_kotlin_class "$kotlin_out/$name.jar:$jna" "com.aurelion.aether.${name}Kt"
}

run_kotlin_class() {
    local classpath="$1"
    local class_name="$2"

    # jna.library.path is the property JNA's own loader reads; java.library.path alone is not
    # enough for the direct-mapped Native.register call in the generated bindings. The
    # DYLD_LIBRARY_PATH exported above cannot cover for it on macOS either, because SIP strips
    # DYLD_* from the environment when launching a system binary such as /usr/bin/java.
    if command -v java >/dev/null 2>&1 && java -version >/dev/null 2>&1; then
        java \
            -Djna.library.path="$ROOT/target/debug" \
            -Djava.library.path="$ROOT/target/debug" \
            -cp "$classpath" \
            "$class_name"
        return
    fi

    if command -v kotlin >/dev/null 2>&1; then
        kotlin \
            -J-Djna.library.path="$ROOT/target/debug" \
            -cp "$classpath" \
            "$class_name"
        return
    fi

    echo "missing required tool: java or kotlin" >&2
    exit 2
}

run_kotlin() {
    need_tool kotlinc

    local kotlin_out="$OUT/kotlin"
    rm -rf "$kotlin_out"
    mkdir -p "$kotlin_out"

    cargo run --locked --features fixture-replay --bin uniffi-bindgen -- generate \
        "$LIB_PATH" \
        --language kotlin \
        --out-dir "$kotlin_out"

    local jna
    jna="$(jna_jar)"
    run_kotlin_harness "FixtureReplay.kt" "FixtureReplay" "$kotlin_out" "$jna"
    run_kotlin_harness "Issue122Coverage.kt" "Issue122Coverage" "$kotlin_out" "$jna"
    run_kotlin_harness "SecureStorageUnexpectedError.kt" "SecureStorageUnexpectedError" "$kotlin_out" "$jna"
}

main() {
    need_tool cargo
    cargo build --locked -p aether-uniffi --features fixture-replay

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
}

if [[ "${AETHER_BINDING_FIXTURE_SOURCE_ONLY:-}" != "1" ]]; then
    main "$@"
fi
