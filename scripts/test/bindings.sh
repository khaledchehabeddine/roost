#!/usr/bin/env bash
#
# Run targeted FFI checks through generated Swift and Kotlin UniFFI bindings.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/target/bindings/ffi"
HARNESS="$ROOT/crates/roost-client/tests/bindings"
JNA_VERSION="5.18.1"

case "$(uname -s)" in
    Darwin)
        LIB_NAME="libroost_client.dylib"
        export DYLD_LIBRARY_PATH="$ROOT/target/debug:${DYLD_LIBRARY_PATH:-}"
        ;;
    Linux)
        LIB_NAME="libroost_client.so"
        export LD_LIBRARY_PATH="$ROOT/target/debug:${LD_LIBRARY_PATH:-}"
        ;;
    *)
        echo "unsupported host OS for binding checks: $(uname -s)" >&2
        exit 2
        ;;
esac

LIB_PATH="$ROOT/target/debug/$LIB_NAME"

run_check() {
    # Python only reads the fixture and supplies process inputs; native code verifies signatures.
    python3 - "$ROOT/crates/roost-protocol/tests/fixtures/evidence_bundles_v1.json" "$@" <<'CHECK'
import json
import os
import subprocess
import sys

with open(sys.argv[1]) as source:
    fixture = json.load(source)
valid = fixture["valid"]
material = valid["verification_material"]
fields = {
    "BUNDLE": valid["bundle_hex"],
    "DOMAIN_ID": fixture["domain_signing_key"]["identifier_hex"],
    "DOMAIN_KEY": fixture["domain_signing_key"]["verifying_key_hex"],
    "RELAY": fixture["expected_relay_domain_hex"],
    "ACCEPTED": fixture["accepted_timestamp_secs"],
    "GRACE": fixture["grace_window_secs"],
    "IDENTITY": valid["decoded"]["evidence_identity_hex"],
    "CERTIFICATE": material["sender_certificate_hex"],
    "CERTIFICATE_SIGNATURE": material["sender_certificate_signature_hex"],
    "MESSAGE_SIGNATURE": material["message_transcript_signature_hex"],
}
subprocess.run(sys.argv[2:], check=True, env={
    **os.environ, **{"ROOST_EVIDENCE_" + key: str(value) for key, value in fields.items()},
})
CHECK
}

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
        -lroost_client \
        "$swift_out/Roost.swift" \
        "$HARNESS/$source" \
        -o "$swift_out/$name"
    run_check "$swift_out/$name"
}

run_swift() {
    need_tool swiftc

    local swift_out="$OUT/swift"
    rm -rf "$swift_out"
    mkdir -p "$swift_out"

    cargo run --locked --bin uniffi-bindgen-swift -- \
        "$LIB_PATH" \
        "$swift_out" \
        --swift-sources --headers
    cargo run --locked --bin uniffi-bindgen-swift -- \
        "$LIB_PATH" \
        "$swift_out" \
        --modulemap --module-name RoostFFI --modulemap-filename module.modulemap

    mkdir -p "$swift_out/module-cache"
    for name in TransportBindingBindings PreparedOperations SecureStorageUnexpectedError EvidenceBundleVectors; do
        run_swift_harness "$name.swift" "$name" "$swift_out"
    done
}

jna_jar() {
    local jar_dir="$OUT/jna"
    local jar="${JNA_JAR:-$jar_dir/jna-$JNA_VERSION.jar}"
    if [[ ! -s "$jar" ]]; then
        need_tool curl
        mkdir -p "$jar_dir"
        curl --fail --location --silent --show-error \
            "https://repo1.maven.org/maven2/net/java/dev/jna/jna/$JNA_VERSION/jna-$JNA_VERSION.jar" \
            --output "$jar" || return
    fi
    echo "260c4b1e22b1db9e110ee441c4f13ce115f841fa48c41d78750986214b395557  $jar" \
        | shasum -a 256 --check >&2 || return
    echo "$jar"
}

run_kotlin_harness() {
    local source="$1"
    local name="$2"
    local kotlin_out="$3"
    local jna="$4"

    kotlinc \
        "$kotlin_out/io/github/relaynet/roost/roost_client.kt" \
        "$HARNESS/$source" \
        -cp "$jna" \
        -include-runtime \
        -d "$kotlin_out/$name.jar"
    run_kotlin_class "$kotlin_out/$name.jar:$jna" "io.github.relaynet.roost.${name}Kt"
}

run_kotlin_class() {
    local classpath="$1"
    local class_name="$2"

    # jna.library.path is the property JNA's own loader reads; java.library.path alone is not
    # enough for the direct-mapped Native.register call in the generated bindings. The
    # DYLD_LIBRARY_PATH exported above cannot cover for it on macOS either, because SIP strips
    # DYLD_* from the environment when launching a system binary such as /usr/bin/java.
    if command -v java >/dev/null 2>&1 && java -version >/dev/null 2>&1; then
        run_check java \
            -Djna.library.path="$ROOT/target/debug" \
            -Djava.library.path="$ROOT/target/debug" \
            -cp "$classpath" \
            "$class_name"
        return
    fi

    if command -v kotlin >/dev/null 2>&1; then
        run_check kotlin \
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

    cargo run --locked --bin uniffi-bindgen -- generate \
        "$LIB_PATH" \
        --language kotlin \
        --out-dir "$kotlin_out"

    local jna
    jna="$(jna_jar)"
    for name in TransportBindingBindings PreparedOperations SecureStorageUnexpectedError EvidenceBundleVectors; do
        run_kotlin_harness "$name.kt" "$name" "$kotlin_out" "$jna"
    done
}

cd "$ROOT"
need_tool cargo
need_tool python3
cargo build --locked -p roost-client

case "${ROOST_BINDING_LANGS:-swift,kotlin}" in
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
        echo "unsupported ROOST_BINDING_LANGS value: ${ROOST_BINDING_LANGS:-swift,kotlin}" >&2
        exit 2
        ;;
esac
