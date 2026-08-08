#!/usr/bin/env bash
# Verify the local quality-harness command surface without invoking toolchains.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

output="$("$ROOT/scripts/check.sh" --help)"
for command in doctor quick full format lint test docs coverage supply-chain shell agent-config bindings fuzz release; do
    if ! grep -Fqx "  $command" <<<"$output"; then
        echo "missing quality-harness command in help: $command" >&2
        exit 1
    fi
done

if [[ "${AETHER_CHECK_HARNESS_COMMAND_SURFACE_ONLY:-}" == "1" ]]; then
    exit 0
fi

temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT
mkdir "$temp_dir/bin"

cat > "$temp_dir/bin/cargo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$AETHER_CHECK_LOG"
EOF
for tool in cargo-deny shellcheck actionlint; do
    cat > "$temp_dir/bin/$tool" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
done
cat > "$temp_dir/bin/rustup" <<'EOF'
#!/usr/bin/env bash
if [[ "$1 $2 $3" == "component list --installed" ]]; then
    printf '%s\n' rustfmt-aarch64-apple-darwin clippy-aarch64-apple-darwin llvm-tools-aarch64-apple-darwin
fi
EOF
chmod +x \
    "$temp_dir/bin/cargo" \
    "$temp_dir/bin/cargo-deny" \
    "$temp_dir/bin/shellcheck" \
    "$temp_dir/bin/actionlint" \
    "$temp_dir/bin/rustup"

export AETHER_CHECK_LOG="$temp_dir/cargo.log"
export AETHER_TEST_BASE_HAS_COVERAGE AETHER_TEST_BASE_FLOORS
export PATH="$temp_dir/bin:$PATH"
"$ROOT/scripts/check.sh" quick

grep -Fx 'fmt --all -- --check' "$AETHER_CHECK_LOG"
grep -Fx 'clippy --locked --workspace --all-targets --all-features -- -D warnings' "$AETHER_CHECK_LOG"
if grep -Eq '^(test|doc) ' "$AETHER_CHECK_LOG"; then
    echo "quick must not run tests or documentation" >&2
    exit 1
fi

cat > "$temp_dir/bin/git" <<'EOF'
#!/usr/bin/env bash
case "$*" in
    'diff --name-only base...HEAD') printf '%s\n' crates/aether-uniffi/src/lib.rs scripts/build/xcframework.sh ;;
    'diff --name-only') printf '%s\n' scripts/release/reproducible-mobile-artifacts.sh ;;
    'diff --cached --name-only') printf '%s\n' crates/aether-uniffi/src/lib.rs ;;
    'ls-files --others --exclude-standard') printf '%s\n' scripts/build/new-package.sh ;;
    'cat-file -e '*':coverage.toml') [[ "${AETHER_TEST_BASE_HAS_COVERAGE:-0}" == "1" ]] ;;
    'show '*':coverage.toml') printf '%s\n' "${AETHER_TEST_BASE_FLOORS:-}" ;;
    'rev-parse --verify '*'^{commit}') exit 0 ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$temp_dir/bin/git"

AETHER_CHECK_HARNESS_SOURCE_ONLY=1 source "$ROOT/scripts/check.sh"

require_rust_component llvm-tools-preview

self_test_log="$temp_dir/harness-self-test.log"
run_harness_self_test() {
    printf 'invoked\n' >> "$self_test_log"
}
shell
grep -Fxq invoked "$self_test_log"

changed="$(changed_paths base)"
for path in \
    crates/aether-uniffi/src/lib.rs \
    scripts/build/xcframework.sh \
    scripts/release/reproducible-mobile-artifacts.sh \
    scripts/build/new-package.sh; do
    grep -Fqx "$path" <<<"$changed"
done
if [[ "$(grep -Fxc 'crates/aether-uniffi/src/lib.rs' <<<"$changed")" -ne 1 ]]; then
    echo "changed paths must be deduplicated" >&2
    exit 1
fi
paths_need_bindings <<<"scripts/build/new-package.sh"
paths_need_release <<<"scripts/build/xcframework.sh"
paths_need_release <<<"scripts/release/reproducible-mobile-artifacts.sh"

for path in \
    crates/aether-core/src/lib.rs \
    crates/aether-crypto/src/lib.rs \
    crates/aether-uniffi/src/lib.rs \
    Cargo.toml \
    Cargo.lock \
    rust-toolchain.toml \
    packaging/android/build.gradle.kts; do
    paths_need_bindings <<<"$path" || {
        echo "binding routing missed local input: $path" >&2
        exit 1
    }
done

for path in crates/aether-core/src/lib.rs crates/aether-crypto/src/lib.rs; do
    if paths_need_release <<<"$path"; then
        echo "release routing included ordinary source input: $path" >&2
        exit 1
    fi
done

for path in \
    crates/aether-uniffi/src/lib.rs \
    Cargo.toml \
    Cargo.lock \
    rust-toolchain.toml \
    packaging/android/build.gradle.kts; do
    paths_need_release <<<"$path" || {
        echo "release routing missed distribution input: $path" >&2
        exit 1
    }
done

write_floors() {
    printf '[coverage]\naether-core = %s\naether-crypto = %s\naether-uniffi = %s\n' \
        "$2" "$3" "$4" > "$1"
}

floor_file="$temp_dir/coverage.toml"
error_file="$temp_dir/floor-error"

write_floors "$floor_file" 79.99 97.46 67.60
if (
    COVERAGE_FLOORS="$floor_file"
    AETHER_COVERAGE_FLOOR_BASE=pre-coverage
    AETHER_TEST_BASE_HAS_COVERAGE=0
    AETHER_COVERAGE_FLOOR_LOWERING_APPROVED=1
    coverage_floor aether-core
) > /dev/null 2> "$error_file"; then
    echo "sub-80 Core floor passed against a base without coverage.toml" >&2
    exit 1
fi
grep -Fq 'coverage floor for aether-core must be at least 80' "$error_file"

write_floors "$floor_file" 86.00 97.46 67.60
if (
    COVERAGE_FLOORS="$floor_file"
    unset AETHER_COVERAGE_FLOOR_BASE AETHER_COVERAGE_FLOOR_LOWERING_APPROVED
    AETHER_TEST_BASE_HAS_COVERAGE=1
    AETHER_TEST_BASE_FLOORS=$'[coverage]\naether-core = 86.68\naether-crypto = 97.46\naether-uniffi = 67.60'
    coverage_floor aether-core
) > /dev/null 2> "$error_file"; then
    echo "normal coverage accepted an unapproved working-tree floor decrease" >&2
    exit 1
fi
grep -Fq 'coverage floor for aether-core decreased from 86.68 to 86.00' "$error_file"

write_floors "$floor_file" invalid 97.46 67.60
if (
    COVERAGE_FLOORS="$floor_file"
    AETHER_TEST_BASE_HAS_COVERAGE=0
    coverage_floor aether-core
) > /dev/null 2> "$error_file"; then
    echo "malformed coverage floor passed" >&2
    exit 1
fi
grep -Fq 'coverage floor for aether-core must be numeric' "$error_file"

write_floors "$floor_file" 86.00 97.46 67.60
if (
    COVERAGE_FLOORS="$floor_file"
    AETHER_COVERAGE_FLOOR_BASE=base
    unset AETHER_COVERAGE_FLOOR_LOWERING_APPROVED
    AETHER_TEST_BASE_HAS_COVERAGE=1
    AETHER_TEST_BASE_FLOORS=$'[coverage]\naether-core = malformed\naether-crypto = 97.46\naether-uniffi = 67.60'
    coverage_floor aether-core
) > /dev/null 2> "$error_file"; then
    echo "malformed historical coverage floor passed" >&2
    exit 1
fi
grep -Fq 'coverage floor for aether-core in base is malformed' "$error_file"

write_floors "$floor_file" 86.00 97.46 67.60
approved_floor="$(
    COVERAGE_FLOORS="$floor_file"
    AETHER_COVERAGE_FLOOR_BASE=base
    AETHER_COVERAGE_FLOOR_LOWERING_APPROVED=1
    AETHER_TEST_BASE_HAS_COVERAGE=1
    AETHER_TEST_BASE_FLOORS=$'[coverage]\naether-core = 86.68\naether-crypto = 97.46\naether-uniffi = 67.60'
    coverage_floor aether-core
)"
[[ "$approved_floor" == "86.00" ]] || {
    echo "explicitly approved above-80 floor decrease failed" >&2
    exit 1
}

: > "$AETHER_CHECK_LOG"
supply_chain
grep -Fxq 'deny --locked --workspace --all-features check' "$AETHER_CHECK_LOG"

missing_rustup="$temp_dir/missing-rustup"
mkdir "$missing_rustup"
for tool in cargo cargo-fuzz; do
    printf '#!/usr/bin/env bash\nexit 0\n' > "$missing_rustup/$tool"
    chmod +x "$missing_rustup/$tool"
done
if (PATH="$missing_rustup:/usr/bin:/bin" fuzz) > /dev/null 2> "$error_file"; then
    echo "fuzz passed without rustup" >&2
    exit 1
fi
grep -Fq 'missing required tool: rustup' "$error_file"

missing_toolchain="$temp_dir/missing-toolchain"
mkdir "$missing_toolchain"
for tool in cargo cargo-fuzz; do
    printf '#!/usr/bin/env bash\nexit 0\n' > "$missing_toolchain/$tool"
    chmod +x "$missing_toolchain/$tool"
done
cat > "$missing_toolchain/rustup" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "toolchain" && "$2" == "list" ]]; then
    echo nightly-aarch64-apple-darwin
    exit 0
fi
exit 1
EOF
chmod +x "$missing_toolchain/rustup"
if (
    AETHER_FUZZ_TOOLCHAIN=nightly-2099-01-01 \
        PATH="$missing_toolchain:/usr/bin:/bin" fuzz
) > /dev/null 2> "$error_file"; then
    echo "fuzz accepted a different installed nightly than the configured toolchain" >&2
    exit 1
fi
grep -Fq 'missing Rust toolchain: nightly-2099-01-01' "$error_file"

binding_tools="$temp_dir/binding-tools"
mkdir "$binding_tools"
for tool in cargo kotlinc java swiftc; do
    printf '#!/usr/bin/env bash\nexit 0\n' > "$binding_tools/$tool"
    chmod +x "$binding_tools/$tool"
done
if (
    AETHER_BINDING_REPLAY_LANGS=kotlin PATH="$binding_tools" require_binding_tools
) > /dev/null 2> "$error_file"; then
    echo "Kotlin binding tools passed without curl or JNA_JAR" >&2
    exit 1
fi
grep -Fq 'missing required tool: curl' "$error_file"
AETHER_BINDING_REPLAY_LANGS=swift PATH="$binding_tools" require_binding_tools
JNA_JAR="$temp_dir/jna.jar" AETHER_BINDING_REPLAY_LANGS=kotlin \
    PATH="$binding_tools" require_binding_tools

AETHER_BINDING_FIXTURE_SOURCE_ONLY=1 source "$ROOT/scripts/test/binding-fixture-replay.sh"
checksum_fixture="$temp_dir/jna-checksum-fixture"
printf 'trusted-jna-fixture' > "$checksum_fixture"
fixture_sha256='af0086c406a19b74e441512408b26e031a97a865f5aef7db573cdc2d8a2e0897'
verify_sha256 "$checksum_fixture" "$fixture_sha256"

JNA_SHA256='0000000000000000000000000000000000000000000000000000000000000000'
if JNA_JAR="$checksum_fixture" jna_jar > /dev/null 2> "$error_file"; then
    echo "custom JNA path passed with a mismatched checksum" >&2
    exit 1
fi
grep -Fq 'JNA checksum mismatch' "$error_file"

curl_log="$temp_dir/curl.log"
cat > "$temp_dir/bin/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$AETHER_CURL_LOG"
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--output" ]]; then
        printf 'trusted-jna-fixture' > "$2"
        exit 0
    fi
    shift
done
exit 1
EOF
chmod +x "$temp_dir/bin/curl"
export AETHER_CURL_LOG="$curl_log"
unset JNA_JAR
OUT="$temp_dir/jna-download"
JNA_SHA256="$fixture_sha256"
downloaded_jna="$(jna_jar)"
[[ "$downloaded_jna" == "$OUT/jna/jna-$JNA_VERSION.jar" ]]
verify_sha256 "$downloaded_jna" "$fixture_sha256"
grep -Fq -- '--proto =https' "$curl_log"
grep -Fq -- '--proto-redir =https' "$curl_log"

cat > "$temp_dir/bin/swiftc" <<'EOF'
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-o" ]]; then
        output="$2"
        printf '#!/usr/bin/env bash\nexit 0\n' > "$output"
        chmod +x "$output"
        exit 0
    fi
    shift
done
exit 1
EOF
chmod +x "$temp_dir/bin/swiftc"
: > "$AETHER_CHECK_LOG"
AETHER_BINDING_REPLAY_LANGS=swift "$ROOT/scripts/test/binding-fixture-replay.sh"
grep -Fxq 'build --locked -p aether-uniffi --features fixture-replay' "$AETHER_CHECK_LOG"
[[ "$(grep -Ec '^run --locked --features fixture-replay --bin uniffi-bindgen-swift -- ' "$AETHER_CHECK_LOG")" -eq 2 ]]

: > "$AETHER_CHECK_LOG"
run_kotlin_harness() { :; }
JNA_JAR="$checksum_fixture"
JNA_SHA256="$fixture_sha256"
run_kotlin
grep -Eq '^run --locked --features fixture-replay --bin uniffi-bindgen -- generate ' \
    "$AETHER_CHECK_LOG"

full_log="$temp_dir/full.log"
log_full_suite() {
    printf '%s\n' "$1" >> "$full_log"
}
agent_config() { log_full_suite agent-config; }
quick() {
    log_full_suite quick
    agent_config
}
test_workspace() { log_full_suite test; }
docs() { log_full_suite docs; }
coverage() { log_full_suite coverage; }
supply_chain() { log_full_suite supply-chain; }
shell() { log_full_suite shell; }
fuzz() { log_full_suite fuzz; }
bindings() { log_full_suite bindings; }
release() { log_full_suite release; }

full
if [[ "$(grep -Fxc agent-config "$full_log")" -ne 1 ]]; then
    echo "full must invoke agent configuration exactly once" >&2
    exit 1
fi
