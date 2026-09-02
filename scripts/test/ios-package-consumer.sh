#!/usr/bin/env bash
#
# Verify that a generated iOS Swift Package can be consumed by an app/test target.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PACKAGE_INPUT="${1:-}"
WORK="$ROOT/target/ios-package-consumer"
TEST_SOURCE="$ROOT/crates/aether-uniffi/tests/bindings/Issue124PackageConsumerTests.swift"
FIXTURES="$ROOT/crates/aether-core/tests/fixtures"
SAFE_EXTRACT="$ROOT/scripts/release/extract-zip-safely.sh"

usage() {
    echo "usage: $0 <path-to-generated-ios-package-or-archive>" >&2
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

if [[ -d "$PACKAGE_INPUT" ]]; then
    PACKAGE_DIR="$(cd "$PACKAGE_INPUT" && pwd -P)"
elif [[ -f "$PACKAGE_INPUT" ]]; then
    VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
    ARCHIVE="$(cd "$(dirname "$PACKAGE_INPUT")" && pwd -P)/$(basename "$PACKAGE_INPUT")"
    ARCHIVE_ROOT="$WORK/archive-input"
    rm -rf "${ARCHIVE_ROOT:?}"
    "$SAFE_EXTRACT" "$ARCHIVE" "$ARCHIVE_ROOT"
    PACKAGE_DIR="$ARCHIVE_ROOT/aether-ios-v$VERSION"
else
    echo "missing generated iOS package or archive: $PACKAGE_INPUT" >&2
    exit 2
fi

if [[ ! -d "$PACKAGE_DIR/Artifacts/Aether.xcframework" ]]; then
    echo "missing Aether.xcframework in package artifacts: $PACKAGE_DIR" >&2
    exit 2
fi

destination() {
    if [[ -n "${AETHER_IOS_DESTINATION:-}" ]]; then
        echo "$AETHER_IOS_DESTINATION"
        return
    fi

    local udid
    udid="$(xcrun simctl list devices available |
        awk -F '[()]' '/iPhone/ { print $2; exit }')"
    if [[ -z "$udid" ]]; then
        echo "no available iPhone simulator; set AETHER_IOS_DESTINATION to override" >&2
        exit 2
    fi
    echo "platform=iOS Simulator,id=$udid"
}

swift_string_literal() {
    local value="$1"

    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    printf '"%s"' "$value"
}

write_consumer_package() {
    local consumer="$1"
    local package="$2"
    local package_literal

    rm -rf "$consumer"
    mkdir -p "$consumer/Tests/AetherPackageConsumerTests/Resources"
    cp "$TEST_SOURCE" "$consumer/Tests/AetherPackageConsumerTests/Issue124PackageConsumerTests.swift"
    cp "$FIXTURES/protocol_state_blobs_v1.json" "$consumer/Tests/AetherPackageConsumerTests/Resources/"
    cp "$FIXTURES/sealed_sender_session_messages_v1.json" "$consumer/Tests/AetherPackageConsumerTests/Resources/"
    package_literal="$(swift_string_literal "$package")"

    cat > "$consumer/Package.swift" <<PACKAGE
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AetherPackageConsumer",
    platforms: [.iOS(.v13)],
    dependencies: [
        .package(name: "AetherIOS", path: $package_literal),
    ],
    targets: [
        .testTarget(
            name: "AetherPackageConsumerTests",
            dependencies: [
                .product(name: "Aether", package: "AetherIOS"),
            ],
            resources: [.copy("Resources")]
        ),
    ]
)
PACKAGE
}

run_consumer() {
    local consumer="$1"
    local destination="$2"

    (
        cd "$consumer"
        xcodebuild \
            -scheme AetherPackageConsumer-Package \
            -destination "$destination" \
            -derivedDataPath "$consumer/.derived-data" \
            CODE_SIGNING_ALLOWED=NO \
            test
    )
}

DESTINATION="$(destination)"
HAPPY="$WORK/happy"
BROKEN_PACKAGE="$WORK/broken-package"
NEGATIVE="$WORK/negative"

write_consumer_package "$HAPPY" "$PACKAGE_DIR"
run_consumer "$HAPPY" "$DESTINATION"

rm -rf "$BROKEN_PACKAGE"
cp -R "$PACKAGE_DIR" "$BROKEN_PACKAGE"
rm -rf "$BROKEN_PACKAGE/Artifacts/Aether.xcframework"

write_consumer_package "$NEGATIVE" "$BROKEN_PACKAGE"
if run_consumer "$NEGATIVE" "$DESTINATION"; then
    echo "negative package verification unexpectedly passed" >&2
    exit 1
fi

echo "iOS package consumer verification passed"
