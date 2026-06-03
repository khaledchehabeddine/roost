#!/usr/bin/env bash
set -euo pipefail

output="${1:-docs/security/unsafe-baseline.md}"
root="$(git rev-parse --show-toplevel)"
target_dir="$(mktemp -d "${TMPDIR:-/tmp}/aether-geiger.XXXXXX")"
mkdir -p "$(dirname "$output")"

cleanup() {
  rm -rf "$target_dir"
}

trap cleanup EXIT

run_geiger() {
  local package="$1"
  local report warnings status
  report="$(mktemp "${TMPDIR:-/tmp}/aether-geiger-report.XXXXXX")"
  warnings="$(mktemp "${TMPDIR:-/tmp}/aether-geiger-warnings.XXXXXX")"

  set +e
  CARGO_TARGET_DIR="$target_dir" cargo geiger \
    --manifest-path "$root/crates/$package/Cargo.toml" \
    --all-targets \
    --all-dependencies \
    --no-indent \
    --output-format GitHubMarkdown \
    --locked \
    >"$report" 2>"$warnings"
  status="$?"
  set -e

  if [ "$status" -ne 0 ] && ! geiger_warning_only "$report" "$warnings"; then
    cat "$warnings" >&2
    cat "$report" >&2
    rm -f "$report" "$warnings"
    return "$status"
  fi

  normalize_report "$report"
  rm -f "$report" "$warnings"
}

geiger_warning_only() {
  local report="$1"
  local warnings="$2"
  local warning_pattern
  warning_pattern='^( *Removed [0-9]+ files.*| *Fresh .+| *Checking .+| *Compiling .+| *Finished .+| *Scanning done|Failed to match \(ignoring source\) package: .+|Failed to parse file: .+|WARNING: Dependency file was never scanned: .+|error: Found [0-9]+ warnings|\{"\$message_type":"artifact".+\})$'

  grep -q "Metric output format" "$report" && ! grep -Evq "$warning_pattern" "$warnings"
}

normalize_report() {
  local report="$1"
  sed -n '1,/^Functions/p' "$report"
  echo
  awk '/^[0-9]+\/[0-9]+/ && NF >= 7 { print }' "$report" | LC_ALL=C sort -u
  echo
  echo "Totals"
  awk '/^[0-9]+\/[0-9]+/ && NF == 5 { total = $0 } END { if (total != "") print total }' "$report"
}

{
  echo "# Unsafe Baseline"
  echo
  echo 'Generated with `cargo geiger --manifest-path <crate>/Cargo.toml --all-targets --all-dependencies --no-indent --output-format GitHubMarkdown --locked`.'
  echo
  echo "The generator sorts dependency rows to avoid cargo-geiger tree-order churn."
  echo "It tolerates cargo-geiger's known source-match warning after a report body is produced."
  echo

  for package in aether-crypto aether-core aether-uniffi; do
    echo "## $package"
    echo
    run_geiger "$package"
    echo
  done
} > "$output"
