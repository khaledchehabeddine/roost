#!/usr/bin/env bash
set -euo pipefail

targets=(
  message_decode
  protocol_state_blob_decode
  prekey_store_decode
  sender_certificate_validate
  sealed_frame_envelope_decode
  sealed_payload_padding
)

toolchain="${AETHER_FUZZ_TOOLCHAIN:-nightly}"
cargo_fuzz=(cargo "+${toolchain}" fuzz)

cargo "+${toolchain}" metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 >/dev/null
"${cargo_fuzz[@]}" --version >/dev/null

runs="${AETHER_FUZZ_RUNS:-64}"
seconds="${AETHER_FUZZ_SECONDS:-}"
smoke_root="fuzz/target/smoke-corpus"
mkdir -p "$smoke_root"

for target in "${targets[@]}"; do
  "${cargo_fuzz[@]}" build --fuzz-dir fuzz "$target"

  args=(-timeout=10)
  if [[ -n "$seconds" ]]; then
    args+=("-max_total_time=$seconds")
  else
    args+=("-runs=$runs")
  fi

  run_corpus="$smoke_root/$target-$$"
  mkdir -p "$run_corpus"
  for seed in "fuzz/corpus/$target"/[0-9][0-9][0-9]-*; do
    [[ -e "$seed" ]] || continue
    cp "$seed" "$run_corpus/"
  done

  "${cargo_fuzz[@]}" run --fuzz-dir fuzz "$target" "$run_corpus" -- "${args[@]}"
done
