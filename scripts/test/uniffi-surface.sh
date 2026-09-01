#!/usr/bin/env bash
# Every public `aether-core` method is either reachable through the bindings or
# deliberately listed here as not being.
#
# The UniFFI layer is a hand-written translation, and `cargo test` says nothing
# about it: every Rust test exercises `aether-core` directly, where the
# behaviour is correct. That is how four identity methods shipped with zero
# wrappers — generated Kotlin and Swift could name the new state kind but could
# not persist a capability received from a peer — and no green run anywhere
# reported it.
#
# So this does not check that a wrapper is *correct*; the binding harnesses in
# `crates/aether-uniffi/tests/bindings/` do that, and a wrapper without one is
# still untested. This checks the cheaper, earlier property: that adding a
# capability to the core cannot silently leave mobile unable to reach it. A new
# name here is a decision to be made rather than an omission to be discovered
# two releases later.
#
# The match is deliberately by name and deliberately loose — anywhere in
# `aether-uniffi/src`, not only as a `pub fn` — because a core method reached by
# a differently-named wrapper is still reached. Loose here means the failures it
# reports are worth reading: it only fires when a name appears nowhere at all.
set -euo pipefail

cd "$(dirname "$0")/../.."

# Not exported, with the reason. Anything not on this list must be reachable.
#
# Keep it explicit rather than pattern-matched: `fuzz_*` could have been one
# glob, but then a real method named `fuzz_something` would be skipped without
# anyone choosing that.
ALLOWED=
# Avoid a here-document inside command substitution: macOS Bash 3.2 reparses quoted heredoc bodies
# there and can treat literal apostrophes as shell syntax.
IFS= read -r -d '' ALLOWED <<'EOF' || true
delivered_inbox_authorization           read used by the core's own redistribution pass; mobile drives that through record_/peer_ instead
diffie_hellman                          raw primitive; the bindings expose the protocol operations built on it, never the operation itself
from_bytes_with_hardening_limits        decode-limit variant used by the fuzz targets; the bindings take the default limits
fuzz_decode_discovery_key_blob          fuzz target entry point
fuzz_decode_one_time_prekey_pool        fuzz target entry point
fuzz_decode_protocol_state_blob         fuzz target entry point
fuzz_decode_sealed_sender_envelope      fuzz target entry point
fuzz_decode_signed_prekey_blob          fuzz target entry point
fuzz_deduplication_digest               fuzz target entry point
fuzz_unpad_sealed_payload               fuzz target entry point
prekey_bundle_lookup_key                internal index key; callers pass the bundle, not its key
set_session_state_with_peer_identity_key lower-level variant; key_store/session.rs calls it, the bindings take the checked wrapper
to_bytes_with_hardening_limits          encode-limit variant, pairs with from_bytes_with_hardening_limits
with_hardening_limits                   builder for the two above
EOF

allowed_names=$(echo "$ALLOWED" | awk 'NF {print $1}' | sort -u)

core_names=$(
    grep -rhoE "^[[:space:]]*pub (async )?fn [a-z_0-9]+" crates/aether-core/src --include='*.rs' |
        sed -E 's/.*fn //' | sort -u
)

# Every identifier in the binding crate, not just its own `pub fn` names: a
# core method called through a renamed wrapper is still reachable.
binding_names=$(grep -rhoE "[a-z_0-9]+" crates/aether-uniffi/src --include='*.rs' | sort -u)

unreachable=$(comm -23 <(echo "$core_names") <(echo "$binding_names"))
unexplained=$(comm -23 <(echo "$unreachable" | sort -u) <(echo "$allowed_names"))

if [ -n "$unexplained" ]; then
    echo "aether-core methods that no binding reaches, and that this script does not explain:" >&2
    echo "$unexplained" | sed 's/^/  /' >&2
    cat >&2 <<'EOF'

Each one is a capability the core has and Kotlin and Swift do not. Either:

  - wrap it in crates/aether-uniffi/src, and cover it from a harness in
    crates/aether-uniffi/tests/bindings/ — a wrapper no harness calls is the
    same blind spot one layer further in; or
  - add it to ALLOWED in this script with the reason it stays internal.

EOF
    exit 1
fi

# A name that stops being unreachable has usually just been wrapped, which is
# fine and wants no ceremony. One that no longer exists is a stale entry, and
# stale entries are how an allowlist quietly starts permitting things nobody
# chose.
stale=$(comm -13 <(echo "$core_names") <(echo "$allowed_names"))
if [ -n "$stale" ]; then
    echo "ALLOWED names in $0 that are no longer public methods of aether-core:" >&2
    echo "$stale" | sed 's/^/  /' >&2
    echo >&2
    echo "Remove them, so the list keeps describing the code it is about." >&2
    exit 1
fi

echo "uniffi surface: $(echo "$core_names" | wc -l | tr -d ' ') core methods, all reachable or explained"
