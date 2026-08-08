#!/usr/bin/env bash
# Verify the local quality-harness command surface without invoking toolchains.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
REAL_GIT="$(command -v git)"
REAL_JQ="$(command -v jq)"

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
repo_temp_dir="$(mktemp -d "$ROOT/.aether-check-harness.XXXXXX")"
trap 'rm -rf "$temp_dir" "$repo_temp_dir"' EXIT
mkdir "$temp_dir/bin"
printf '%s\n' 'reviewed body' > "$repo_temp_dir/body.md"
printf '%s\n' 'outside body' > "$temp_dir/body.md"
mkfifo "$repo_temp_dir/body.fifo"
ln -s "$repo_temp_dir/body.md" "$repo_temp_dir/body-link.md"
error_file="$temp_dir/error"

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
    '-c remote.origin.mirror=false -c push.gpgSign=false -c push.pushOption= push --no-follow-tags -u origin HEAD') printf '%s\n' "$*" >> "$AETHER_TEST_PUSH_LOG" ;;
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

export AETHER_TEST_PUSH_LOG="$temp_dir/push.log"
: > "$AETHER_TEST_PUSH_LOG"
"$ROOT/scripts/push-reviewed-branch.sh"
grep -Fxq -- '-c remote.origin.mirror=false -c push.gpgSign=false -c push.pushOption= push --no-follow-tags -u origin HEAD' "$AETHER_TEST_PUSH_LOG"
if "$ROOT/scripts/push-reviewed-branch.sh" --force > /dev/null 2> "$error_file"; then
    echo "reviewed push wrapper accepted arguments" >&2
    exit 1
fi
if [[ "$(wc -l < "$AETHER_TEST_PUSH_LOG")" -ne 1 ]]; then
    echo "rejected reviewed push arguments reached Git" >&2
    exit 1
fi

push_probe="$temp_dir/push-probe"
mkdir -p "$push_probe/work/scripts"
fixture_git() {
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 "$REAL_GIT" "$@"
}
fixture_git init --bare -b main "$push_probe/remote.git" > /dev/null
fixture_git -C "$push_probe/work" init -b review > /dev/null
fixture_git -C "$push_probe/work" config user.name 'Aether Harness'
fixture_git -C "$push_probe/work" config user.email 'harness@example.invalid'
fixture_git -C "$push_probe/work" config commit.gpgSign false
fixture_git -C "$push_probe/work" config tag.gpgSign false
fixture_git -C "$push_probe/work" config push.followTags true
fixture_git -C "$push_probe/work" commit --allow-empty -m 'reviewed branch' > /dev/null
fixture_git -C "$push_probe/work" tag -a v-review-probe -m 'unreviewed tag'
fixture_git -C "$push_probe/work" remote add origin "$push_probe/remote.git"
fixture_git -C "$push_probe/work" config remote.origin.mirror true
cat > "$push_probe/global.gitconfig" <<'EOF'
[push]
    gpgSign = true
    pushOption = ci.skip
EOF
cp "$ROOT/scripts/push-reviewed-branch.sh" "$push_probe/work/scripts/"
(
    cd "$push_probe/work"
    GIT_CONFIG_GLOBAL="$push_probe/global.gitconfig" \
        GIT_CONFIG_NOSYSTEM=1 \
        PATH="$(dirname "$REAL_GIT"):/usr/bin:/bin" \
        scripts/push-reviewed-branch.sh > /dev/null
)
fixture_git --git-dir="$push_probe/remote.git" \
    show-ref --verify --quiet refs/heads/review
if fixture_git --git-dir="$push_probe/remote.git" \
    show-ref --verify --quiet refs/tags/v-review-probe; then
    echo "reviewed push wrapper followed an unreviewed annotated tag" >&2
    exit 1
fi

raw_push_hook="$ROOT/scripts/hooks/enforce-git-boundary.sh"
expect_shell_denied() {
    local command="$1"
    local hook_input
    hook_input="$(jq -cn --arg command "$command" '{tool_input: {command: $command}}')"
    if printf '%s\n' "$hook_input" | bash "$raw_push_hook" > /dev/null 2> "$error_file"; then
        echo "raw push hook allowed: $command" >&2
        exit 1
    else
        local status="$?"
        if [[ "$status" -ne 2 ]]; then
            echo "raw push hook returned $status instead of 2 for: $command" >&2
            exit 1
        fi
    fi
}

expect_shell_denied 'git push origin main'
expect_shell_denied 'git --paginate push --force origin main'
expect_shell_denied 'git -P push --force origin main'
expect_shell_denied 'git --git-dir=.git push --force origin main'
expect_shell_denied '/usr/bin/git -c core.hooksPath=/dev/null push origin main'
expect_shell_denied "'git' --no-pager 'push' origin main"
expect_shell_denied $'cd /tmp\ngit --paginate push --force origin main'
expect_shell_denied $'git status\ngit push origin main'
expect_shell_denied "g''it push origin main"
expect_shell_denied 'g\it push origin main'
expect_shell_denied "$'\\x67\\x69\\x74' push origin main"
expect_shell_denied $'"g\\\nit" push origin main'
expect_shell_denied '"g\it" status'
expect_shell_denied '"c\argo" test'
expect_shell_denied 'bash "scripts/chec\k.sh" --help'
# shellcheck disable=SC2016 # Submit the expansion syntax literally.
expect_shell_denied 'G=g; ${G}it push origin main'
expect_shell_denied 'time git push origin main'
expect_shell_denied "eval 'git push origin main'"
expect_shell_denied 'builtin command git push origin main'
expect_shell_denied '! git push origin main'
expect_shell_denied '! scripts/push-reviewed-branch.sh'
expect_shell_denied "awk 'BEGIN { system(\"git push origin main\") }'"
expect_shell_denied "python3 -c 'import subprocess; subprocess.run([\"scripts/push-reviewed-branch.sh\"])'"
expect_shell_denied "perl -e 'exec \"scripts/push-reviewed-branch.sh\"'"
expect_shell_denied 'source scripts/push-reviewed-branch.sh'
expect_shell_denied '. scripts/push-reviewed-branch.sh'
expect_shell_denied '/Applications/Xcode.app/Contents/Developer/usr/libexec/git-core/git-push origin main'
expect_shell_denied 'bash scripts/push-reviewed-branch.sh'
expect_shell_denied 'bash scripts/*reviewed*'
expect_shell_denied 'bash scripts/[p]ush-reviewed-branch.sh'
expect_shell_denied 'sh scripts/push-*.sh'
expect_shell_denied './scripts/push-reviewed-branch.sh'
expect_shell_denied 'scripts//push-reviewed-branch.sh'
expect_shell_denied 'scripts/./push-reviewed-branch.sh'
expect_shell_denied 'scripts/push?reviewed?branch.sh'
expect_shell_denied "scripts/push-review''ed-branch.sh"
expect_shell_denied 'scripts/push-review?d-branch.sh'
expect_shell_denied 'scripts/push-reviewed-br?nch.sh'
expect_shell_denied $'"scripts/push-reviewed-br\\\nanch.sh"'
expect_shell_denied 'scripts/push-*-branch.sh'
expect_shell_denied 'scripts/push-reviewed-branch.sh && git status --short'
expect_shell_denied 'FOO=bar git push origin main'
expect_shell_denied 'env git push origin main'
expect_shell_denied 'command git push origin main'
expect_shell_denied 'exec git push origin main'
expect_shell_denied "env sh -c 'git push origin main'"
expect_shell_denied "env -S 'git push origin main'"
expect_shell_denied "sh -c 'git push origin main'"
expect_shell_denied 'if git push origin main; then :; fi'
# shellcheck disable=SC2016 # Submit the expansion syntax literally.
expect_shell_denied 'git${IFS}push origin main'
expect_shell_denied 'git publish origin main'
expect_shell_denied "rg --hostname-bin=scripts/push-reviewed-branch.sh --hyperlink-format='file://{host}{path}' Aether AGENTS.md"
expect_shell_denied "rg -n 'git push' README.md"
expect_shell_denied 'command rg --hostname-bin=/usr/bin/id Aether AGENTS.md'
expect_shell_denied 'env rg --pre=/usr/bin/id Aether AGENTS.md'
expect_shell_denied 'RIPGREP_CONFIG_PATH=/tmp/rg.conf rg Aether AGENTS.md'
expect_shell_denied 'gh pr merge 199'
expect_shell_denied 'gh -R Aurelion/aether pr merge 199'
expect_shell_denied '/opt/homebrew/bin/gh pr merge 199'
expect_shell_denied 'env gh pr merge 199'
expect_shell_denied 'gh auth token'
expect_shell_denied '/opt/homebrew/bin/gh auth token'
expect_shell_denied 'env gh auth token'
expect_shell_denied 'time gh auth token'
expect_shell_denied 'gh auth status --show-token'
expect_shell_denied 'gh auth status --show-token=true'
expect_shell_denied 'gh auth status -t'
expect_shell_denied 'gh auth status -at'
expect_shell_denied 'gh auth status --hostname --show-token'
expect_shell_denied 'gh auth status -h -t'
expect_shell_denied 'time scripts/push-reviewed-branch.sh'
expect_shell_denied 'gh pr create --base main --head review --title test --body body'
expect_shell_denied 'gh pr create --draft --head review --title test --body body'
expect_shell_denied 'gh pr create --draft --base main --title test --body body'
expect_shell_denied 'gh pr create --draft --base main --head= --title test --body body'
expect_shell_denied 'gh pr create --head review --title test --body body --web'
expect_shell_denied 'gh pr create --head review --title test --body body -w'
expect_shell_denied 'gh pr create --head review --editor'
expect_shell_denied 'gh pr create --head review --title test --body --web'
expect_shell_denied 'gh pr create --head review --base main'
expect_shell_denied 'gh pr create --draft --base main --head review --fill'
expect_shell_denied 'gh pr create --draft --base main --head review --fill-first'
expect_shell_denied 'gh pr create --draft --base main --head review --fill-verbose'
expect_shell_denied 'gh pr create --draft --base main --head review -f'
for unsafe_body_file in \
    - \
    /dev/stdin \
    /dev/tty \
    "$repo_temp_dir/body.fifo" \
    "$repo_temp_dir/body-link.md" \
    "$temp_dir/body.md"; do
    expect_shell_denied \
        "gh pr create --draft --base main --head review --title test --body-file $unsafe_body_file"
done
expect_shell_denied \
    "gh pr create --draft --base main --head review --title test --template $repo_temp_dir/body.md"
expect_shell_denied \
    "gh pr create --draft --base main --head review --title test --template=$repo_temp_dir/body.md"
expect_shell_denied \
    "gh pr create --draft --base main --head review --title test -T $repo_temp_dir/body.md"
expect_shell_denied 'gh api --method GET -XPOST repos/Aurelion/aether/issues'
expect_shell_denied 'gh api --method GET -XDELETE repos/Aurelion/aether/issues/1'
expect_shell_denied 'gh api --method GET -iXPUT repos/Aurelion/aether/pulls/199/merge'
expect_shell_denied 'gh api --method GET -iXPOST repos/Aurelion/aether/issues'
expect_shell_denied 'gh api --method GET -iX DELETE repos/Aurelion/aether/issues/1'
expect_shell_denied 'gh api --method GET -fquery=mutation repos/Aurelion/aether/graphql'
expect_shell_denied 'gh api --method GET --input=payload.json repos/Aurelion/aether/issues'

for allowed_command in \
    'git status --short' \
    'git diff --check' \
    'gh auth status' \
    'gh auth status --active --hostname github.com' \
    'gh pr create --draft --base main --head review --title test --body body' \
    "gh pr create --draft --base main --head review --title test --body-file $repo_temp_dir/body.md" \
    'gh pr view 199' \
    "sed -n '1p' .github/PULL_REQUEST_TEMPLATE.md" \
    'ls .gitignore' \
    'cargo test digital_signature' \
    'AETHER_FUZZ_SECONDS=900 scripts/ci/fuzz-smoke.sh' \
    'AETHER_COVERAGE_FLOOR_LOWERING_APPROVED=1 scripts/check.sh full --base main' \
    'time git status --short' \
    "rg --no-config -n 'git push' README.md" \
    "rg --no-config -n 'scripts/push-reviewed-branch.sh' ." \
    "find . -type f -name '*.rs'" \
    'bash -n scripts/check.sh' \
    'bash scripts/check.sh --help' \
    'scripts/push-reviewed-branch.sh'; do
    allowed_input="$(jq -cn --arg command "$allowed_command" '{tool_input: {command: $command}}')"
    printf '%s\n' "$allowed_input" | bash "$raw_push_hook"
done

expect_registered_hook_denied() {
    local config="$1"
    local working_directory="$2"
    local hook_command
    local hook_input
    hook_command="$($REAL_JQ -er '.hooks.PreToolUse[0].hooks[0].command' "$config")"
    # shellcheck disable=SC2016 # Expand command inside jq, not in this shell.
    hook_input="$($REAL_JQ -cn --arg command 'git push origin main' \
        '{tool_input: {command: $command}}')"
    if (
        cd "$working_directory"
        printf '%s\n' "$hook_input" | \
            CLAUDE_PROJECT_DIR="$ROOT" \
            PATH="$(dirname "$REAL_GIT"):$(dirname "$REAL_JQ"):/usr/bin:/bin" \
            bash -c "$hook_command" > /dev/null 2> "$error_file"
    ); then
        echo "registered hook allowed a raw push from $working_directory: $config" >&2
        exit 1
    else
        local status="$?"
        if [[ "$status" -ne 2 ]]; then
            echo "registered hook returned $status instead of 2 from $working_directory: $config" >&2
            exit 1
        fi
    fi
}

for config in "$ROOT/.claude/settings.json" "$ROOT/.codex/hooks.json"; do
    expect_registered_hook_denied "$config" "$ROOT/crates/aether-core"
    expect_registered_hook_denied "$config" "$ROOT/.git"
    expect_registered_hook_denied "$config" "$temp_dir"
done

cat > "$temp_dir/hostile-ripgrep.conf" <<'EOF'
--pre=/usr/bin/false
EOF
RIPGREP_CONFIG_PATH="$temp_dir/hostile-ripgrep.conf" \
    repository_search -Fq '# Aether' "$ROOT/AGENTS.md"

if printf '{\n' | bash "$raw_push_hook" > /dev/null 2> "$error_file"; then
    echo "raw push hook accepted malformed input" >&2
    exit 1
else
    [[ "$?" -eq 2 ]] || {
        echo "raw push hook did not fail closed on malformed input" >&2
        exit 1
    }
fi

adapter_root="$temp_dir/agent-adapters"
mkdir -p \
    "$adapter_root/.agents/instructions/skills/example" \
    "$adapter_root/.agents/instructions/rules" \
    "$adapter_root/.agents/instructions/agents" \
    "$adapter_root/.agents/skills/example" \
    "$adapter_root/.claude/skills/example" \
    "$adapter_root/.claude/rules" \
    "$adapter_root/.claude/agents" \
    "$adapter_root/.codex/agents"
cat > "$adapter_root/AGENTS.md" <<'EOF'
# Fixture instructions
EOF
cat > "$adapter_root/CLAUDE.md" <<'EOF'
@AGENTS.md
EOF
cat > "$adapter_root/.agents/instructions/skills/example/SKILL.md" <<'EOF'
# Example

Canonical instructions.
EOF
cat > "$adapter_root/.agents/instructions/rules/example.md" <<'EOF'
# Example rule
EOF
cat > "$adapter_root/.agents/instructions/agents/example.md" <<'EOF'
# Example reviewer
EOF
cat > "$adapter_root/.agents/skills/example/SKILL.md" <<'EOF'
---
name: example
description: Example adapter used by the quality-harness test.
---

Read [SKILL.md](../../instructions/skills/example/SKILL.md).
EOF
cat > "$adapter_root/.claude/skills/example/SKILL.md" <<'EOF'
---
name: example
description: Example Claude skill adapter.
---

Read [SKILL.md](../../../.agents/instructions/skills/example/SKILL.md).
EOF
cat > "$adapter_root/.claude/rules/example.md" <<'EOF'
Read [example.md](../../.agents/instructions/rules/example.md).
EOF
cat > "$adapter_root/.claude/agents/example.md" <<'EOF'
---
name: example
description: Example Claude reviewer adapter.
tools: Read
---

Read [example.md](../../.agents/instructions/agents/example.md).
EOF
cat > "$adapter_root/.codex/agents/example.toml" <<'EOF'
name = "example"
description = "Example Codex reviewer adapter."
sandbox_mode = "read-only"
developer_instructions = "Read .agents/instructions/agents/example.md"
EOF
check_agent_adapters "$adapter_root"

expect_adapter_failure() {
    local label="$1"
    local pattern="$2"
    if check_agent_adapters "$adapter_root" > /dev/null 2> "$error_file"; then
        echo "$label passed agent adapter validation" >&2
        exit 1
    fi
    grep -Fq "$pattern" "$error_file"
}

ln -s example/SKILL.md "$adapter_root/.agents/skills/alias.md"
expect_adapter_failure "symlinked Markdown adapter" 'symlinked adapter entry'
unlink "$adapter_root/.agents/skills/alias.md"

ln -s example.toml "$adapter_root/.codex/agents/alias.toml"
expect_adapter_failure "symlinked TOML adapter" 'symlinked adapter entry'
unlink "$adapter_root/.codex/agents/alias.toml"

mv "$adapter_root/.claude/agents" "$temp_dir/claude-agents.valid"
ln -s "$temp_dir/claude-agents.valid" "$adapter_root/.claude/agents"
expect_adapter_failure "symlinked adapter directory" 'adapter directory must be a regular non-symlink directory'
unlink "$adapter_root/.claude/agents"
mv "$temp_dir/claude-agents.valid" "$adapter_root/.claude/agents"

mv "$adapter_root/.claude/agents" "$temp_dir/claude-agents.broken"
ln -s "$temp_dir/missing-claude-agents" "$adapter_root/.claude/agents"
expect_adapter_failure "broken adapter directory symlink" 'adapter directory must be a regular non-symlink directory'
unlink "$adapter_root/.claude/agents"
mv "$temp_dir/claude-agents.broken" "$adapter_root/.claude/agents"

mv "$adapter_root/CLAUDE.md" "$temp_dir/root-claude.valid"
ln -s "$temp_dir/root-claude.valid" "$adapter_root/CLAUDE.md"
expect_adapter_failure "symlinked root CLAUDE adapter" 'root CLAUDE.md must be a regular non-symlink file'
unlink "$adapter_root/CLAUDE.md"
ln -s "$temp_dir/missing-root-claude" "$adapter_root/CLAUDE.md"
expect_adapter_failure "broken root CLAUDE adapter symlink" 'root CLAUDE.md must be a regular non-symlink file'
unlink "$adapter_root/CLAUDE.md"
mv "$temp_dir/root-claude.valid" "$adapter_root/CLAUDE.md"

cat > "$adapter_root/CLAUDE.md" <<'EOF'
Read [AGENTS.md](AGENTS.md).
EOF
expect_adapter_failure \
    "root CLAUDE adapter without its native import" \
    'root CLAUDE.md must contain only @AGENTS.md'
cat > "$adapter_root/CLAUDE.md" <<'EOF'
@AGENTS.md
EOF

cp "$adapter_root/.agents/skills/example/SKILL.md" "$temp_dir/agents-skill.valid"
cat > "$adapter_root/.agents/skills/example/SKILL.md" <<'EOF'
---
name: example
description: Example adapter used by the quality-harness test.
---

Read [SKILL.md](../../instructions/skills/missing/SKILL.md).
EOF
expect_adapter_failure "missing Markdown target" 'missing canonical target'
cp "$temp_dir/agents-skill.valid" "$adapter_root/.agents/skills/example/SKILL.md"

cat >> "$adapter_root/.agents/skills/example/SKILL.md" <<'EOF'
Canonical instructions copied into the adapter.
EOF
expect_adapter_failure "multiline Markdown body" 'copied adapter body'
cp "$temp_dir/agents-skill.valid" "$adapter_root/.agents/skills/example/SKILL.md"

cp "$adapter_root/.claude/rules/example.md" "$temp_dir/claude-rule.valid"
cat > "$adapter_root/README.md" <<'EOF'
# Existing non-canonical file
EOF
cat > "$adapter_root/.claude/rules/example.md" <<'EOF'
Read [README.md](../../README.md).
EOF
expect_adapter_failure "existing non-canonical Markdown target" 'non-canonical target'

cat > "$adapter_root/.claude/rules/example.md" <<'EOF'
Read [AGENTS.md](AGENTS.md).
EOF
expect_adapter_failure "nested Markdown AGENTS target" 'missing canonical target'
cp "$temp_dir/claude-rule.valid" "$adapter_root/.claude/rules/example.md"

cp "$adapter_root/.claude/skills/example/SKILL.md" "$temp_dir/claude-skill.valid"
cat > "$adapter_root/.claude/skills/example/SKILL.md" <<'EOF'
---
name: example
description: Example Claude skill adapter.
---

Read [SKILL.md](../../../.agents/skills/example/SKILL.md).
EOF
expect_adapter_failure "adapter-to-adapter route" 'non-canonical target'
cp "$temp_dir/claude-skill.valid" "$adapter_root/.claude/skills/example/SKILL.md"

cp "$adapter_root/.codex/agents/example.toml" "$temp_dir/codex-agent.valid"
cat > "$adapter_root/.codex/agents/example.toml" <<'EOF'
name = "example"
description = "Example Codex reviewer adapter."
sandbox_mode = "read-only"
developer_instructions = "Read .agents/instructions/agents/missing.md"
EOF
expect_adapter_failure "missing TOML target" 'missing canonical target'

cat > "$adapter_root/.codex/agents/example.toml" <<'EOF'
name = "example"
description = "Example Codex reviewer adapter."
sandbox_mode = "read-only"
developer_instructions = """
Read .agents/instructions/agents/example.md
Copied reviewer instructions.
"""
EOF
expect_adapter_failure "multiline TOML instruction" 'copied adapter body'

cat > "$adapter_root/.codex/agents/example.toml" <<'EOF'
name = "example"
description = "Example Codex reviewer adapter."
sandbox_mode = "read-only"
developer_instructions = "Read README.md"
EOF
expect_adapter_failure "existing non-canonical TOML target" 'non-canonical target'

mkdir "$adapter_root/outside"
cat > "$adapter_root/outside/escaped.md" <<'EOF'
# Escaped target
EOF
ln -s "$adapter_root/outside" "$adapter_root/.agents/instructions/escaped"
cat > "$adapter_root/.codex/agents/example.toml" <<'EOF'
name = "example"
description = "Example Codex reviewer adapter."
sandbox_mode = "read-only"
developer_instructions = "Read .agents/instructions/escaped/escaped.md"
EOF
expect_adapter_failure "symlink directory escape" 'non-canonical target'
cp "$temp_dir/codex-agent.valid" "$adapter_root/.codex/agents/example.toml"

ln -s example.md "$adapter_root/.agents/instructions/agents/alias.md"
cat > "$adapter_root/.codex/agents/example.toml" <<'EOF'
name = "example"
description = "Example Codex reviewer adapter."
sandbox_mode = "read-only"
developer_instructions = "Read .agents/instructions/agents/alias.md"
EOF
expect_adapter_failure "symlink target" 'non-canonical target'
cp "$temp_dir/codex-agent.valid" "$adapter_root/.codex/agents/example.toml"

cat > "$adapter_root/.claude/agents/example.md" <<'EOF'
---
name: example
description: Example Claude reviewer adapter.
tools: Read
---

Read [agents](../../.agents/instructions/agents).
EOF
expect_adapter_failure "directory target" 'non-canonical target'

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
