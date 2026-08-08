#!/usr/bin/env bash
# Run local quality checks without installing tools or mutating source files.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
COVERAGE_FLOORS="$ROOT/coverage.toml"

usage() {
    cat <<'EOF'
usage: scripts/check.sh <command> [options]

Commands:
  doctor
  quick
  full
  format
  lint
  test
  docs
  coverage
  supply-chain
  shell
  agent-config
  bindings
  fuzz
  release

Options:
  full --base <revision>  Run binding and release suites only when affected paths changed.
EOF
}

die() {
    echo "$*" >&2
    exit 2
}

tool_setup() {
    case "$1" in
        cargo-llvm-cov) echo "install with: cargo install cargo-llvm-cov --locked" ;;
        cargo-deny) echo "install with: cargo install cargo-deny --locked" ;;
        cargo-fuzz) echo "install with: cargo install cargo-fuzz --locked; rustup toolchain install nightly" ;;
        shellcheck) echo "install with: brew install shellcheck" ;;
        actionlint) echo "install with: brew install actionlint" ;;
        curl) echo "install curl and ensure curl is on PATH" ;;
        swiftc) echo "install Xcode Command Line Tools" ;;
        kotlinc) echo "install Kotlin and ensure kotlinc is on PATH" ;;
        java) echo "install a JDK and ensure java is on PATH" ;;
        gpg) echo "install GnuPG and ensure gpg is on PATH" ;;
        gh) echo "install GitHub CLI and authenticate with gh auth login" ;;
        codex) echo "install Codex CLI and ensure codex is on PATH" ;;
        git) echo "install Git and ensure git is on PATH" ;;
        jq) echo "install jq and ensure jq is on PATH" ;;
        rg) echo "install ripgrep and ensure rg is on PATH" ;;
        rustup) echo "install rustup from https://rustup.rs and ensure rustup is on PATH" ;;
        *) echo "install $1 and ensure it is on PATH" ;;
    esac
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        die "missing required tool: $1; $(tool_setup "$1")"
    fi
}

repository_search() {
    rg --no-config "$@"
}

require_rust_component() {
    require_tool rustup
    local installed_name="${1%-preview}"
    if ! rustup component list --installed | grep -Eq "^$installed_name(-|$)"; then
        die "missing Rust component: $1; install with: rustup component add $1"
    fi
}

format() {
    require_tool cargo
    require_rust_component rustfmt
    cargo fmt --all -- --check
}

lint() {
    require_tool cargo
    require_rust_component clippy
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
}

test_workspace() {
    require_tool cargo
    cargo test --locked --workspace --all-targets --all-features
}

docs() {
    require_tool cargo
    RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -D warnings" \
        cargo doc --locked --workspace --all-features --no-deps
    RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -D warnings" \
        cargo test --locked --workspace --all-features --doc
}

coverage_floor() {
    local package="$1"
    local floor
    floor="$(floor_from_file "$COVERAGE_FLOORS" "$package")"
    [[ -n "$floor" ]] || die "missing coverage floor for $package in $COVERAGE_FLOORS"
    is_numeric_floor "$floor" || die "coverage floor for $package must be numeric"
    case "$package" in
        aether-core | aether-crypto)
            awk -v floor="$floor" 'BEGIN { exit !(floor >= 80) }' || \
                die "coverage floor for $package must be at least 80"
            ;;
    esac
    ensure_floor_not_lowered "$package" "$floor"
    printf '%s\n' "$floor"
}

is_numeric_floor() {
    grep -Eq '^[0-9]+([.][0-9]+)?$' <<<"$1"
}

floor_from_file() {
    local file="$1"
    local package="$2"
    awk -F '=' -v package="$package" '
        $1 ~ "^[[:space:]]*" package "[[:space:]]*$" {
            gsub(/[[:space:]]/, "", $2)
            print $2
            exit
        }
    ' "$file"
}

ensure_floor_not_lowered() {
    local package="$1"
    local current="$2"
    local base="${AETHER_COVERAGE_FLOOR_BASE:-HEAD}"
    require_tool git
    if ! git cat-file -e "$base:coverage.toml" 2>/dev/null; then
        git rev-parse --verify "$base^{commit}" >/dev/null 2>&1 || \
            die "cannot validate coverage floors against base revision: $base"
        return
    fi

    local previous
    previous="$(git show "$base:coverage.toml" | floor_from_file /dev/stdin "$package")"
    is_numeric_floor "$previous" || \
        die "coverage floor for $package in $base is malformed"
    if awk -v current="$current" -v previous="$previous" 'BEGIN { exit !(current < previous) }'; then
        [[ "${AETHER_COVERAGE_FLOOR_LOWERING_APPROVED:-}" == "1" ]] || \
            die "coverage floor for $package decreased from $previous to $current; explicit human approval is required (then set AETHER_COVERAGE_FLOOR_LOWERING_APPROVED=1)"
    fi
}

coverage() {
    require_tool cargo
    require_tool cargo-llvm-cov
    require_rust_component llvm-tools-preview
    cargo llvm-cov clean --workspace
    cargo llvm-cov --locked --workspace --all-targets --all-features --no-report
    local package
    for package in aether-core aether-crypto aether-uniffi; do
        cargo llvm-cov report --locked -p "$package" \
            --fail-under-lines "$(coverage_floor "$package")"
    done
}

supply_chain() {
    require_tool cargo
    require_tool cargo-deny
    cargo deny --locked --workspace --all-features check
}

run_harness_self_test() {
    bash "$ROOT/scripts/test/check-harness.sh"
}

check_canonical_target() {
    local root="$1"
    local canonical_root="$2"
    local adapter="$3"
    local target="$4"
    local target_path="$5"
    local target_dir
    target_dir="$(dirname "$target_path")"
    if [[ ! -d "$target_dir" ]] || \
        [[ ! -e "$target_path" && ! -L "$target_path" ]]; then
        echo "missing canonical target for ${adapter#"$root/"}: $target" >&2
        return 1
    fi
    local resolved
    resolved="$(cd "$target_dir" && pwd -P)/$(basename "$target_path")"
    case "$resolved" in
        "$canonical_root"/*) ;;
        *)
            echo "non-canonical target for ${adapter#"$root/"}: $target" >&2
            return 1
            ;;
    esac
    if [[ ! -f "$resolved" || -L "$target_path" ]]; then
        echo "non-canonical target for ${adapter#"$root/"}: $target" >&2
        return 1
    fi
}

check_markdown_adapter() {
    local root="$1"
    local canonical_root="$2"
    local adapter="$3"
    local body
    body="$(awk '
        NR == 1 && $0 == "---" { frontmatter = 1; next }
        frontmatter && $0 == "---" { frontmatter = 0; next }
        frontmatter { next }
        NF { print }
    ' "$adapter")"
    local route_pattern='^Read \[[^]]+\]\(([^)]+)\)\.$'
    if [[ "$(wc -l <<<"$body")" -ne 1 ]] || \
        [[ ! "$body" =~ $route_pattern ]]; then
        echo "copied adapter body in ${adapter#"$root/"}; keep one canonical route" >&2
        return 1
    fi
    local target="${BASH_REMATCH[1]}"
    check_canonical_target \
        "$root" "$canonical_root" "$adapter" "$target" \
        "$(dirname "$adapter")/$target"
}

check_toml_adapter() {
    local root="$1"
    local canonical_root="$2"
    local adapter="$3"
    local instruction
    local instruction_pattern='^developer_instructions = "Read ([^"]+)"$'
    instruction="$(awk '/^developer_instructions = / { print }' "$adapter")"
    if [[ "$(wc -l <<<"$instruction")" -ne 1 ]] || \
        [[ ! "$instruction" =~ $instruction_pattern ]]; then
        echo "copied adapter body in ${adapter#"$root/"}; keep one canonical route" >&2
        return 1
    fi
    local target="${BASH_REMATCH[1]}"
    check_canonical_target \
        "$root" "$canonical_root" "$adapter" "$target" "$root/$target"
}

check_root_claude_adapter() {
    local root="$1"
    local adapter="$root/CLAUDE.md"
    if [[ ! -f "$adapter" || -L "$adapter" ]]; then
        echo "root CLAUDE.md must be a regular non-symlink file" >&2
        return 1
    fi
    if [[ "$(wc -l < "$adapter")" -ne 1 ]] || \
        [[ "$(sed -n '1p' "$adapter")" != "@AGENTS.md" ]]; then
        echo "root CLAUDE.md must contain only @AGENTS.md" >&2
        return 1
    fi
    if [[ ! -f "$root/AGENTS.md" || -L "$root/AGENTS.md" ]]; then
        echo "root CLAUDE.md target must be a regular non-symlink AGENTS.md" >&2
        return 1
    fi
}

check_adapter_tree() {
    local root="$1"
    local directory="$2"
    if [[ ! -d "$directory" || -L "$directory" ]]; then
        echo "adapter directory must be a regular non-symlink directory: ${directory#"$root/"}" >&2
        return 1
    fi
    local symlink
    symlink="$(find "$directory" -type l -print -quit)"
    if [[ -n "$symlink" ]]; then
        echo "symlinked adapter entry: ${symlink#"$root/"}" >&2
        return 1
    fi
}

check_agent_adapters() {
    local root="${1:-$ROOT}"
    local physical_root
    physical_root="$(cd "$root" && pwd -P)"
    local canonical_root
    if [[ ! -d "$root/.agents/instructions" ]] || \
        [[ -L "$root/.agents/instructions" ]]; then
        echo "missing canonical instruction root: .agents/instructions" >&2
        return 1
    fi
    canonical_root="$(cd "$root/.agents/instructions" && pwd -P)"
    if [[ "$canonical_root" != "$physical_root/.agents/instructions" ]]; then
        echo "non-canonical instruction root: .agents/instructions" >&2
        return 1
    fi
    local directory
    local adapter
    for directory in \
        "$root/.agents/skills" \
        "$root/.claude/skills" \
        "$root/.claude/rules" \
        "$root/.claude/agents"; do
        check_adapter_tree "$root" "$directory" || return 1
        while IFS= read -r adapter; do
            check_markdown_adapter \
                "$root" "$canonical_root" "$adapter" || return 1
        done < <(find "$directory" -type f -name '*.md' -print | sort)
    done
    check_root_claude_adapter "$root" || return 1
    directory="$root/.codex/agents"
    check_adapter_tree "$root" "$directory" || return 1
    while IFS= read -r adapter; do
        check_toml_adapter \
            "$root" "$canonical_root" "$adapter" || return 1
    done < <(find "$directory" -type f -name '*.toml' -print | sort)
}

shell() {
    require_tool shellcheck
    require_tool actionlint
    local shell_scripts=()
    local script
    while IFS= read -r script; do
        shell_scripts+=("$script")
    done < <(find "$ROOT/scripts" "$ROOT/fuzz" -type f -name '*.sh' -print)
    shellcheck --external-sources "${shell_scripts[@]}"
    actionlint "$ROOT/.github/workflows"/*.yml
    run_harness_self_test
}

agent_config() {
    require_tool rg
    require_tool codex
    require_tool jq
    [[ -x "$ROOT/scripts/check.sh" ]] || die "scripts/check.sh must be executable"
    [[ -x "$ROOT/scripts/push-reviewed-branch.sh" ]] || \
        die "scripts/push-reviewed-branch.sh must be executable"
    [[ ! -e "$ROOT/scripts/hooks/check.sh" ]] || die "obsolete scripts/hooks/check.sh must be removed"
    for config in "$ROOT/.codex/hooks.json" "$ROOT/.claude/settings.json"; do
        repository_search -Fq 'scripts/check.sh quick' "$config" || die "$config must invoke scripts/check.sh quick"
        repository_search -Fq 'scripts/hooks/enforce-git-boundary.sh' "$config" || \
            die "$config must enforce the Git boundary before execution"
        ! repository_search -Fq 'scripts/hooks/check.sh' "$config" || die "$config still invokes the obsolete nested check script"
    done
    local codex_safety="$ROOT/.codex/rules/safety.rules"
    local codex_reviewed_push
    codex_reviewed_push=$'pattern = ["scripts/push-reviewed-branch.sh"],\n    decision = "prompt",'
    repository_search -UFq "$codex_reviewed_push" "$codex_safety" || \
        die ".codex/rules/safety.rules must prompt for the reviewed push wrapper"
    local codex_raw_push
    codex_raw_push=$'pattern = ["git", "push"],\n    decision = "forbidden",'
    repository_search -UFq "$codex_raw_push" "$codex_safety" || \
        die ".codex/rules/safety.rules must forbid raw Git pushes"
    local policy_output
    local policy_decision
    policy_output="$(
        codex execpolicy check \
            --rules "$codex_safety" \
            scripts/push-reviewed-branch.sh 2> /dev/null
    )" || die "Codex could not evaluate .codex/rules/safety.rules"
    policy_decision="$(jq -er '.decision' <<< "$policy_output")" || \
        die "Codex returned no final decision for the reviewed push wrapper"
    [[ "$policy_decision" == "prompt" ]] || \
        die "reviewed push wrapper must resolve to a prompt decision"
    local claude_settings="$ROOT/.claude/settings.json"
    repository_search -Fq '"Bash(scripts/push-reviewed-branch.sh)"' "$claude_settings" || \
        die ".claude/settings.json must ask before the reviewed push wrapper"
    repository_search -Fq '"Bash(git push*)"' "$claude_settings" || \
        die ".claude/settings.json must deny direct raw Git pushes"
    repository_search -Fq '"Bash(git * push*)"' "$claude_settings" || \
        die ".claude/settings.json must deny global-option raw Git pushes"
    repository_search -Fq '"Bash(gh auth token*)"' "$claude_settings" || \
        die ".claude/settings.json must deny GitHub credential output"
    repository_search -Fq '"Bash(gh pr merge*)"' "$claude_settings" || \
        die ".claude/settings.json must deny agent-driven pull-request merges"
    local commit_push_adapter="$ROOT/.claude/skills/commit-push/SKILL.md"
    ! repository_search -Fq 'Bash(git *)' "$commit_push_adapter" || \
        die ".claude/skills/commit-push/SKILL.md must not grant broad Git access"
    repository_search -Fq 'Bash(scripts/push-reviewed-branch.sh)' "$commit_push_adapter" || \
        die ".claude/skills/commit-push/SKILL.md must use the reviewed push wrapper"
    ! repository_search -Fq 'Bash(gh *)' "$commit_push_adapter" || \
        die ".claude/skills/commit-push/SKILL.md must not grant broad GitHub access"
    local issue_adapter="$ROOT/.claude/skills/issue/SKILL.md"
    ! repository_search -Fq 'Bash(gh *)' "$issue_adapter" || \
        die ".claude/skills/issue/SKILL.md must not grant broad GitHub access"
    local commit_push_workflow="$ROOT/.agents/instructions/skills/commit-push/SKILL.md"
    repository_search -Fq 'scripts/push-reviewed-branch.sh' "$commit_push_workflow" || \
        die "canonical commit-push must use the reviewed push wrapper"
    ! repository_search -Fq 'git push -u origin HEAD' "$commit_push_workflow" || \
        die "canonical commit-push must not invoke raw Git push"
    check_agent_adapters "$ROOT"
    AETHER_CHECK_HARNESS_COMMAND_SURFACE_ONLY=1 bash "$ROOT/scripts/test/check-harness.sh"
}

require_binding_tools() {
    local languages="${AETHER_BINDING_REPLAY_LANGS:-swift,kotlin}"
    require_tool cargo
    case "$languages" in
        swift)
            require_tool swiftc
            ;;
        kotlin)
            require_tool kotlinc
            require_tool java
            [[ -n "${JNA_JAR:-}" ]] || require_tool curl
            ;;
        swift,kotlin | kotlin,swift)
            require_tool swiftc
            require_tool kotlinc
            require_tool java
            [[ -n "${JNA_JAR:-}" ]] || require_tool curl
            ;;
        *)
            die "unsupported AETHER_BINDING_REPLAY_LANGS value: $languages"
            ;;
    esac
}

bindings() {
    require_binding_tools
    cargo build --locked -p aether-uniffi --all-features
    scripts/test/binding-fixture-replay.sh
}

fuzz() {
    require_tool cargo
    require_tool cargo-fuzz
    require_tool rustup
    local toolchain="${AETHER_FUZZ_TOOLCHAIN:-nightly}"
    [[ -n "$toolchain" ]] || die "AETHER_FUZZ_TOOLCHAIN must not be empty"
    rustup run "$toolchain" rustc --version >/dev/null 2>&1 || \
        die "missing Rust toolchain: $toolchain; install with: rustup toolchain install $toolchain"
    AETHER_FUZZ_TOOLCHAIN="$toolchain" scripts/ci/fuzz-smoke.sh
}

release() {
    require_tool gh
    require_tool gpg
    scripts/release/verify-release-gates.sh
}

doctor() {
    local missing=0
    local tool
    local installed_name
    for tool in cargo rustup git rg jq codex cargo-llvm-cov cargo-deny shellcheck actionlint cargo-fuzz curl swiftc kotlinc java gpg gh; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "available: $tool"
        else
            echo "missing: $tool; $(tool_setup "$tool")" >&2
            missing=1
        fi
    done
    for tool in rustfmt clippy llvm-tools-preview; do
        installed_name="${tool%-preview}"
        if command -v rustup >/dev/null 2>&1 && rustup component list --installed | grep -Eq "^$installed_name(-|$)"; then
            echo "available Rust component: $tool"
        else
            echo "missing Rust component: $tool; install with: rustup component add $tool" >&2
            missing=1
        fi
    done
    (( missing == 0 )) || exit 2
}

changed_paths() {
    {
        git diff --name-only "$1"...HEAD
        git diff --name-only
        git diff --cached --name-only
        git ls-files --others --exclude-standard
    } | sort -u
}

paths_need_bindings() {
    grep -Eq '^(crates/aether-(core|crypto|uniffi)/|Cargo\.(toml|lock)$|rust-toolchain\.toml$|packaging/|scripts/build/|scripts/test/(binding-|android-aar-|ios-package-)|\.github/workflows/(bindings|release-verification)\.yml$)'
}

paths_need_release() {
    grep -Eq '^(crates/aether-uniffi/|Cargo\.(toml|lock)$|rust-toolchain\.toml$|packaging/|scripts/(build|release)/|scripts/test/(android|ios|release|binding-)|\.github/workflows/(bindings|release-verification)\.yml$|docs/release)'
}

full() {
    local base=""
    if [[ $# -gt 0 ]]; then
        [[ $# -eq 2 && "$1" == "--base" ]] || die "usage: scripts/check.sh full [--base <revision>]"
        base="$2"
        require_tool git
        git rev-parse --verify "$base^{commit}" >/dev/null || die "invalid base revision: $base"
    fi

    quick
    test_workspace
    docs
    if [[ -n "$base" ]]; then
        AETHER_COVERAGE_FLOOR_BASE="$base" coverage
    else
        coverage
    fi
    supply_chain
    shell
    fuzz

    if [[ -z "$base" ]]; then
        bindings
        release
        return
    fi

    local paths
    paths="$(changed_paths "$base")"
    if paths_need_bindings <<<"$paths"; then
        bindings
    fi
    if paths_need_release <<<"$paths"; then
        release
    fi
}

quick() {
    [[ $# -eq 0 ]] || die "usage: scripts/check.sh quick"
    format
    lint
    agent_config
}

main() {
    local command="${1:-quick}"
    if [[ $# -gt 0 ]]; then
        shift
    fi
    cd "$ROOT"
    case "$command" in
        -h | --help | help) [[ $# -eq 0 ]] || die "usage: scripts/check.sh --help"; usage ;;
        doctor) [[ $# -eq 0 ]] || die "usage: scripts/check.sh doctor"; doctor ;;
        quick) quick "$@" ;;
        full) full "$@" ;;
        format) [[ $# -eq 0 ]] || die "usage: scripts/check.sh format"; format ;;
        lint) [[ $# -eq 0 ]] || die "usage: scripts/check.sh lint"; lint ;;
        test) [[ $# -eq 0 ]] || die "usage: scripts/check.sh test"; test_workspace ;;
        docs) [[ $# -eq 0 ]] || die "usage: scripts/check.sh docs"; docs ;;
        coverage) [[ $# -eq 0 ]] || die "usage: scripts/check.sh coverage"; coverage ;;
        supply-chain) [[ $# -eq 0 ]] || die "usage: scripts/check.sh supply-chain"; supply_chain ;;
        shell) [[ $# -eq 0 ]] || die "usage: scripts/check.sh shell"; shell ;;
        agent-config) [[ $# -eq 0 ]] || die "usage: scripts/check.sh agent-config"; agent_config ;;
        bindings) [[ $# -eq 0 ]] || die "usage: scripts/check.sh bindings"; bindings ;;
        fuzz) [[ $# -eq 0 ]] || die "usage: scripts/check.sh fuzz"; fuzz ;;
        release) [[ $# -eq 0 ]] || die "usage: scripts/check.sh release"; release ;;
        *) die "unknown quality-harness command: $command; run scripts/check.sh --help" ;;
    esac
}

if [[ "${AETHER_CHECK_HARNESS_SOURCE_ONLY:-}" != "1" ]]; then
    main "$@"
fi
