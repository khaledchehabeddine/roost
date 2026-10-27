#!/usr/bin/env bash
# Runs the checks this branch's changes need, and prints one line per check and the
# problems behind each failure. Full logs go to target/check/.
set -uo pipefail
cd "$(dirname "$0")/.."

logs=target/check
mutants=true
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-mutants)
            mutants=false
            shift
            ;;
        *)
            echo "Usage: scripts/check.sh [--no-mutants]" >&2
            exit 2
            ;;
    esac
done

# The newest commit this branch shares with main or origin/main, so a stale copy of
# either doesn't add unrelated changes.
if ! base=$(git merge-base HEAD $(git for-each-ref --format='%(refname)' refs/heads/main refs/remotes/origin/main) 2> /dev/null); then
    echo "Can't find the commit this branch shares with main or origin/main" >&2
    exit 2
fi
changed=$({ git diff --name-only "$base"; git ls-files --others --exclude-standard; } | sort -u)
if [[ -z $changed ]]; then
    echo "No changes since $(git rev-parse --short "$base")"
    exit 0
fi
echo "Checking $(wc -l <<< "$changed" | tr -d ' ') changed files since $(git rev-parse --short "$base")"
mkdir -p "$logs"
failures=0

# Prints the lines of a failed check's log that name each problem, or the log's end
# when none match.
details() {
    local log=$logs/$1.log lines
    case $1 in
        fmt) lines=$(grep -E '^Diff in' "$log") ;;
        clippy | doc) lines=$(grep -E '^[^ ]+:[0-9]+:[0-9]+: (error|warning)' "$log") ;;
        test) lines=$(sed -n '/^failures:$/,/^test result: FAILED/p' "$log") ;;
        deny) lines=$(grep -E '^error|┌─|^ *[0-9]+ │ |├ ID:' "$log") ;;
        mutants) lines=$(cat "$logs/mutants.out/missed.txt" 2> /dev/null) ;;
    esac
    if [[ -z $lines ]]; then
        lines=$(tail -n 20 "$log")
    fi
    head -n 40 <<< "$lines" | sed 's/^/    /'
}

# Runs one check, writes its output to a log, and prints its result.
run() {
    local name=$1
    shift
    if "$@" > "$logs/$name.log" 2>&1; then
        echo "pass  $name"
        return 0
    fi
    echo "FAIL  $name  (log: $logs/$name.log)"
    details "$name"
    failures=$((failures + 1))
    return 1
}

skip() {
    echo "skip  $1  ($2)"
}

# Writes a diff cargo mutants can parse, whatever the user's Git config.
plain_diff() {
    git diff --no-color --no-ext-diff --src-prefix=a/ --dst-prefix=b/ "$@"
}

# A mutant that hangs the tests counts as caught, so a run that only reports
# timeouts (exit code 3) passes.
mutation_test() {
    rm -f "$logs/mutants.out/missed.txt"
    cargo mutants "$@"
    local status=$?
    if ((status == 3)) && [[ ! -s $logs/mutants.out/missed.txt ]]; then
        return 0
    fi
    return $status
}

tests_passed=false
if grep -qvE '\.md$' <<< "$changed" || grep -qE '^crates/' <<< "$changed"; then
    run fmt cargo fmt --all -- --check
    if run clippy cargo clippy --locked --workspace --all-targets --all-features --message-format=short -- -D warnings; then
        run test cargo test --locked --workspace --all-features --no-fail-fast && tests_passed=true
        run doc env RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --all-features --message-format=short
    else
        skip test "clippy failed"
        skip doc "clippy failed"
    fi
else
    for name in fmt clippy test doc; do
        skip $name "only Markdown outside crates/ changed"
    done
fi

if grep -qE '(^|/)Cargo\.(toml|lock)$|^deny\.toml$' <<< "$changed"; then
    run deny cargo deny --locked --log-level error check
else
    skip deny "no manifest changed"
fi

sources=$(grep -E '^crates/[^/]+/src/.+\.rs$' <<< "$changed")
if [[ -z $sources ]]; then
    skip mutants "no crate source changed"
elif ! $mutants; then
    skip mutants "--no-mutants"
elif ! $tests_passed; then
    skip mutants "tests didn't pass"
else
    # Git leaves untracked files out of a diff, so add each new source file as a
    # diff against an empty file.
    {
        plain_diff "$base" -- $sources
        for file in $(git ls-files --others --exclude-standard -- $sources 2> /dev/null); do
            plain_diff --no-index -- /dev/null "$file"
        done
    } > "$logs/mutants.diff"
    run mutants mutation_test --in-diff "$logs/mutants.diff" --workspace --jobs 4 --output "$logs"
fi

if ((failures > 0)); then
    echo "$failures failed"
    exit 1
fi
echo "All checks passed"
