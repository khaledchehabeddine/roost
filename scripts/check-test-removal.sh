#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C

usage() {
    echo "Usage: $0 -p <crate> [-p <crate>]... [<test>...]" >&2
    exit 1
}

crates=()
while [[ $# -ge 2 && $1 == -p ]]; do
    crates+=("$2")
    shift 2
done
if [[ ${#crates[@]} -eq 0 || ${1-} == -* ]]; then
    usage
fi

base=$(git merge-base HEAD origin/main)
worktree=$(mktemp -d)
trap 'git worktree remove --force "$worktree" 2>/dev/null || rm -rf "$worktree"' EXIT
git worktree add --quiet --detach "$worktree" "$base"

crate_args=()
for crate in "${crates[@]}"; do
    crate_args+=(-p "$crate")
done
tree=$(cargo tree --locked --manifest-path "$worktree/Cargo.toml" "${crate_args[@]}" -e normal,dev --prefix none)
packages=$(grep -oE '^roost-[a-z]+' <<<"$tree" | sort -u)
package_args=()
for package in $packages; do
    package_args+=(-p "$package")
done
echo "Mutating $(paste -sd' ' - <<<"$packages") at $(git rev-parse --short "$base")."

without_positions() {
    sed -E 's/:[0-9]+:[0-9]+:/:/' | sort
}

listed_mutants() {
    cargo mutants --list "${package_args[@]}" "$@" | without_positions
}

base_mutants=$(listed_mutants -d "$worktree")
branch_mutants=$(listed_mutants)
if [[ $base_mutants != "$branch_mutants" ]]; then
    echo "This branch changes more than tests, because the set of mutants differs:" >&2
    diff <(echo "$base_mutants") <(echo "$branch_mutants") >&2 || true
    exit 1
fi

output=.scratch/test-removal/catchers-$base-$(paste -sd- - <<<"$packages")
if [[ -d $output ]]; then
    echo "Reusing $output. Delete it to run cargo-mutants again."
else
    if pgrep -x cargo-mutants >/dev/null; then
        echo "Another cargo-mutants run is using this machine, and its load turns mutants into timeouts. Wait for it to finish." >&2
        exit 1
    fi
    rm -rf "$output.partial"
    mkdir -p "$output.partial"
    status=0
    # Cargo ignores --package when --workspace is set, so the baseline and every mutant run the whole
    # workspace's tests. With --test-workspace=true, the baseline would run only the mutated crates' tests.
    # Without fail-fast, every test binary runs, so each mutant's log names every test that catches it.
    # The JSON names the package and target of each test binary.
    cargo mutants -d "$worktree" "${package_args[@]}" --cargo-arg=--workspace --cargo-arg=--locked -j 4 \
        --cargo-test-arg=--no-fail-fast --cargo-test-arg=--message-format=json \
        --output "$output.partial" || status=$?
    # Code 2 means a mutant was missed and 3 means one timed out. Both finish the run.
    if [[ $status -ne 0 && $status -ne 2 && $status -ne 3 ]]; then
        echo "cargo mutants failed with exit code $status, so it found no catchers." >&2
        exit 1
    fi
    mv "$output.partial" "$output"
fi
results=$output/mutants.out

jq -r '
    .outcomes[]
    | select(.scenario | type == "object")
    | [.summary, .log_path, .scenario.Mutant.name]
    | @tsv
' "$results/outcomes.json" >"$output/outcomes.tsv"
logs=()
while IFS= read -r log; do
    logs+=("$log")
done < <(cut -f2 "$output/outcomes.tsv")
if [[ ${#logs[@]} -eq 0 ]]; then
    echo "cargo mutants found no mutants, so there is nothing to compare." >&2
    exit 1
fi

# Each test binary in each log gets a name of the form <package>/<target>.
(cd "$results" && { grep -H '^{"reason":"compiler-artifact"' "${logs[@]}" || true; }) | jq -rR '
    capture("^(?<log>[^:]+):(?<message>.+)$") as $line
    | $line.message
    | fromjson
    | select(.package_id | startswith("path+"))
    | (
        .package_id
        | if test("#[^@/]+@") then sub(".*#"; "") | sub("@.*"; "") else sub("#.*"; "") | sub(".*/"; "") end
    ) as $package
    | any(.target.kind[]; endswith("lib")) as $lib
    | if .executable then
        [$line.log, (.executable | sub(".*/"; "")), $package + "/" + (if $lib then "lib" else .target.name end)]
    elif $lib then
        [$line.log, "Doc-tests " + .target.name, $package + "/doc"]
    else
        empty
    end
    | @tsv
' | sort -u >"$output/binaries.tsv"

(cd "$results" && awk '
    BEGIN { FS = OFS = "\t" }
    FILENAME == ARGV[1] { binary[$1, $2] = $3; next }
    FNR == 1 { finish(); testing = 0 }
    /^\*\*\* / { testing = $0 ~ /cargo test / && $0 !~ /--no-run/; next }
    !testing { next }
    /^     Running `rustdoc / { next }
    /^     Running `/ {
        key = substr($0, 15)
        sub(/[ `].*/, "", key)
        sub(/.*\//, "", key)
        start(key)
        next
    }
    /^   Doc-tests / { start(substr($0, 4)); next }
    running && /^running [0-9]+ tests?$/ { blocks++ }
    running && /^test .* \.\.\. / {
        name = substr($0, 6)
        split_at = index(name, " ... ")
        result = substr(name, split_at + 5)
        name = substr(name, 1, split_at - 1)
        sub(/ - should panic$/, "", name)
        print "test", log_file, current "/" name, result
    }
    running && /^test result: / { results++ }
    function start(key) {
        finish()
        log_file = FILENAME
        current = binary[FILENAME, key]
        if (current == "") {
            print "No JSON names the test binary " key " in " FILENAME "." >"/dev/stderr"
            failed = 1
            exit
        }
        running = 1
        blocks = 0
        results = 0
    }
    # A block of tests that never prints its result crashed or ran out of time, so its other tests never ran.
    function finish() {
        if (running && (results == 0 || results < blocks)) {
            print "unfinished", log_file, current
        }
        running = 0
    }
    END {
        if (!failed) {
            finish()
        }
        exit failed
    }
' ../binaries.tsv "${logs[@]}") >"$output/tests.tsv"

removals=$output/removals.txt
if [[ $# -eq 0 ]]; then
    : >"$removals"
else
    printf '%s\n' "$@" >"$removals"
fi

status=0
awk -v crates="${crates[*]}" '
    BEGIN {
        FS = OFS = "\t"
        split(crates, list, " ")
        for (i in list) {
            examined[list[i]] = 1
        }
    }
    FILENAME == ARGV[1] { removing[$0] = 1; next }
    FILENAME == ARGV[2] { summary[$2] = $1; mutant[$2] = $3; next }
    $1 == "test" {
        tests[$3] = 1
        if ($4 == "FAILED") {
            catcher[$2, ++catchers[$2]] = $3
        }
    }
    $1 == "unfinished" { unfinished[$2] = 1 }
    END {
        for (test in removing) {
            package = test
            sub(/\/.*/, "", package)
            if (!(test in tests) || !(package in examined)) {
                print "The examined crates have no test named " test "." >"/dev/stderr"
                exit 1
            }
        }
        for (log_file in summary) {
            if (summary[log_file] != "CaughtMutant" && summary[log_file] != "Timeout") {
                continue
            }
            caught++
            if (summary[log_file] == "Timeout") {
                timeouts++
            }
            # A complete log names every test that catches the mutant. Any other names only some of them.
            complete = summary[log_file] == "CaughtMutant" && !(log_file in unfinished)
            if (catchers[log_file] == 0) {
                unknown[++unknowns] = mutant[log_file] (summary[log_file] == "Timeout" ? " (timed out)" : " (crashed)")
                continue
            }
            if (catchers[log_file] == 1) {
                if (complete) {
                    only[catcher[log_file, 1]]++
                } else {
                    maybe_only[catcher[log_file, 1]]++
                }
            }
            kept = 0
            for (i = 1; i <= catchers[log_file]; i++) {
                if (!(catcher[log_file, i] in removing)) {
                    kept = 1
                }
            }
            if (!kept) {
                if (complete) {
                    lost[++losses] = mutant[log_file]
                } else {
                    maybe_lost[++maybe_losses] = mutant[log_file]
                }
            }
        }
        print caught " mutants caught, " timeouts + 0 " of them by timing out."
        if (unknowns > 0) {
            report("These caught mutants have no test result, so check them by hand:", unknown, unknowns, "sort")
        }
        for (test in tests) {
            package = test
            sub(/\/.*/, "", package)
            if (package in examined) {
                row[++rows] = sprintf("%4d %4d  %s", only[test], maybe_only[test], test)
            }
        }
        report("Each test with the number of mutants only it catches, then the number it may be the only catcher of" \
            " because they timed out or crashed. A test at 0 and 0 is a removal candidate:", row, rows, "sort -k1,1n -k2,2n -k3")
        if (length(removing) == 0) {
            exit 0
        }
        report("The removals lose " losses + 0 " of " caught " caught mutants:", lost, losses, "sort")
        if (maybe_losses > 0) {
            report("They may also lose these, which timed out or crashed:", maybe_lost, maybe_losses, "sort")
        }
        if (unknowns > 0) {
            print ""
            print "They may also lose each caught mutant with no test result."
        }
        exit losses + maybe_losses + unknowns > 0 ? 10 : 0
    }
    function report(header, items, count, command,    i) {
        if (count == 0) {
            sub(/:$/, ".", header)
        }
        print ""
        print header
        fflush()
        for (i = 1; i <= count; i++) {
            print "  " items[i] | command
        }
        close(command)
    }
' "$removals" "$output/outcomes.tsv" "$output/tests.tsv" || status=$?
# The lookup exits 10 for a loss, because awk exits 2 on its own errors.
case $status in
0) ;;
10) status=2 ;;
*) exit 1 ;;
esac

thin=$(awk -F: '
    FILENAME == ARGV[1] { caught[$1]++; next }
    { unviable[$1]++ }
    END {
        for (file in unviable) {
            if (unviable[file] > caught[file]) {
                printf "%s: %d caught, %d unviable\n", file, caught[file], unviable[file]
            }
        }
    }
' <(cat "$results"/{caught,timeout}.txt) "$results/unviable.txt" | sort)
if [[ -n $thin ]]; then
    echo
    echo "Thin files, with more unviable mutants than caught ones:"
    echo "$thin"
fi

added=$(
    git diff --no-color --no-ext-diff -U0 --src-prefix=a/ --dst-prefix=b/ "$base" | awk '
        /^\+\+\+ / { file = substr($0, 7); next }
        /^\+/ { print file ": " substr($0, 2) }
    '
    while IFS= read -r -d '' file; do
        awk -v file="$file" '{ print file ": " $0 }' "$file"
    done < <(git ls-files -z --others --exclude-standard)
)
if [[ -n $added ]]; then
    echo
    echo "The lookup assumes the branch only deletes tests. Check that none of these added lines weakens a test it keeps:"
    echo "$added"
fi

exit $status
