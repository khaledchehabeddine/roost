#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
COMMAND="$(
    jq -er '(.tool_input.command // .tool_input.cmd) | select(type == "string" and length > 0)'
)" || {
    echo "Cannot validate shell command; refusing execution." >&2
    exit 2
}

REVIEWED_PUSH='scripts/push-reviewed-branch.sh'
declare -a COMMAND_WORDS=()
FUZZ_SECONDS_PREFIX=0
COVERAGE_APPROVAL_PREFIX=0

deny() {
    echo "Use one approved direct command; publish only with $REVIEWED_PUSH." >&2
    exit 2
}

parse_direct_command() {
    local input="$1"
    local state='plain'
    local word=''
    local character
    local next_character
    local word_started=0
    local index

    for ((index = 0; index < ${#input}; index++)); do
        character="${input:index:1}"
        case "$state" in
            plain)
                case "$character" in
                    ' ' | $'\t')
                        if ((word_started)); then
                            COMMAND_WORDS+=("$word")
                            word=''
                            word_started=0
                        fi
                        ;;
                    "'")
                        state='single'
                        word_started=1
                        ;;
                    '"')
                        state='double'
                        word_started=1
                        ;;
                    \\)
                        ((index++))
                        ((index < ${#input})) || return 1
                        next_character="${input:index:1}"
                        [[ "$next_character" != $'\n' && "$next_character" != $'\r' ]] || return 1
                        word+="$next_character"
                        word_started=1
                        ;;
                    '$' | '`' | ';' | '&' | '|' | '<' | '>' | '(' | ')' | '{' | '}' | $'\n' | $'\r' | '#')
                        return 1
                        ;;
                    '*' | '?' | '[')
                        ((${#COMMAND_WORDS[@]} > 0)) || return 1
                        word+="$character"
                        word_started=1
                        ;;
                    *)
                        word+="$character"
                        word_started=1
                        ;;
                esac
                ;;
            single)
                if [[ "$character" == "'" ]]; then
                    state='plain'
                elif [[ "$character" == $'\n' || "$character" == $'\r' ]]; then
                    return 1
                else
                    word+="$character"
                fi
                ;;
            double)
                case "$character" in
                    '"') state='plain' ;;
                    '$' | '`' | $'\n' | $'\r') return 1 ;;
                    \\)
                        ((index++))
                        ((index < ${#input})) || return 1
                        next_character="${input:index:1}"
                        [[ "$next_character" != $'\n' && "$next_character" != $'\r' ]] || return 1
                        case "$next_character" in
                            '$' | '`' | '"' | \\) word+="$next_character" ;;
                            *) word+="\\$next_character" ;;
                        esac
                        ;;
                    *) word+="$character" ;;
                esac
                ;;
        esac
    done

    [[ "$state" == 'plain' ]] || return 1
    if ((word_started)); then
        COMMAND_WORDS+=("$word")
    fi
    ((${#COMMAND_WORDS[@]} > 0))
}

shift_command_word() {
    COMMAND_WORDS=("${COMMAND_WORDS[@]:1}")
}

normalize_prefixes() {
    local value
    while ((${#COMMAND_WORDS[@]} > 0)); do
        case "${COMMAND_WORDS[0]}" in
            '!')
                shift_command_word
                ;;
            time)
                shift_command_word
                if ((${#COMMAND_WORDS[@]} > 0)) && [[ "${COMMAND_WORDS[0]}" == '-p' ]]; then
                    shift_command_word
                fi
                ;;
            AETHER_FUZZ_SECONDS=*)
                value="${COMMAND_WORDS[0]#*=}"
                [[ "$value" =~ ^[1-9][0-9]*$ ]] || return 1
                FUZZ_SECONDS_PREFIX=1
                shift_command_word
                ;;
            AETHER_COVERAGE_FLOOR_LOWERING_APPROVED=1)
                COVERAGE_APPROVAL_PREFIX=1
                shift_command_word
                ;;
            *=*)
                return 1
                ;;
            *)
                break
                ;;
        esac
    done
    ((${#COMMAND_WORDS[@]} > 0))
}

contains_glob() {
    case "$1" in
        *'*'* | *'?'* | *'['*) return 0 ;;
        *) return 1 ;;
    esac
}

validate_repository_script_path() {
    local path="$1"
    local physical_parent
    case "$path" in
        scripts/*) ;;
        *) return 1 ;;
    esac
    case "$path" in
        *'//'* | *'/./'* | *'/../'*) return 1 ;;
    esac
    contains_glob "$path" && return 1
    [[ -f "$ROOT/$path" && ! -L "$ROOT/$path" ]] || return 1
    physical_parent="$(cd "$ROOT/$(dirname "$path")" && pwd -P)" || return 1
    [[ "$physical_parent" == "$ROOT/scripts" || "$physical_parent" == "$ROOT/scripts/"* ]]
}

validate_ripgrep() {
    local end_of_options=0
    local expects_value=0
    local saw_no_config=0
    local token
    local index

    for ((index = 1; index < ${#COMMAND_WORDS[@]}; index++)); do
        token="${COMMAND_WORDS[index]}"
        if ((expects_value)); then
            expects_value=0
            continue
        fi
        if ((end_of_options)); then
            continue
        fi
        case "$token" in
            --)
                end_of_options=1
                ;;
            -A | -B | -C | -g | -m | -t | -T | --after-context | --before-context | \
                --context | --glob | --max-count | --max-depth | --sort | --sortr | \
                --type | --type-not)
                expects_value=1
                ;;
            --after-context=* | --before-context=* | --context=* | --glob=* | \
                --max-count=* | --max-depth=* | --sort=* | --sortr=* | --type=* | \
                --type-not=*)
                ;;
            --count | --files | --files-with-matches | --files-without-match | \
                --fixed-strings | --follow | --hidden | --ignore-case | --json | \
                --line-number | --line-regexp | --no-follow | --no-ignore | --pcre2 | \
                --quiet | --smart-case | --stats | --word-regexp)
                ;;
            --no-config)
                saw_no_config=1
                ;;
            -[FilnPqSwx] | -[FilnPqSwx][FilnPqSwx]*)
                ;;
            -[ABCm][0-9]* | -g?*)
                ;;
            -*)
                return 1
                ;;
        esac
    done
    ((expects_value == 0 && saw_no_config == 1))
}

validate_git() {
    ((${#COMMAND_WORDS[@]} >= 2)) || return 1
    case "${COMMAND_WORDS[1]}" in
        add | branch | commit | diff | log | ls-files | merge-base | rev-parse | show | status | switch)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

validate_cargo() {
    local index=1
    ((${#COMMAND_WORDS[@]} > index)) || return 1
    if [[ "${COMMAND_WORDS[index]}" == +* ]]; then
        ((index++))
        ((${#COMMAND_WORDS[@]} > index)) || return 1
    fi
    case "${COMMAND_WORDS[index]}" in
        -h | --help | -V | --version | add | bench | build | check | clean | clippy | deny | \
            doc | fetch | fix | fmt | fuzz | generate-lockfile | llvm-cov | metadata | remove | \
            test | tree | update | vendor)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

validate_rustup() {
    ((${#COMMAND_WORDS[@]} >= 2)) || return 1
    case "${COMMAND_WORDS[1]}" in
        -h | --help | -V | --version | component | default | override | show | target | toolchain | which)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

validate_gh_api() {
    local index
    local saw_get=0
    local token

    for ((index = 2; index < ${#COMMAND_WORDS[@]}; index++)); do
        token="${COMMAND_WORDS[index]}"
        case "$token" in
            --method)
                ((index++))
                ((index < ${#COMMAND_WORDS[@]})) || return 1
                [[ "${COMMAND_WORDS[index]}" == 'GET' ]] || return 1
                saw_get=1
                ;;
            --method=GET)
                saw_get=1
                ;;
            --cache | --hostname | --jq | --preview | --template)
                ((index++))
                ((index < ${#COMMAND_WORDS[@]})) || return 1
                ;;
            --cache=* | --hostname=* | --jq=* | --preview=* | --template=* | \
                --include | --paginate | --slurp | --verbose)
                ;;
            --* | -*)
                return 1
                ;;
        esac
    done
    ((saw_get == 1))
}

validate_github_cli() {
    ((${#COMMAND_WORDS[@]} >= 3)) || return 1
    case "${COMMAND_WORDS[1]}:${COMMAND_WORDS[2]}" in
        auth:status | issue:create | issue:list | issue:view | label:list | \
            pr:checks | pr:create | pr:diff | pr:edit | pr:list | pr:status | pr:view | \
            run:list | run:view | run:watch | workflow:list | workflow:view)
            return 0
            ;;
        *)
            [[ "${COMMAND_WORDS[1]}" == 'api' ]] && validate_gh_api
            ;;
    esac
}

validate_shell_script() {
    local basename
    local index=1
    local syntax_only=0
    local token

    while ((${#COMMAND_WORDS[@]} > index)) && [[ "${COMMAND_WORDS[index]}" == '-n' ]]; do
        syntax_only=1
        ((index++))
    done
    ((${#COMMAND_WORDS[@]} > index)) || return 1
    token="${COMMAND_WORDS[index]}"
    [[ "$token" != -* ]] || return 1
    contains_glob "$token" && return 1
    if ((syntax_only)); then
        return 0
    fi
    validate_repository_script_path "$token" || return 1
    basename="${token##*/}"
    case "$basename" in
        push-reviewed-branch.sh | *push*branch*) return 1 ;;
    esac
    return 0
}

validate_find() {
    local token
    for token in "${COMMAND_WORDS[@]:1}"; do
        case "$token" in
            -exec | -execdir | -ok | -okdir) return 1 ;;
        esac
    done
    return 0
}

parse_direct_command "$COMMAND" || deny
normalize_prefixes || deny

executable="${COMMAND_WORDS[0]}"
executable_basename="${executable##*/}"
contains_glob "$executable" && deny
((FUZZ_SECONDS_PREFIX == 0)) || [[ "$executable" == 'scripts/ci/fuzz-smoke.sh' ]] || deny
((COVERAGE_APPROVAL_PREFIX == 0)) || [[ "$executable" == 'scripts/check.sh' ]] || deny

case "$executable_basename" in
    push-reviewed-branch.sh | *push*branch*)
        [[ "$COMMAND" == "$REVIEWED_PUSH" && ${#COMMAND_WORDS[@]} -eq 1 ]] || deny
        ;;
    git-*)
        deny
        ;;
    git)
        [[ "$executable" == 'git' ]] || deny
        validate_git || deny
        ;;
    gh)
        [[ "$executable" == 'gh' ]] || deny
        validate_github_cli || deny
        ;;
    rg)
        [[ "$executable" == 'rg' ]] || deny
        if ! validate_ripgrep; then
            echo "Run ripgrep directly with --no-config and non-executing options." >&2
            exit 2
        fi
        ;;
    bash | sh | zsh)
        [[ "$executable" == "$executable_basename" ]] || deny
        validate_shell_script || deny
        ;;
    find)
        [[ "$executable" == 'find' ]] || deny
        validate_find || deny
        ;;
    cargo)
        [[ "$executable" == 'cargo' ]] || deny
        validate_cargo || deny
        ;;
    rustup)
        [[ "$executable" == 'rustup' ]] || deny
        validate_rustup || deny
        ;;
    actionlint | basename | cat | chmod | cmp | cp | cut | date | diff | dirname | du | \
        echo | false | file | gpg | grep | head | jq | kill | ln | ls | mkdir | mktemp | \
        mv | od | openssl | plutil | printf | pwd | readlink | realpath | rm | rustc | \
        rustdoc | rustfmt | sed | shasum | shellcheck | sort | stat | swiftc | tail | tar | \
        tee | test | touch | tr | true | uname | unzip | wc | which | zip)
        [[ "$executable" == "$executable_basename" ]] || deny
        ;;
    *)
        if [[ "$executable" == scripts/* ]]; then
            validate_repository_script_path "$executable" || deny
            [[ -x "$ROOT/$executable" ]] || deny
        else
            deny
        fi
        ;;
esac

exit 0
