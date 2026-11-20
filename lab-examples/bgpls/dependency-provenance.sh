#!/bin/bash
# Embedded by prepare-collector.py; executed only against its copied cache.
# The pinned Ubuntu Swift image provides Bash, Git, find, sort, cmp and readlink,
# but not Python. Bash 3.2 and newer are also supported by the offline fixtures.
set -euo pipefail
export LC_ALL=C
export GIT_OPTIONAL_LOCKS=0

provenance_error() {
    printf 'dependency provenance: %s: %s\n' "$checkout" "$*" >&2
    exit 1
}

dependency_git() {
    git --no-replace-objects -c core.fsmonitor=false -c core.quotePath=true -c core.worktree="$checkout" \
        -c safe.directory="$checkout" -C "$checkout" "$@"
}

normalize_paths() {
    local path
    while IFS= read -r -d '' path; do
        printf '%s\0' "${path#./}"
    done
}

verify_dependency() (
    checkout=$1
    revision=$2
    [ -d "$checkout" ] && [ ! -L "$checkout" ] ||
        provenance_error "checkout is not a real directory"
    head=$(dependency_git rev-parse HEAD)
    [ "$head" = "$revision" ] || provenance_error "HEAD does not match the pin"
    # Keep staged changes disallowed, but never use the index or its cached stat
    # data to establish worktree provenance.
    dependency_git diff-index --cached --quiet --no-ext-diff "$revision" --
    scratch=$(mktemp -d)
    trap 'rm -rf -- "$scratch"' EXIT

    #  status/diff can hide modified bytes behind assume-unchanged,
    # skip-worktree, stat-cache hits or clean filters. Compare raw blob hashes,
    # actual file types, symlink text and Git's owner-executable bit instead.
    # Capture commands before reading their output: a failed process substitution
    # must not be mistaken for an empty (and therefore clean) dependency tree.
    dependency_git ls-tree -r -t -z "$revision" > "$scratch/tree"
    : > "$scratch/expected-paths"
    : > "$scratch/expected-executable"
    while IFS= read -r -d '' entry; do
        header=${entry%%$'\t'*}
        path=${entry#*$'\t'}
        read -r mode kind object <<< "$header"
        file=$checkout/$path
        case "$mode:$kind" in
            040000:tree)
                [ -d "$file" ] && [ ! -L "$file" ] ||
                    provenance_error "directory type differs: $path"
                ;;
            100644:blob|100755:blob)
                [ -f "$file" ] && [ ! -L "$file" ] ||
                    provenance_error "regular-file type differs: $path"
                printf '%s\0' "$path" >> "$scratch/expected-paths"
                if [ "$mode" = 100755 ]; then
                    printf '%s\0' "$path" >> "$scratch/expected-executable"
                fi
                ;;
            120000:blob)
                [ -L "$file" ] || provenance_error "symlink type differs: $path"
                # -n and the sentinel retain newlines belonging to the target
                # itself. && preserves readlink failures on GNU/BSD platforms.
                target=$(readlink -n "$file" && printf '.')
                target=${target%.}
                actual=$(printf '%s' "$target" | dependency_git hash-object --no-filters --stdin)
                [ "$actual" = "$object" ] || provenance_error "symlink target differs: $path"
                printf '%s\0' "$path" >> "$scratch/expected-paths"
                ;;
            *)
                provenance_error "unsupported tree entry (including gitlinks): $path"
                ;;
        esac
    done < "$scratch/tree"

    # Git's non-NUL tree format C-quotes unusual paths (tabs/newlines included),
    # which hash-object --stdin-paths decodes. Hash all regular files in one
    # process, without filters, worktree/index comparisons or object writes.
    dependency_git ls-tree -r "$revision" > "$scratch/quoted-tree"
    : > "$scratch/regular-paths"
    : > "$scratch/expected-blobs"
    while IFS=$'\t' read -r header path; do
        read -r mode kind object <<< "$header"
        case "$mode" in
            100644|100755)
                printf '%s\n' "$path" >> "$scratch/regular-paths"
                printf '%s\n' "$object" >> "$scratch/expected-blobs"
                ;;
        esac
    done < "$scratch/quoted-tree"
    dependency_git hash-object --no-filters --stdin-paths \
        < "$scratch/regular-paths" > "$scratch/actual-blobs"
    cmp -s "$scratch/expected-blobs" "$scratch/actual-blobs" ||
        provenance_error "tracked file bytes differ from the pinned tree"

    # Ignore only root Git metadata and empty directories (Git tracks neither).
    # Unlike git status, find cannot suppress ignored or index-hidden additions.
    (cd "$checkout" && find . -path './.git' -prune -o ! -type d -print0) > "$scratch/found-paths"
    normalize_paths < "$scratch/found-paths" > "$scratch/actual-paths"
    (cd "$checkout" && find . -path './.git' -prune -o -type f -perm -0100 -print0) \
        > "$scratch/found-executable"
    normalize_paths < "$scratch/found-executable" > "$scratch/actual-executable"
    for inventory in paths executable; do
        sort -z "$scratch/expected-$inventory" > "$scratch/sorted-expected"
        sort -z "$scratch/actual-$inventory" > "$scratch/sorted-actual"
        cmp -s "$scratch/sorted-expected" "$scratch/sorted-actual" ||
            provenance_error "extra paths or executable modes differ: $inventory"
    done
    printf 'verified pinned dependency: %s %s\n' "$checkout" "$revision"
)
