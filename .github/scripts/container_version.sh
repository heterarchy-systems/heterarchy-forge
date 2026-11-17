#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: %s <refs/heads/main|refs/tags/container-vX.Y.Z> <Cargo.toml>\n' "$0" >&2
    exit 2
}

if (( $# != 2 )); then
    usage
fi

reference=$1
cargo_manifest=$2
if [[ ! -f "$cargo_manifest" ]]; then
    printf 'Cargo workspace manifest is missing: %s\n' "$cargo_manifest" >&2
    exit 1
fi

version=$(awk '
    $0 == "[workspace.package]" { in_workspace_package = 1; next }
    in_workspace_package && /^\[/ { exit }
    in_workspace_package && /^[[:space:]]*version[[:space:]]*=/ {
        sub(/^[[:space:]]*version[[:space:]]*=[[:space:]]*"/, "")
        sub(/".*$/, "")
        print
        exit
    }
' "$cargo_manifest")

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    printf 'Cargo workspace version must be plain numeric SemVer MAJOR.MINOR.PATCH.\n' >&2
    exit 1
fi

if [[ "$reference" != "refs/heads/main" && "$reference" != "refs/tags/container-v${version}" ]]; then
    printf 'Container images are built from main or published from container-v%s; received %s.\n' \
        "$version" "$reference" >&2
    exit 1
fi

printf 'version=%s\n' "$version"
