#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: %s <ghcr.io/heterarchy-systems/heterarchy-forge> <version> <inspect|prepare|published>\n' "$0" >&2
    exit 2
}

if (( $# != 3 )); then
    usage
fi

image=$1
version=$2
phase=$3
if [[ "$image" != "ghcr.io/heterarchy-systems/heterarchy-forge" ]]; then
    printf 'Unexpected Forge image name.\n' >&2
    exit 2
fi
if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    printf 'Image version must be plain numeric SemVer MAJOR.MINOR.PATCH.\n' >&2
    exit 2
fi
case "$phase" in
    inspect|prepare|published) ;;
    *) usage ;;
esac

package=${image#ghcr.io/}
owner=${package%%/*}
name=${package#*/}
endpoint="orgs/$owner/packages/container/$name"
temporary_root=$(mktemp -d)
response="$temporary_root/response"
error="$temporary_root/error"
trap 'rm -rf "$temporary_root"' EXIT

api_status=0
gh api --include --jq .visibility "$endpoint" > "$response" 2> "$error" || api_status=$?
http_status=$(awk 'NR == 1 { print $2 }' "$response")
if [[ "$http_status" == "404" && "$phase" != "published" ]]; then
    printf 'New GHCR package will use the default private visibility.\n'
    exit 0
fi
if [[ "$api_status" -ne 0 || "$http_status" != "200" ]]; then
    printf 'GHCR package visibility verification failed (HTTP %s).\n' "${http_status:-unknown}" >&2
    exit 1
fi

visibility=$(tail -n 1 "$response")
if [[ "$visibility" != "private" ]]; then
    printf 'Expected private GHCR visibility; received %s.\n' "${visibility:-empty}" >&2
    exit 1
fi
printf 'GHCR package visibility verified: private.\n'
if [[ "$phase" == "inspect" ]]; then
    exit 0
fi

if ! version_records=$(gh api --paginate "$endpoint/versions?per_page=100" \
    --jq '.[].metadata.container.tags // [] | join(",")' 2> "$error"); then
    printf 'GHCR package version lookup failed.\n' >&2
    exit 1
fi

version_exists=false
latest_matches_version=false
while IFS= read -r tags; do
    if [[ ",$tags," == *",$version,"* ]]; then
        version_exists=true
        if [[ ",$tags," == *,latest,* ]]; then
            latest_matches_version=true
        fi
    fi
done <<< "$version_records"

if [[ "$phase" == "prepare" && "$version_exists" == true ]]; then
    printf 'GHCR numeric version %s already exists; refusing to overwrite it.\n' "$version" >&2
    exit 1
fi
if [[ "$phase" == "published" && "$version_exists" != true ]]; then
    printf 'Published GHCR numeric version %s was not found.\n' "$version" >&2
    exit 1
fi
if [[ "$phase" == "published" && "$latest_matches_version" != true ]]; then
    printf 'GHCR latest does not refer to the same image version %s.\n' "$version" >&2
    exit 1
fi
printf 'GHCR numeric version and latest tag verified: %s.\n' "$version"
