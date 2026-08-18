#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
environment=${1:-qualification}
checkout=${2:-}
release_file="$repo_root/releases/$environment.env"

if [[ -z $checkout || ! -d $checkout ]] ||
  ! git -C "$checkout" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  printf 'TRUSTEE_CHECKOUT must name a Trustee Git checkout\n' >&2
  exit 1
fi

python3 "$repo_root/scripts/readiness.py" validate "$environment" >/dev/null

release_value() {
  local key=$1
  awk -F= -v key="$key" '
    $1 == key {
      sub(/^[^=]*=/, "")
      print
      found = 1
    }
    END { if (!found) exit 1 }
  ' "$release_file"
}

source_repository=$(release_value TRUSTEE_SOURCE_REPOSITORY)
source_revision=$(release_value TRUSTEE_SOURCE_REVISION)
upstream_repository=$(release_value TRUSTEE_UPSTREAM_REPOSITORY)
upstream_revision=$(release_value TRUSTEE_UPSTREAM_BASE_REVISION)

git -C "$checkout" cat-file -e "$source_revision^{commit}"
git -C "$checkout" cat-file -e "$upstream_revision^{commit}"

actual_base=$(git -C "$checkout" merge-base "$source_revision" "$upstream_revision")
if [[ $actual_base != "$upstream_revision" ]]; then
  printf 'recorded upstream base is not an ancestor of the source revision\n' >&2
  exit 1
fi

printf 'source lock verified\n'
printf '  source:   %s@%s\n' "$source_repository" "$source_revision"
printf '  upstream: %s@%s\n' "$upstream_repository" "$upstream_revision"
