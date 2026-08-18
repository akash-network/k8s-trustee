#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT

for tool in kubectl python3 shellcheck; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required tool not found: %s\n' "$tool" >&2
    exit 1
  fi
done

shellcheck "$repo_root"/scripts/*.sh
python3 -m unittest discover -s "$repo_root/tests" -p 'test_*.py'

while IFS= read -r json_file; do
  python3 -m json.tool "$json_file" >/dev/null
done < <(find "$repo_root/contracts" -type f -name '*.json' -print | sort)

private_key_pattern='-----BEGIN (EC |RSA |OPENSSH )?PRIVATE KEY-----'
if grep -R -E --exclude-dir=.git --exclude-dir=__pycache__ \
  -- "$private_key_pattern" "$repo_root"; then
  printf 'private key material is forbidden in this repository\n' >&2
  exit 1
fi

if grep -R -E --exclude-dir=.git \
  -- 'postgres(ql)?://[^[:space:]]+:[^[:space:]]+@' "$repo_root"; then
  printf 'PostgreSQL credentials are forbidden in this repository\n' >&2
  exit 1
fi

for environment in qualification staging production; do
  python3 "$repo_root/scripts/readiness.py" validate "$environment"
  kubectl kustomize "$repo_root/deploy/overlays/$environment" \
    >"$tmp_dir/$environment.yaml"
  python3 "$repo_root/scripts/readiness.py" render "$tmp_dir/$environment.yaml"
  kubectl kustomize "$repo_root/deploy/routes/$environment" \
    >"$tmp_dir/$environment-routes.yaml"
  python3 "$repo_root/scripts/readiness.py" route-render \
    "$tmp_dir/$environment-routes.yaml"
done
