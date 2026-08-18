#!/usr/bin/env bash
set -euo pipefail

if [[ -z ${KBS_URL:-} || $KBS_URL != https://* ]]; then
  printf 'KBS_URL must be an https:// origin\n' >&2
  exit 1
fi

origin=${KBS_URL%/}
curl --fail --silent --show-error --output /dev/null "$origin/healthz"

deny_cases=(
  "GET /kbs/v0/attestation-policy"
  "POST /kbs/v0/attestation-policy"
  "GET /kbs/v0/reference-value"
  "POST /kbs/v0/reference-value"
  "GET /kbs/v0/resource-policy"
  "POST /kbs/v0/resource-policy"
  "POST /kbs/v0/resource/probe/probe/probe"
  "GET /metrics"
)

for probe in "${deny_cases[@]}"; do
  read -r method path <<<"$probe"
  status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --request "$method" "$origin$path")
  if [[ $status != 404 && $status != 405 ]]; then
    printf 'public route unexpectedly exposed %s %s (HTTP %s)\n' \
      "$method" "$path" "$status" >&2
    exit 1
  fi
done

printf 'public KBS route passed smoke checks\n'
