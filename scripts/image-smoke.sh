#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=${TRUSTEE_IMAGE:-}
postgres_image=docker.io/library/postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20

if [[ -z $image ]]; then
  printf 'TRUSTEE_IMAGE must name a locally available image\n' >&2
  exit 1
fi

for tool in cmp curl docker openssl python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required tool not found: %s\n' "$tool" >&2
    exit 1
  fi
done

base64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

expected_revision=$(awk -F= '$1 == "TRUSTEE_SOURCE_REVISION" { print $2 }' \
  "$repo_root/releases/qualification.env")
actual_revision=$(docker image inspect "$image" \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
image_user=$(docker image inspect "$image" --format '{{.Config.User}}')
image_platform=$(docker image inspect "$image" --format '{{.Os}}/{{.Architecture}}')

if [[ $actual_revision != "$expected_revision" ]]; then
  printf 'image revision does not match the qualification lock\n' >&2
  exit 1
fi
if [[ $image_user != 65532:65532 || $image_platform != linux/amd64 ]]; then
  printf 'qualification image must default to UID/GID 65532 on linux/amd64\n' >&2
  exit 1
fi

suffix=$$
network="ocl-trustee-image-smoke-$suffix"
postgres_container="ocl-trustee-image-smoke-postgres-$suffix"
kbs_container="ocl-trustee-image-smoke-kbs-$suffix"
temp_dir=$(mktemp -d)

cleanup() {
  set +e
  docker container rm --force --volumes \
    "$kbs_container" "$postgres_container" >/dev/null 2>&1
  docker network rm "$network" >/dev/null 2>&1
  rm -rf -- "$temp_dir"
}
trap cleanup EXIT

mkdir -p \
  "$temp_dir/admin" \
  "$temp_dir/admin/bundle" \
  "$temp_dir/admin/resources/qualification-smoke/secret" \
  "$temp_dir/serving" \
  "$temp_dir/token"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost \
  -keyout "$temp_dir/serving/tls.key" \
  -out "$temp_dir/serving/tls.crt" >/dev/null 2>&1

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=trustee-token-smoke-root \
  -addext basicConstraints=critical,CA:TRUE \
  -keyout "$temp_dir/token/root.key" \
  -out "$temp_dir/token/attestation-token-root-ca.pem" >/dev/null 2>&1
openssl ecparam -name prime256v1 -genkey -noout \
  -out "$temp_dir/token/attestation-token.key"
openssl req -new \
  -key "$temp_dir/token/attestation-token.key" \
  -subj /CN=trustee-token-smoke-signer \
  -out "$temp_dir/token/signer.csr" >/dev/null 2>&1
openssl x509 -req -days 1 \
  -in "$temp_dir/token/signer.csr" \
  -CA "$temp_dir/token/attestation-token-root-ca.pem" \
  -CAkey "$temp_dir/token/root.key" \
  -CAcreateserial \
  -out "$temp_dir/token/signer.crt" >/dev/null 2>&1
cp "$temp_dir/token/signer.crt" \
  "$temp_dir/token/attestation-token-chain.pem"
printf '\n' >>"$temp_dir/token/attestation-token-chain.pem"
openssl x509 -in "$temp_dir/token/attestation-token-root-ca.pem" \
  >>"$temp_dir/token/attestation-token-chain.pem"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$temp_dir/admin/admin.key" >/dev/null 2>&1
openssl pkey -in "$temp_dir/admin/admin.key" -pubout \
  -out "$temp_dir/admin/admin-public.pem" >/dev/null 2>&1

now=$(date +%s)
jwt_header=$(printf '%s' '{"alg":"RS256","typ":"JWT"}' | base64url)
jwt_payload=$(printf \
  '{"iss":"https://smoke.invalid/","role":"trustee-provisioner","aud":["ocl-trustee-admin"],"iat":%s,"exp":%s}' \
  "$now" "$((now + 300))" | base64url)
jwt_unsigned="$jwt_header.$jwt_payload"
jwt_signature=$(printf '%s' "$jwt_unsigned" | \
  openssl dgst -sha256 -sign "$temp_dir/admin/admin.key" | base64url)
admin_token="$jwt_unsigned.$jwt_signature"
printf 'header = "Authorization: Bearer %s"\n' "$admin_token" \
  >"$temp_dir/admin/admin-curl.conf"
printf '%s' "$admin_token" >"$temp_dir/admin/admin-token"
chmod 0600 \
  "$temp_dir/admin/admin-curl.conf" \
  "$temp_dir/admin/admin-token"
unset admin_token jwt_signature jwt_unsigned jwt_payload jwt_header

printf '%s\n' 'package policy' '' 'default allow := false' \
  >"$temp_dir/admin/bundle/deny-all.rego"
printf '%s' 'qualification-smoke-resource' \
  >"$temp_dir/admin/resources/qualification-smoke/secret/state"
chmod 0600 "$temp_dir/admin/resources/qualification-smoke/secret/state"
policy_sha=$(openssl dgst -sha256 -r \
  "$temp_dir/admin/bundle/deny-all.rego" | awk '{ print $1 }')
resource_sha=$(openssl dgst -sha256 -r \
  "$temp_dir/admin/resources/qualification-smoke/secret/state" | awk '{ print $1 }')
printf '{"version":"v1","grantSha256":"%s","workload":{"owner":"qualification-smoke","dseq":"1","gseq":1,"oseq":1,"service":"smoke","replica":0},"expiresAt":"2099-01-01T00:00:00Z","expiresAtEpoch":4070908800,"policies":[{"repository":"qualification-smoke","type":"secret","file":"deny-all.rego","policySha256":"%s","resources":[{"tag":"state","sha256":"%s"}]}]}\n' \
  "$(printf 'a%.0s' {1..64})" "$policy_sha" "$resource_sha" \
  >"$temp_dir/admin/bundle/index.json"
policy_b64=$(base64url <"$temp_dir/admin/bundle/deny-all.rego")
printf '{"type":"rego","policy_id":"qualification-smoke","policy":"%s"}\n' \
  "$policy_b64" >"$temp_dir/admin/attestation-policy.json"
unset policy_b64 policy_sha resource_sha

reference_provenance=$(printf \
  '%s' '{"qualification-smoke-reference":"qualification-smoke-value"}' | \
  openssl base64 -A)
printf '{"version":"0.1.0","type":"sample","payload":"%s"}\n' \
  "$reference_provenance" >"$temp_dir/admin/reference-value.json"
unset reference_provenance
printf '%s\n' \
  '{"version":"0.4.0","tee":"snp","extra-params":{}}' \
  >"$temp_dir/admin/auth.json"

awk '
  /^issuer_name = / {
    print "issuer_name = \"https://localhost/attestation\""
    next
  }
  /{ issuer = / {
    print "  { issuer = \"https://smoke.invalid/\", audience = \"ocl-trustee-admin\", public_key_uri = \"/run/trustee/admin/admin-public.pem\" }"
    next
  }
  { print }
' "$repo_root/deploy/overlays/qualification/config/kbs-config.toml" \
  >"$temp_dir/kbs-config.toml"

chmod 0444 \
  "$temp_dir/admin/admin-public.pem" \
  "$temp_dir/kbs-config.toml" \
  "$temp_dir/serving/tls.crt" \
  "$temp_dir/serving/tls.key" \
  "$temp_dir/token/attestation-token-chain.pem" \
  "$temp_dir/token/attestation-token-root-ca.pem" \
  "$temp_dir/token/attestation-token.key"

postgres_password=$(openssl rand -hex 24)
docker network create "$network" >/dev/null
docker run --detach \
  --name "$postgres_container" \
  --network "$network" \
  --network-alias trustee-postgres \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=512m \
  --env POSTGRES_DB=trustee \
  --env POSTGRES_PASSWORD="$postgres_password" \
  --env POSTGRES_USER=trustee \
  "$postgres_image" >/dev/null

postgres_ready=false
for _ in $(seq 1 30); do
  if docker exec --env PGPASSWORD="$postgres_password" "$postgres_container" \
    pg_isready --username trustee --dbname trustee >/dev/null 2>&1; then
    postgres_ready=true
    break
  fi
  sleep 1
done
if [[ $postgres_ready != true ]]; then
  printf 'PostgreSQL did not become ready\n' >&2
  exit 1
fi

docker exec --interactive --env PGPASSWORD="$postgres_password" \
  "$postgres_container" psql --username trustee --dbname trustee \
  --set ON_ERROR_STOP=1 --quiet \
  <"$repo_root/database/schema.sql"

postgres_authority="trustee:$postgres_password"
postgres_url="postgresql://$postgres_authority@trustee-postgres:5432/trustee?sslmode=disable"
docker run --detach \
  --platform linux/amd64 \
  --name "$kbs_container" \
  --network "$network" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --publish 127.0.0.1::8080 \
  --env POSTGRES_URL="$postgres_url" \
  --env RUST_LOG=info \
  --mount "type=bind,source=$temp_dir/kbs-config.toml,target=/etc/trustee/kbs-config.toml,readonly" \
  --mount "type=bind,source=$temp_dir/serving,target=/run/trustee/tls,readonly" \
  --mount "type=bind,source=$temp_dir/token,target=/run/trustee/token,readonly" \
  --mount "type=bind,source=$temp_dir/admin,target=/run/trustee/admin,readonly" \
  "$image" \
  --config-file /etc/trustee/kbs-config.toml >/dev/null

kbs_port=$(docker port "$kbs_container" 8080/tcp | awk -F: '{ print $NF }')
kbs_ready=false
for _ in $(seq 1 30); do
  health_status=$(curl --silent --show-error \
    --cacert "$temp_dir/serving/tls.crt" \
    --output /dev/null \
    --write-out '%{http_code}' \
    "https://localhost:$kbs_port/healthz" 2>/dev/null || true)
  if [[ $health_status == 200 ]]; then
    kbs_ready=true
    break
  fi
  if ! docker container inspect "$kbs_container" \
    --format '{{.State.Running}}' 2>/dev/null | grep -Fqx true; then
    break
  fi
  sleep 1
done
if [[ $kbs_ready != true ]]; then
  printf 'Trustee did not become healthy\n' >&2
  exit 1
fi

unauthenticated_admin_status=$(curl --silent --show-error \
  --cacert "$temp_dir/serving/tls.crt" \
  --output /dev/null \
  --write-out '%{http_code}' \
  "https://localhost:$kbs_port/kbs/v0/resource-policy")
if [[ $unauthenticated_admin_status != 401 ]]; then
  printf 'unauthenticated admin request returned HTTP %s\n' \
    "$unauthenticated_admin_status" >&2
  exit 1
fi

admin_post() {
  local path=$1
  local content_type=$2
  local request_file=$3
  local operation=$4
  local response_file="$temp_dir/admin/response"
  local status

  status=$(curl --silent --show-error \
    --config "$temp_dir/admin/admin-curl.conf" \
    --cacert "$temp_dir/serving/tls.crt" \
    --http1.1 \
    --request POST \
    --header "Content-Type: $content_type" \
    --data-binary "@$request_file" \
    --output "$response_file" \
    --write-out '%{http_code}' \
    "https://localhost:$kbs_port$path")
  if [[ $status != 200 ]]; then
    printf '%s returned HTTP %s: ' "$operation" "$status" >&2
    sed -e 's/[[:cntrl:]]/ /g' "$response_file" >&2
    printf '\n' >&2
    exit 1
  fi
}

admin_expect() {
  local path=$1
  local expected_file=$2
  local operation=$3
  local response_file="$temp_dir/admin/response"
  local status

  status=$(curl --silent --show-error \
    --config "$temp_dir/admin/admin-curl.conf" \
    --cacert "$temp_dir/serving/tls.crt" \
    --http1.1 \
    --request GET \
    --output "$response_file" \
    --write-out '%{http_code}' \
    "https://localhost:$kbs_port$path")
  if [[ $status != 200 ]]; then
    printf '%s returned HTTP %s\n' "$operation" "$status" >&2
    exit 1
  fi
  if ! cmp --silent "$response_file" "$expected_file"; then
    printf '%s returned different bytes after restart\n' "$operation" >&2
    exit 1
  fi
}

python3 "$repo_root/scripts/provision_canary.py" apply \
  --bundle "$temp_dir/admin/bundle" \
  --resources "$temp_dir/admin/resources" \
  --base-url "https://localhost:$kbs_port" \
  --ca-certificate "$temp_dir/serving/tls.crt" \
  --admin-token-file "$temp_dir/admin/admin-token" \
  --connect-port "$kbs_port" \
  --receipt "$temp_dir/admin/provisioning-receipt.json" >/dev/null
admin_post \
  /kbs/v0/attestation-policy \
  application/json \
  "$temp_dir/admin/attestation-policy.json" \
  'attestation-policy provisioning'
admin_post \
  /kbs/v0/reference-value \
  application/json \
  "$temp_dir/admin/reference-value.json" \
  'reference-value provisioning'

auth_status=$(curl --silent --show-error \
  --cacert "$temp_dir/serving/tls.crt" \
  --request POST \
  --header 'Content-Type: application/json' \
  --data-binary "@$temp_dir/admin/auth.json" \
  --output "$temp_dir/admin/auth-response.json" \
  --write-out '%{http_code}' \
  "https://localhost:$kbs_port/kbs/v0/auth")
if [[ $auth_status != 200 ]]; then
  printf 'SNP protocol session creation returned HTTP %s\n' "$auth_status" >&2
  exit 1
fi

postgres_state=$(docker exec --env PGPASSWORD="$postgres_password" \
  "$postgres_container" psql --username trustee --dbname trustee \
  --tuples-only --no-align --command \
  "SELECT 'repository=' || count(*) FROM repository WHERE key = 'qualification-smoke/secret/state'
   UNION ALL
   SELECT 'kbs=' || count(*) FROM kbs WHERE key LIKE 'resource-policy-scope-sha256-%'
   UNION ALL
   SELECT 'attestation_service_policy=' || count(*) FROM attestation_service_policy WHERE key = 'qualification-smoke.rego'
   UNION ALL
   SELECT 'reference_value=' || count(*) FROM reference_value WHERE key = 'qualification-smoke-reference'
   UNION ALL
   SELECT 'kbs_protocol_session=' || count(*) FROM kbs_protocol_session;")
for table in \
  repository \
  kbs \
  attestation_service_policy \
  reference_value \
  kbs_protocol_session; do
  if ! grep -Fqx -- "$table=1" <<<"$postgres_state"; then
    printf 'Trustee did not persist the qualification probe in %s\n' "$table" >&2
    exit 1
  fi
done

docker restart "$kbs_container" >/dev/null
kbs_port=$(docker port "$kbs_container" 8080/tcp | awk -F: '{ print $NF }')
kbs_restarted=false
for _ in $(seq 1 30); do
  health_status=$(curl --silent --show-error \
    --cacert "$temp_dir/serving/tls.crt" \
    --output /dev/null \
    --write-out '%{http_code}' \
    "https://localhost:$kbs_port/healthz" 2>/dev/null || true)
  if [[ $health_status == 200 ]]; then
    kbs_restarted=true
    break
  fi
  sleep 1
done
if [[ $kbs_restarted != true ]]; then
  printf 'Trustee did not become healthy after restart\n' >&2
  docker container inspect "$kbs_container" \
    --format 'container={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}' \
    >&2 || true
  docker logs --since 1m "$kbs_container" 2>&1 \
    | sed -E \
      -e 's#postgres(ql)?://[^[:space:]]+#postgresql://<redacted>#g' \
      -e 's#trustee:[^@[:space:]]+@#trustee:<redacted>@#g' \
    | tail -40 >&2 || true
  exit 1
fi
admin_expect \
  /kbs/v0/resource-policy/qualification-smoke/secret \
  "$temp_dir/admin/bundle/deny-all.rego" \
  'resource-policy readback after restart'
admin_resource_status=$(curl --silent --show-error \
  --config "$temp_dir/admin/admin-curl.conf" \
  --cacert "$temp_dir/serving/tls.crt" \
  --http1.1 \
  --request GET \
  --output /dev/null \
  --write-out '%{http_code}' \
  "https://localhost:$kbs_port/kbs/v0/resource/qualification-smoke/secret/state")
if [[ $admin_resource_status != 401 ]]; then
  printf 'admin JWT unexpectedly read a guest resource after restart (HTTP %s)\n' \
    "$admin_resource_status" >&2
  exit 1
fi
resource_rows_after_restart=$(docker exec --env PGPASSWORD="$postgres_password" \
  "$postgres_container" psql --username trustee --dbname trustee \
  --tuples-only --no-align --command \
  "SELECT count(*) FROM repository WHERE key = 'qualification-smoke/secret/state';")
if [[ $resource_rows_after_restart != 1 ]]; then
  printf 'resource row did not survive Trustee restart\n' >&2
  exit 1
fi

metrics=$(curl --fail --silent --show-error \
  --cacert "$temp_dir/serving/tls.crt" \
  "https://localhost:$kbs_port/metrics")
for counter in \
  kbs_policy_approvals_total \
  kbs_policy_violations_total; do
  if ! grep -Fq -- "# HELP $counter " <<<"$metrics"; then
    printf 'Trustee metrics are missing counter %s\n' "$counter" >&2
    exit 1
  fi
done

connection_count=$(docker exec --env PGPASSWORD="$postgres_password" \
  "$postgres_container" psql --username trustee --dbname trustee \
  --tuples-only --no-align --command \
  "SELECT count(*) FROM pg_stat_activity WHERE datname = 'trustee' AND client_addr IS NOT NULL;")
if ((connection_count < 6)); then
  printf 'Trustee did not open every PostgreSQL-backed state namespace\n' >&2
  exit 1
fi

docker logs "$kbs_container" >"$temp_dir/kbs.log" 2>&1
if grep -Fq -- "$postgres_password" "$temp_dir/kbs.log"; then
  printf 'Trustee logs exposed the PostgreSQL credential\n' >&2
  exit 1
fi
if grep -Eq -- 'postgres(ql)?://' "$temp_dir/kbs.log" ||
  grep -Fq -- 'trustee-postgres:5432/trustee' "$temp_dir/kbs.log"; then
  printf 'Trustee logs exposed the PostgreSQL connection URL\n' >&2
  exit 1
fi
for expected_log in \
  'KBS storage backend' \
  'Attestation Service storage backend' \
  'launch a built-in RVPS.' \
  'Starting HTTPS server'; do
  if ! grep -Fq -- "$expected_log" "$temp_dir/kbs.log"; then
    printf 'Trustee startup log is missing: %s\n' "$expected_log" >&2
    exit 1
  fi
done

printf 'qualification image smoke passed\n'
printf '  revision: %s\n' "$actual_revision"
printf '  health: HTTP %s\n' "$health_status"
printf '  unauthenticated admin: HTTP %s\n' "$unauthenticated_admin_status"
printf '  private metrics: expected counters present\n'
printf '  PostgreSQL: all five namespaces persisted through Trustee APIs\n'
printf '  restart: scoped policy read back; resource retained; admin read denied\n'
printf '  PostgreSQL connections: %s active backends\n' "$connection_count"
