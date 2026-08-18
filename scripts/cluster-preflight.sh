#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
environment=${1:-staging}

if [[ -z ${KUBE_CONTEXT:-} ]]; then
  printf 'KUBE_CONTEXT is required; the current context is never used implicitly\n' >&2
  exit 1
fi

if [[ -z ${TRUSTEE_GATEWAY_NAMESPACE:-} ]]; then
  printf 'TRUSTEE_GATEWAY_NAMESPACE is required\n' >&2
  exit 1
fi

if [[ $environment == qualification ]]; then
  python3 "$repo_root/scripts/readiness.py" core-readiness "$environment"
else
  "$repo_root/scripts/readiness.sh" "$environment"
fi

if ! kubectl config get-contexts "$KUBE_CONTEXT" --output=name \
  | grep -Fqx -- "$KUBE_CONTEXT"; then
  printf 'unknown Kubernetes context: %s\n' "$KUBE_CONTEXT" >&2
  exit 1
fi

kubectl_cmd=(kubectl --context "$KUBE_CONTEXT")
required_crds=(
  backendtlspolicies.gateway.networking.k8s.io
  certificates.cert-manager.io
  dopplersecrets.secrets.doppler.com
  gateways.gateway.networking.k8s.io
  httproutes.gateway.networking.k8s.io
)

for crd in "${required_crds[@]}"; do
  "${kubectl_cmd[@]}" get customresourcedefinition "$crd" --output=name >/dev/null
done

gateway_namespace_role=$("${kubectl_cmd[@]}" get namespace \
  "$TRUSTEE_GATEWAY_NAMESPACE" \
  --output=jsonpath='{.metadata.labels.ocl\.network/role}')
if [[ $gateway_namespace_role != edge ]]; then
  printf 'Gateway namespace %s must have label ocl.network/role=edge\n' \
    "$TRUSTEE_GATEWAY_NAMESPACE" >&2
  exit 1
fi

gateway_pods=$("${kubectl_cmd[@]}" get pods \
  --namespace "$TRUSTEE_GATEWAY_NAMESPACE" \
  --selector=ocl.network/trustee-ingress=true \
  --field-selector=status.phase=Running \
  --output=name)
if [[ -z $gateway_pods ]]; then
  printf 'Gateway namespace %s has no running pod labeled ocl.network/trustee-ingress=true\n' \
    "$TRUSTEE_GATEWAY_NAMESPACE" >&2
  exit 1
fi

gateway_file="$repo_root/deploy/routes/$environment/gateway-trustee-public.yaml"
gateway_class=$(awk '$1 == "gatewayClassName:" { print $2; exit }' "$gateway_file")
issuer_file="$repo_root/deploy/overlays/$environment/certificate-trustee-backend.yaml"
issuer_name=$(sed -n '/issuerRef:/,/secretName:/p' "$issuer_file" \
  | awk '$1 == "name:" { print $2; exit }')
doppler_file="$repo_root/deploy/overlays/$environment/dopplersecret-trustee.yaml"
doppler_token_secret=$(sed -n '/tokenSecret:/,/verifyTLS:/p' "$doppler_file" \
  | awk '$1 == "name:" { print $2; exit }')

"${kubectl_cmd[@]}" get gatewayclass "$gateway_class" --output=name >/dev/null
"${kubectl_cmd[@]}" get clusterissuer "$issuer_name" --output=name >/dev/null
"${kubectl_cmd[@]}" get namespace doppler-operator-system --output=name >/dev/null
"${kubectl_cmd[@]}" get secret "$doppler_token_secret" \
  --namespace doppler-operator-system --output=name >/dev/null

printf 'cluster preflight passed for context=%s environment=%s\n' \
  "$KUBE_CONTEXT" "$environment"
