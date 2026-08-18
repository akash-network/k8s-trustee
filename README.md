# OCL-managed Trustee

This repository is the deployment and operations boundary for OCL's managed
Trustee and KBS service. Trustee remains an upstream dependency. This repository
pins a reviewed Trustee image, configures it, exposes the guest protocol, and
holds OCL-specific policy, provisioning contracts, and runbooks.

It is a scaffold, not a production-ready deployment. The isolated
`qualification` overlay is the first target for the external-KBS hardware
canary. `make validate` is expected to pass. Readiness is expected to fail until
the selected environment's release lock and manifests have real, reviewed
values.

## First deployment shape

The first release uses one all-in-one KBS process with the built-in Attestation
Service and RVPS. Only the guest protocol is exposed through the public Gateway:

- `POST /kbs/v0/auth`
- `POST /kbs/v0/attest`
- `GET /kbs/v0/resource/...`
- `GET /healthz`

KBS administration remains on a private ClusterIP service and requires a JWT
from the OCL identity provider. PostgreSQL stores resources, policy, reference
values, and protocol sessions. Doppler supplies runtime secrets; no secret value
belongs in this repository.

The service starts with one replica and a `Recreate` rollout. We should not claim
high availability until shared sessions, key rotation, database failover, and
mixed-version rollouts have been exercised.

## Repository boundary

This repository owns:

- Kubernetes composition and environment overlays
- Trustee configuration and image/source locks
- Public and private network boundaries
- Managed-service policy and provisioning contracts
- Deployment, rollback, rotation, and recovery runbooks
- Conformance checks for the external KBS topology

This repository does not own:

- Trustee Rust source or Blackwell verification logic
- Provider, Kata, or guest-components source
- Cluster creation, DNS zones, or the shared Gateway controller
- Tenant secret values
- A copy of generated qualification artifacts

## Local checks

Requirements are Python 3.11+, `kubectl` with Kustomize support, and ShellCheck.

```bash
make validate
make render ENV=qualification
make render ENV=staging
make readiness ENV=staging
KUBE_CONTEXT=<explicit-context> \
  TRUSTEE_GATEWAY_NAMESPACE=<gateway-namespace> \
  make cluster-preflight ENV=staging
TRUSTEE_IMAGE=<local-linux-amd64-image> make image-smoke
```

`readiness` fails closed when it finds a placeholder hostname, an unpinned image,
an unreviewed source revision, or an incomplete security capability.

The normal environment overlays intentionally omit the public Gateway and
HTTPRoute. `deploy/routes/<environment>` is a separate activation unit and must
not be referenced by Flux until `make readiness` succeeds.

The qualification workflow is in
[docs/runbooks/qualification-deploy.md](docs/runbooks/qualification-deploy.md).
The canary scoped-policy compiler is
[`scripts/render_resource_policies.py`](scripts/render_resource_policies.py).
The private, port-forward-only canary provisioner is
[`scripts/provision_canary.py`](scripts/provision_canary.py). It validates the
complete local bundle before installing policies and resource bodies; it is not
the production Akash ownership and lease-lifecycle service.
Its example grant is synthetic and must not be used as a hardware reference
value.

## What must exist before staging can release secrets

1. A Trustee image containing upstream Blackwell local verification, verified
   PostgreSQL TLS support, and a fix that keeps PostgreSQL credentials out of
   logs. The image and source revision must be locked in
   `releases/staging.env`.
2. Repository/type-scoped resource-policy enforcement. Replacing one global
   policy is not a safe multi-tenant lifecycle.
3. An authenticated provisioning control plane that verifies Akash ownership,
   computes the exact measured initdata, and installs lease-scoped resources and
   policy. The Provider must never receive its admin credential.
4. Reviewed SNP and Blackwell reference values and attestation policy. This repo
   deliberately contains no invented measurements.
5. Isolation tests and one live external-KBS qualification run covering private
   image credentials, a persistent volume key, and multiple Blackwell GPUs.

The detailed design and alternatives are in [docs/architecture.md](docs/architecture.md).
The implementation order is in [docs/roadmap.md](docs/roadmap.md).
The source documents are listed in [docs/references.md](docs/references.md).
