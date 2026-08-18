# Deploy the qualification environment

The qualification environment exists for the external-KBS canary. It is not
staging or production, and none of its unfinished gates should be copied into
those release locks.

Flux remains the only deployment writer. The commands below inspect local files
or read cluster state. They do not apply Kubernetes resources.

## Lock the Trustee image

The qualification source is the Akash fork at
`a9be1a25bccd6ec1bd5ee1f849d00332b9be9a2a`. Its canonical upstream base is
`8db724e019e3a1d44d104713a340661e09f7dc40`.

This exact revision does not include a SQLx TLS backend. The qualification
database must therefore be reachable only over the selected cluster's private,
NetworkPolicy-restricted path. `DATABASE_TLS` remains false for qualification
and remains a required gate for staging and production. Native KBS HTTPS and
Gateway-to-backend TLS are still mandatory in every environment.

Verify those commits in a local checkout before building:

```bash
TRUSTEE_CHECKOUT=/absolute/path/to/trustee-managed-blackwell \
  make verify-source ENV=qualification
```

Set `TRUSTEE_IMAGE_REPOSITORY` to a package owned by the repository's GitHub
organization, then manually dispatch `Build qualification Trustee image`. The
workflow verifies the source lock, builds `images/trustee/Dockerfile` against
that exact source for `linux/amd64` with only the built-in CoCo AS feature, and
publishes a tag derived from both the Trustee and deployment revisions with
provenance and an SBOM. It then pulls the returned manifest digest and runs the
PostgreSQL and authorization smoke test against that exact image before
recording the digest and both source revisions.
It does not publish `latest`, edit a release lock, or deploy anything.

In a separate reviewed change:

* set `TRUSTEE_IMAGE_DIGEST` and `TRUSTEE_IMAGE_BUILD_REVISION` in
  `releases/qualification.env`; and
* set the same image digest in
  `deploy/overlays/qualification/kustomization.yaml`.

The release lock deliberately names `akash-network/trustee` as the source and
the canonical Trustee commit as its upstream base. The Akash revision must not
be represented as a commit from `confidential-containers/trustee`.

## Fill the environment inputs

Replace only the qualification placeholders:

* public and backend DNS names;
* public and backend certificate issuers;
* Gateway class;
* Gateway data-plane namespace and the labels required by the checked-in
  NetworkPolicy;
* Doppler project, configuration, and token Secret name;
* PostgreSQL destination CIDR;
* administrator identity provider and audience.

The backend certificate must chain to a root trusted by the selected Gateway.
The checked-in `BackendTLSPolicy` uses the Gateway's system roots, so a private
backend issuer requires a reviewed `caCertificateRefs` replacement before the
route can open.

The `trustee-runtime` Secret supplied by Doppler must contain `POSTGRES_URL`,
the attestation-token signing key and chain, and the root that KBS uses to
verify those tokens. The qualification URL must use `sslmode=disable` and a
private database address covered by the checked-in egress allowlist. Do not put
the URL or any key in Git. Do not copy this database transport exception into
staging or production.

Apply `database/schema.sql` with a migration identity before starting Trustee.
The runtime database identity needs `SELECT`, `INSERT`, `UPDATE`, and `DELETE`
on those five tables, but it does not need permission to create or alter them.
The schema is idempotent so database provisioning can safely retry it.

Keep these settings unchanged for the canary:

* built-in Attestation Service and RVPS;
* local NVIDIA verification;
* AMD KDS as the SNP VCEK source;
* PostgreSQL for resources, policies, reference values, and sessions;
* scoped resource policies;
* native KBS TLS;
* `verbose_token = false`.

The qualification overlay raises Trustee logging from `warn` to `info` so the
canary can retain verification and authorization events. Review the selected
log sink before the run and confirm that it does not export raw evidence or
resource bodies.

Set a release gate to `true` only when its evidence exists. Then run:

```bash
make validate
make core-readiness
KUBE_CONTEXT=<context> \
  TRUSTEE_GATEWAY_NAMESPACE=<gateway-namespace> \
  make cluster-preflight ENV=qualification
```

The Gateway namespace must carry `ocl.network/role=edge`, and at least one
running data-plane pod must carry `ocl.network/trustee-ingress=true`. The
preflight verifies both because the Trustee ingress NetworkPolicy requires
them.

## Deploy the private core

Add `deploy/overlays/qualification` to the cluster's Flux repository. Do not add
`deploy/routes/qualification` yet. Wait for the Deployment, backend
Certificate, DopplerSecret, and PostgreSQL connection to become healthy.

The qualification overlay removes the in-cluster provisioner ingress rule.
Canary administration uses a local port forward to the private ClusterIP
Service:

```bash
kubectl --context "$KUBE_CONTEXT" --namespace trustee-system \
  port-forward service/trustee-admin 18443:8443
```

Use the configured backend hostname when validating TLS over the forwarded
port, and send the administrator JWT from a mode-0600 client configuration or
a client option that reads a token file. Do not put the token in a command-line
argument, environment variable, terminal transcript, or repository file.
The locked Trustee revision matches admin ACLs against the serialized request
URI, so direct curl-based admin probes must use `--http1.1`. The included
provisioner uses HTTP/1.1 already.

Through that private connection:

1. Install the deny-first attestation policy and reviewed reference values.
2. Compile and install a repository/type-scoped resource policy for the canary
   lease.
3. Write only the canary resources authorized by that policy.
4. Prove that a mismatched initdata hash and a different lease identity cannot
   read those paths.

Create the policy bundle in a new protected directory. The input grant contains
no secret values; resource bodies are provisioned separately.

```bash
umask 077
python3 scripts/render_resource_policies.py \
  --grant /protected/path/canary-resource-grant.json \
  --output-dir /protected/path/canary-policy-bundle
```

The compiler rejects unknown fields, duplicate resource paths, unsupported
architectures, replicas other than zero, and GPU counts above eight. Its policy
requires an affirming SNP appraisal, the exact initdata digest, the expected
architecture-specific NVIDIA submodules, distinct attestation signing keys,
the exact resource path, and an unexpired grant. The grant's Akash identity is
not read directly from the attestation token; it is bound through the canonical
initdata digest. For qualification, independently confirm the grant against
chain state before compiling it.

`index.json` maps each generated file to
`/kbs/v0/resource-policy/<repository>/<type>` and records the grant, policy, and
resource digests. Put each resource body in a mode-0600 file at
`<resource-root>/<repository>/<type>/<tag>`. The qualification provisioner
rejects symlinks, unindexed files, permissive resource files, and any digest
mismatch before making a network request. It installs and reads back every
scoped policy before sending the first resource body:

```bash
python3 scripts/provision_canary.py validate \
  --bundle /protected/path/canary-policy-bundle \
  --resources /protected/path/canary-resources

python3 scripts/provision_canary.py apply \
  --bundle /protected/path/canary-policy-bundle \
  --resources /protected/path/canary-resources \
  --base-url https://<backend-certificate-hostname>:18443 \
  --connect-port 18443 \
  --ca-certificate /protected/path/backend-ca.pem \
  --admin-token-file /protected/path/admin.jwt \
  --receipt /protected/path/canary-provisioning-receipt.json
```

The admin token file must be mode 0600. The provisioner passes it to `curl`
over standard input, not through arguments or environment variables. The
receipt contains only policy and resource paths and SHA-256 digests.

This script is for the controlled qualification run. It does not replace the
production provisioning service described in `docs/provisioning-contract.md`;
in particular, Trustee's current resource API has no create-only transaction.

The compiler uses `time.now_ns()` for grant expiry. Keep the Trustee node clock
synchronized; a clock rollback could otherwise extend access. The synthetic
example is only an authorization fixture and contains no hardware measurement
values.

After the policy and reference-value records are installed, mark those release
gates complete, verify the audit events contain no raw evidence or resource
bodies, and run `make readiness ENV=qualification`. This is the gate for opening
the public route. The separate core-readiness check does not require those
records or the audit result because the private core must be running before the
canary can exercise them.

If port forwarding does not work with the cluster's CNI policy, stop. Do not
expose an admin path through the public Gateway as a workaround.

## Open the guest route

After the private checks pass, add `deploy/routes/qualification` to Flux. The
HTTPRoute exposes only:

* `POST /kbs/v0/auth`
* `POST /kbs/v0/attest`
* `GET /kbs/v0/resource/*`
* `GET /healthz`

Check route status, backend TLS status, and the public deny cases. Then run:

```bash
KBS_URL=https://<qualification-host> make smoke
```

The live canary can now point its measured tenant-KBS configuration at this
origin. Capture redacted evidence for local Blackwell verification, SNP
verification, private-image credential release, persistent-volume key release,
multi-GPU claims, and cross-lease denials.

## Close the canary

Remove the public route through Flux first. Revoke the canary resource policies
and resources through the port forward, retain only approved redacted proof,
and remove the qualification core through Flux when the test ends. Do not mark
`EXTERNAL_E2E`, `ISOLATION_TESTS`, or recovery gates complete until their proof
has been reviewed. Once they are recorded, close the run with:

```bash
make qualification-status
```
