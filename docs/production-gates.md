# Production gates

`releases/<environment>.env` is the machine-checked gate ledger. Staging and
production require every boolean before route activation.

Qualification has three checkpoints because the canary provisions policy and
reference values through the private core before opening its guest route:

1. `make core-readiness` permits the private core to start. It does not require
   policy, reference-value, audit-observability, Gateway-conformance, recovery,
   isolation, external E2E, or production provisioning-control-plane results.
2. `make readiness ENV=qualification` permits the public guest route. It adds
   the policy, reference-value, and Gateway checks.
3. `make qualification-status` closes the run after recovery, isolation, and
   external E2E evidence exists.

The qualification canary uses authenticated administration over
`kubectl port-forward`, so its status does not claim that the later production
provisioning control plane exists.

The locked qualification revision also evaluates its admin ACL against the
serialized request URI. HTTP/2 carries an absolute URI there, while the ACL
configuration only accepts anchored `/kbs/...` paths. The canary provisioner
uses HTTP/1.1. Fix the authorization check to evaluate the request path before
shipping an HTTP/2-capable production provisioner.

- `LOCAL_BLACKWELL`: the locked image contains the reviewed upstream Blackwell
  local verifier and its tests.
- `POSTGRES_URL_REDACTED`: Trustee cannot log the PostgreSQL URL or credentials.
  Staging and production keep Trustee at warning-level logs. Qualification uses
  info-level logs only after it locks the redaction fix, so the canary can retain
  attestation and authorization events.
- `SCOPED_RESOURCE_POLICIES`: missing repository/type policy denies and scoped
  policies have persistence and isolation coverage.
- `PROVISIONING_CONTROL_PLANE`: an authenticated, audited single writer verifies
  Akash ownership and manages grants.
- `ATTESTATION_POLICY`: production policy rejects sample evidence and enforces
  approved CPU, GPU, initdata, and agent-policy claims.
- `REFERENCE_VALUES`: authenticated, reviewed values exist for the accepted
  platform and GPU software; no value was invented from one passing run.
- `GATEWAY_CONFORMANCE`: the chosen controller passed method/path matching and
  verified backend TLS tests.
- `CONTAINER_HARDENING`: the locked image starts with the repository's non-root,
  read-only filesystem, capability-free security context.
- `AUDIT_OBSERVABILITY`: resource and policy mutations, attestations, denials,
  and release decisions are observable without recording evidence or secret
  bodies.
- `DATABASE_TLS`: KBS verifies PostgreSQL's TLS identity, and the database uses
  restricted credentials and encryption at rest. The exact Trustee revision
  locked for qualification does not provide a SQLx TLS backend, so this gate is
  intentionally a staging/production gate and must remain false in the
  qualification ledger.
- `DATABASE_RECOVERY_TEST`: an isolated restore met the recorded recovery goals.
- `ISOLATION_TESTS`: Lease A could not read Lease B's registry, volume, or
  environment resources.
- `EXTERNAL_E2E`: a real Kata guest completed SNP plus local Blackwell
  attestation against this externally hosted endpoint and consumed both private
  registry credentials and a persistent volume key.
