# Roadmap

## 1. Lock a usable Trustee artifact

- Merge the generic local Blackwell verifier upstream.
- Keep PostgreSQL URLs out of diagnostics and enable a SQLx TLS backend.
- Confirm repository/type-scoped resource policy behavior and tests.
- Build the all-in-one x86_64 KBS reproducibly and pin its OCI digest to the
  exact upstream revision.
- Prove that image runs under the restricted Pod security context.

## 2. Bring up the private qualification core

- Select the OCL qualification cluster, managed PostgreSQL database, Doppler project,
  certificate issuer, identity provider, and Gateway implementation.
- Replace every qualification placeholder and run `make core-readiness`.
- Reconcile only `deploy/overlays/qualification`; do not activate the public route.
- Install deny-all bootstrap policy, attestation policy, and authenticated
  reference values through an authenticated `kubectl port-forward` session.
- Restart and restore the service while verifying durable state.

## 3. Build the provisioning control plane

- Finalize `contracts/resource-grant-v1.schema.json` with chain-sdk and Provider
  maintainers.
- Authenticate the tenant and independently verify Akash lease ownership.
- Compile the exact measured initdata from a version-locked contract.
- Provision immutable resources and scoped policies with one idempotent writer.
- Add revocation, garbage collection, audit, and cross-lease negative tests.

This application should have its own source and release lifecycle. The
`k8s-trustee` repository consumes its digest and remains the deployment owner.

## 4. Activate and qualify the external endpoint

- Pass the selected Gateway's method-match and backend-TLS tests.
- Reconcile `deploy/routes/qualification`.
- Point today's Akash `tenant` KBS profile at the OCL endpoint.
- Run the combined SNP, Blackwell, private-registry, persistent-volume, and
  multi-GPU qualification in `docs/qualification.md`.
- Retain cross-lease denials and proof that the Provider received no secret or
  admin credential.

## 5. Production and availability

- Repeat recovery and external qualification against production-equivalent
  identity, database, DNS, and certificates.
- Add the product-level `managed` profile only after profile resolution is
  tenant-authorized and measured.
- Start with one replica. Qualify shared sessions, signing-key rotation,
  concurrent policy updates, database failover, and rolling upgrades before
  changing that limit.
