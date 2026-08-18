# Flux integration

The cluster inventory repository, not this repository, creates Flux
`Kustomization` objects.

Use two phases:

1. Reconcile `deploy/overlays/<environment>` for the namespace, private Trustee
   service, configuration, certificate, and runtime secret reference.
2. After `make readiness` and private authorization checks pass, reconcile
   `deploy/routes/<environment>` with a dependency on phase one.

Both sources must be pinned to one reviewed Git revision. Enable pruning. Do not
use post-build substitution for credentials; Doppler materializes the referenced
runtime Secret out of band.

Removing the route Kustomization is the fail-closed emergency action. It stops
new guest sessions without deleting policy, resources, or database state.
