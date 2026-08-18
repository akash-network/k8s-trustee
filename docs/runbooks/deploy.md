# Deploy

Flux is the deployment writer. These commands render and inspect; they do not
apply anything.

1. Update `releases/<environment>.env` with the reviewed image digest, matching
   upstream source revision, and completed qualification gates.
2. Update the environment overlay with the real Doppler references, database
   egress destination, hostnames, certificate issuer, identity provider, and
   Gateway class.
3. Run `make validate` and `make readiness ENV=<environment>`.
   Then run the read-only cluster check with an explicit context:
   `KUBE_CONTEXT=<context> make cluster-preflight ENV=<environment>`.
4. Have a second reviewer compare the release lock with the image provenance and
   upstream source.
5. Reference `deploy/overlays/<environment>` from the cluster's Flux repository.
   Wait for the Pod, PostgreSQL state, policy, reference values, and private admin
   tests to pass.
6. Only then reference `deploy/routes/<environment>` to expose guest traffic.
7. Run `KBS_URL=https://<host> make smoke` from outside the cluster.

Do not add a local `kubectl apply` shortcut. Emergency changes should still be
made through the environment's reviewed GitOps path so Flux does not silently
revert them.
