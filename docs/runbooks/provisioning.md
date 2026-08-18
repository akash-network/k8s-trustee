# Provision a resource

Production provisioning must be performed by the authenticated control plane
described in `docs/provisioning-contract.md`. Direct administrator calls are
reserved for a closed staging canary and break-glass recovery.

For a canary:

1. Verify the tenant, deployment, and active lease independently of the
   Provider.
2. Generate an immutable resource URI and exact measured initdata using the
   locked contract.
3. Install the repository/type-scoped policy through the private endpoint.
4. Write the resource body from a protected file descriptor or secret stream.
   Do not place it in shell arguments or environment variables.
5. Confirm a matching synthetic claim allows the path and a cross-lease claim
   denies it before enabling the workload.
6. Record only resource and policy digests in the audit record.

If any step is ambiguous or fails, revoke the policy first and stop. Do not make
the global policy permissive to unblock a test.
