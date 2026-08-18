# Decision 0001: start with an all-in-one Trustee process

Status: accepted for the first managed-service qualification

## Context

Trustee can run KBS, Attestation Service, and RVPS as separate services or in one
process. The managed service needs a small, reviewable security boundary before
it needs independent scaling.

## Decision

Run the KBS binary with the built-in Attestation Service and built-in RVPS. Put
one public Gateway in front of the guest protocol and keep administration on a
private Service protected by KBS JWT authorization.

This avoids exposing the split deployment's policy and reference-value mutation
APIs over internal unauthenticated gRPC. It also leaves one network protocol to
secure and observe during the first external-KBS qualification.

## Alternatives considered

### Split KBS, Attestation Service, and RVPS

This gives independent scaling and clearer component ownership. The current
internal APIs add authentication and transport work before they are appropriate
for a multi-tenant service. Reconsider this after those interfaces are secured
and there is measured load that requires independent scaling.

### One Trustee deployment per lease

Per-lease instances isolate policy and storage without shared-policy support.
They also create a new endpoint, database lifecycle, signing lifecycle, and
workload for every lease. That cost and failure surface are a poor default. It
remains a possible containment strategy if scoped policy cannot be delivered.

### Adopt trustee-operator as the service boundary

The operator can automate Kubernetes lifecycle, but it does not provide Akash
ownership verification, resource provisioning, or lease authorization. It may
be used later underneath this repository; it does not replace the managed
control plane.

## Consequences

- One KBS outage affects attestation and resource release.
- Independent AS/RVPS scaling is deferred.
- The process needs stable token signing material and PostgreSQL-backed sessions.
- Public routing must continue to exclude administration endpoints.
- Production remains blocked until scoped policy and provisioning are real.
