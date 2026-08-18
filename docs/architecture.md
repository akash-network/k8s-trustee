# Architecture

## Boundary

The confidential guest is the client. It sends CPU and GPU evidence directly to
the managed KBS and receives only resources authorized for that attested
workload. The Provider supplies hardware, Kata, networking, and block devices;
it does not operate this service or receive its administration credentials.

```text
Kata guest                         OCL-managed service
┌──────────────────┐              ┌──────────────────────────┐
│ Attestation Agent│── HTTPS ────>│ KBS                      │
│ CDH              │              │  ├─ Attestation Service  │
│ SNP + GPU reports│<─ encrypted ─│  └─ built-in RVPS        │
└──────────────────┘   resources  └──────────┬───────────────┘
                                             │
                                      PostgreSQL + audit
```

The configured KBS URL and trust material are part of measured initdata. The
Provider may relay those public values, but it may not select a different KBS
without changing the measurement checked by policy.

## Runtime components

The initial deployment has these runtime boundaries:

1. A public Gateway terminates TLS and exposes only guest protocol methods.
2. A single all-in-one Trustee pod runs KBS, the built-in Attestation Service,
   and built-in RVPS.
3. A private ClusterIP service exposes the same process to the provisioning
   control plane. KBS still authenticates and authorizes every admin request.
4. PostgreSQL provides durable shared storage. Its connection string and the
   attestation-token signing material are delivered through Doppler.
5. A separate provisioning control plane owns the Akash-to-KBS lifecycle. It is
   intentionally not faked by shell scripts in this repository.

The public and private Services select the same pod because KBS currently serves
guest and admin APIs on one listener. Route filtering and KBS JWT authorization
are both required; neither is treated as a substitute for the other.

## Provisioning flow

The intended control-plane flow is:

1. Authenticate the tenant and verify deployment ownership against Akash chain
   state.
2. Resolve the managed KBS profile into the public endpoint and trust material.
3. Build the exact initdata with the locked Provider/chain contract and record
   its SHA-256 digest.
4. Allocate canonical repository/type/tag resource paths for the lease.
5. Install the scoped deny-by-default policy for those paths.
6. Write the resource versions, then mark the grant active.
7. Return only public KBS references to the deployment path.
8. Revoke and garbage-collect grants after lease closure under an audited
   retention policy.

Missing scoped policy must deny access. This ordering means a crash between
policy installation and resource creation does not expose an ungoverned secret.

## Resource authorization

Hardware validity alone is insufficient because a malicious Provider can boot a
real confidential VM. A resource grant must bind the requested path to:

- the exact measured initdata digest;
- an affirming SNP submodule;
- an affirming NVIDIA Blackwell submodule;
- the expected GPU count and architecture;
- a canonical Akash owner, deployment, lease, service, and replica identity;
- an explicit list of resource paths.

The Akash identity is bound through the expected measured initdata. The
provisioning service is responsible for deriving that digest from a canonical,
version-locked contract rather than accepting a caller-provided hash.

## Storage and custody

OCL is initially the secret custodian. PostgreSQL stores Trustee values as
application plaintext, so database encryption, restricted database credentials,
backups, and audit controls are part of the service's security boundary. An HSM
can protect signing or envelope keys, but it does not by itself remove OCL from
the trust model.

Tenant resources never belong in Git or Doppler project configuration. Doppler
is only for service runtime credentials. Tenant resources enter through the
authenticated provisioning plane and are stored in the selected Trustee resource
backend.

## Availability

The first deployment is deliberately single-replica. PostgreSQL-backed protocol
sessions are necessary but not sufficient evidence that active sessions,
rotation, and rolling upgrades work across replicas. HA is a later qualification
step, not a manifest setting.

## Environment separation

Staging and production use separate clusters where possible, and always use
separate PostgreSQL databases, Doppler configurations, signing roots, reference
values, policies, hostnames, and release locks. A staging identity must never be
accepted by production.
