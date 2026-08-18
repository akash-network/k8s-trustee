# Threat model

## Protected assets

- persistent-volume encryption keys;
- private-registry credentials;
- workload secrets and environment values;
- attestation policy and reference values;
- attestation-token signing keys;
- KBS administration credentials.

## Untrusted or partially trusted actors

- Akash Providers and host administrators;
- other tenants and leases;
- callers on the public KBS endpoint;
- compromised tenant workloads outside the approved measured guest;
- network observers between the guest and OCL.

OCL is trusted as verifier operator, policy administrator, and secret custodian
in the initial model.

## Required security properties

- The guest authenticates the selected KBS over HTTPS and measures that choice.
- The public route cannot mutate resources, policy, or reference values.
- Admin requests require an OCL-issued JWT and a narrow role ACL.
- A resource is released only to an affirming, expected workload measurement.
- A lease cannot read another lease's path even when it knows the URI.
- Missing or malformed policy, evidence, identity, or reference values deny.
- Provider-visible manifests contain references, not credential bytes or keys.
- Sample evidence cannot receive production resources.
- Every resource and policy mutation is attributable and auditable.

## Known residual risks

- OCL can access resources in its custody.
- PostgreSQL compromise exposes stored resource values unless a separate
  encryption or secret backend is added.
- A Provider can deny service, block KBS traffic, or destroy attached storage.
- A valid hardware report does not prove an approved workload unless initdata
  and Kata agent policy are enforced together.
- Rollback and reference-value mistakes can authorize an obsolete workload.
