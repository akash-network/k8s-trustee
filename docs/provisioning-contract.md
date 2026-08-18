# Provisioning contract

The provisioning API is the missing product boundary between Akash and Trustee.
It should be a small authenticated service, not a collection of operator curl
commands.

## Input

A grant request needs:

- authenticated Akash owner;
- deployment and lease identifiers;
- service and replica identity;
- a versioned workload/initdata contract;
- expected CPU TEE and GPU architecture/count;
- resource values or references supplied over a secret-safe channel;
- requested lifetime and rotation metadata.

The service must obtain ownership and active-lease status from trusted Akash
state. It must not trust an owner, lease ID, initdata hash, or Provider address
solely because the request supplied it.

## Output

The deployment path receives only:

- the managed KBS HTTPS origin and trust profile;
- `kbs:///repository/type/tag` resource URIs;
- the version of the measured initdata contract;
- an activation identifier suitable for audit and revocation.

It never receives a KBS admin token, volume key, registry password, or plaintext
workload secret.

## Atomicity

Trustee currently stores policy and resources through separate calls. The safe
order for a new path is:

1. verify the grant and compute the canonical initdata;
2. install a scoped policy that allows only the exact path and measurement;
3. store the resource;
4. record the active grant in the provisioning database.

`require_scoped_resource_policy` must make a missing policy deny. Retrying any
step must converge on the same versioned grant. Partial failure may leave an
unreachable policy or resource, but must not create an ungoverned readable
resource.

Updates should create new immutable resource tags. Deleting the old grant is a
separate, audited operation after the new workload is active.

## Open design work

- canonical resource naming and collision rules;
- canonical initdata compiler ownership;
- chain reorganization and lease-close handling;
- replica identity and scale changes;
- policy/resource transaction support;
- resource encryption or an external secret backend;
- audit event schema and retention;
- tenant-managed KBS registration.
