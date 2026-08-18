# Qualification

The existing Akash `tenant` KBS mode can point a guest at the OCL endpoint. That
is enough to qualify the external topology before a `managed` product profile is
added.

Use the isolated `qualification` overlay and follow
[`runbooks/qualification-deploy.md`](runbooks/qualification-deploy.md). The
staging and production overlays are not canary workspaces.

## Offline

- verify the image digest against its upstream source revision and build
  provenance;
- render core and route manifests and pass repository readiness;
- prove the public route matrix with the chosen Gateway implementation;
- prove unauthenticated and wrong-role admin requests fail;
- compile synthetic scoped policies and test the allow case plus wrong path,
  expiry, initdata, GPU count, architecture, and device-identity denials;
- restart KBS and restore PostgreSQL while public routing is absent;
- prove Lease A cannot read any Lease B path.

Synthetic claims test authorization mechanics. They do not prove hardware
attestation.

## Live hardware

Run one combined workload from a Provider that does not run Trustee or KBS:

1. Boot an SNP Kata guest with multiple RTX PRO 6000 Blackwell GPUs.
2. Attest directly to the public OCL KBS and capture the KBS/AS audit event.
3. Confirm every NVIDIA submodule was verified locally and no NRAS request or
   credential exists.
4. Retrieve a registry credential through `kbs:///...`, pull the digest-pinned
   private image, and start it.
5. Retrieve a volume key through `kbs:///...`, initialize a clean Block volume,
   write a marker, restart the workload, and reopen the same encrypted volume.
6. Attempt Lease B's registry, volume, and environment paths from Lease A and
   retain the denials.
7. Inspect Provider manifests, annotations, environment, and logs for absence of
   KBS admin credentials and tenant secret bytes.

Keep evidence hashes, software versions, route status, policy digests, and test
results. Do not put raw tenant credentials, keys, or unredacted evidence in this
repository.
