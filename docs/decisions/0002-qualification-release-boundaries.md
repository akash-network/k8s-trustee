# Decision 0002: keep deployment and workload release locks separate

Status: accepted for qualification

## Context

The external-KBS canary combines two independently operated systems. OCL runs
Trustee, while an Akash Provider runs Provider, Kata, and the CoCo guest. A
single flat lock in this repository would make `k8s-trustee` appear to own
software it does not build or deploy. Duplicating the Trustee configuration in
the workload test package would create two competing sources of truth.

Reviewed pull-request heads are also not deployable artifacts by themselves.
Some Provider changes need composition, and a dirty local worktree cannot serve
as a release revision.

## Decision

Use two linked release locks:

1. `releases/qualification.env` owns the managed Trustee image, exact Akash
   source revision, canonical upstream base, endpoint, and service gates.
2. The sandbox qualification package owns the Provider, chain SDK, Kata, guest
   image, workload image, and SDL revisions used by the hardware run.

The workload lock must reference the immutable Trustee image digest and the
hash of the reviewed managed-service release lock. The proof package records
both locks without copying credentials, local paths, host addresses, device
UUIDs, or raw evidence into Git.

Source revisions, composed integration revisions, OCI manifest digests, and
test results remain separate fields. A pull-request head is recorded as source
input; it is not described as the tested integration revision unless that exact
commit was built and run. Uncommitted source is never eligible for either lock.

The minimal secret-release qualification stack includes the Provider changes
that select and measure an external KBS plus the matching chain SDK contract.
Console quote sidecars and gateway evidence routes are tracked separately
because they are not on the guest-to-KBS resource-release path.

## Alternatives considered

### Put every repository in `releases/qualification.env`

This is easy to read once, but gives this deployment repository ownership of
Provider and guest releases. It also makes normal Trustee rollouts depend on
unrelated workload components.

### Let the sandbox package copy the Trustee values

This makes the test package self-contained, but the copied image, endpoint, or
source provenance can silently drift from the deployed service.

### Use Git submodules for every source tree

Submodules pin source commits but do not identify the composed revision, image
digest, configuration, or live cluster result. They add repository mechanics
without proving what ran.

## Consequences

- A canary is valid only when the two lock references agree.
- The sandbox tooling needs a preflight check for that link before creating a
  lease.
- Trustee can be promoted independently of Provider and Kata after its own
  gates pass.
- Optional Console attestation work cannot accidentally become a blocker for
  the KBS secret-release path.
- The first live target remains RTX PRO 6000. B200 topology, including any
  additional protected-PCIe submodules, needs its own hardware qualification.
