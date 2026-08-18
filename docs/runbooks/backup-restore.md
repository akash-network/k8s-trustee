# Backup and restore

PostgreSQL contains KBS resources, resource policy, attestation policy, reference
values, and protocol sessions. Backups therefore contain tenant secrets and must
receive the same access controls as the live database.

The managed database platform owns encrypted backups, point-in-time recovery,
retention, and deletion. This repository records only the recovery contract.

Before enabling a release gate:

1. Restore a backup into a new isolated database.
2. Start the exact digest-pinned Trustee image against that database with no
   public route.
3. Compare expected policy and reference-value digests through the private admin
   path.
4. Prove a known resource remains authorized only for its matching synthetic
   attestation claims and that a cross-lease claim is denied.
5. Record the observed recovery point and recovery time outside this repository.
6. Destroy the restored database according to the secret-data retention policy.

Never copy a database dump into GitHub Actions artifacts or this repository.
