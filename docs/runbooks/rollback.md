# Rollback

Rollback is a GitOps revision change, not an image-tag edit.

1. Remove or suspend the public route activation first if resource authorization
   may be incorrect.
2. Restore the last reviewed environment revision and its exact image digest.
3. Do not roll Trustee back across an unknown storage-schema change. Verify the
   pinned revision's storage compatibility before reconciliation.
4. Confirm `/healthz` privately, then verify policy, reference values, and a
   known denied cross-lease request.
5. Restore public routing only after those checks pass.

If authorization behavior is uncertain, leave the route disabled. Losing
availability is preferable to releasing a resource under the wrong policy.
