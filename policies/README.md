# Policies

`resource/deny-all.rego` is the only bootstrap resource policy in this
repository. It contains no exception and is safe to install before a public
route exists.

Production resource policies will be generated from verified lease grants and
installed per repository/type. They are not checked in as tenant-specific Rego.
Each generated policy must bind the canonical resource path to the exact
initdata digest, expected SNP and GPU submodules, architecture, count, and
workload identity. Unknown or missing claims deny.

Attestation policy and reference values are intentionally absent. Those require
an authenticated source and review process; one passing hardware report is not
a production reference value.
