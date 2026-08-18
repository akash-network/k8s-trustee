# Security

Do not open a public issue containing a credential, tenant resource, evidence
capture, private key, database URL, KBS token, provider address, lease ID, or
device identifier. Use OCL's private security reporting channel.

If a secret enters Git history, treat it as compromised. Revoke or rotate it
before attempting to remove it from the repository.

Changes to public routing, admin authorization, attestation policy, reference
values, resource policy, storage, or release gates require security review and a
deny-case test.
