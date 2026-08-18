# Repository rules

This repository deploys OCL's managed Trustee service. It does not fork or vendor
Trustee source.

- Never commit tenant resources, credentials, keys, certificates, tokens,
  kubeconfigs, evidence captures, or rendered secret manifests.
- Pin every deployed image by digest and record the matching source revision.
- Keep the public guest route separate from the private administration route.
- A change that broadens resource release needs a deny-case test.
- Do not publish an image, release, or deployment from a development command.
- Flux owns deployment. Local scripts may render, validate, and test; they must
  not apply manifests implicitly.
