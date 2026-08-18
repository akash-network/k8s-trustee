# Rotate keys and certificates

The KBS serving certificate and the Attestation Service token-signing chain have
different trust consumers and should be rotated independently.

## KBS serving certificate

1. Issue a certificate containing the backend SNI used by
   `BackendTLSPolicy`.
2. Add the new trust path before replacing the serving certificate.
3. Restart the single KBS Pod through Flux and verify backend TLS from the
   Gateway.
4. Remove the old trust path only after the overlap window.

## Attestation token signer

1. Generate the new key in the approved secret system.
2. Add its chain to KBS token trust before the signer changes.
3. Keep both chains trusted longer than the maximum token lifetime.
4. Restart KBS through Flux, complete a new attestation, and retrieve a harmless
   canary resource.
5. Remove the old chain after all old tokens have expired.

Do not print or copy private keys during either procedure. Changing a Doppler
value alone does not prove the Pod reloaded it; the rollout and verification are
required.
