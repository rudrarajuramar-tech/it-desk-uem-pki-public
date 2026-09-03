# Public Artifact Policy

This repository publishes only the public verification material needed by IT-Desk UEM relying parties. Its publication origin is:

`https://rudrarajuramar-tech.github.io/it-desk-uem-pki-public`

## Publication order

1. Approve the CA profiles and offline ceremony.
2. Publish CA certificates and current CRLs with an integrity manifest.
3. Verify byte identity, signatures, freshness, and retrieval from every required platform context.
4. Only then issue certificates containing these AIA and CRL Distribution Point URLs.

Certificate or CRL replacement must use a reviewed pull request. A replacement CRL must be published and observed before the previous CRL expires. Missing, stale, malformed, or unreachable artifacts block UEM TLS activation and renewal.

## Public boundary

Public CA certificates, CRLs, hashes, bounded policy text, and validation automation are allowed. No private key, passphrase, credential, identity container, CSR, dashboard certificate, endpoint information, inventory, log, or manager configuration is allowed.

The root and issuing private keys remain offline and outside this repository. The dashboard private key remains only on the UEM manager.
