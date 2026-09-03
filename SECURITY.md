# Security Policy

This repository is public by design, but it accepts only public PKI artifacts and bounded validation metadata.

Never commit or upload:

- private or encrypted private keys;
- passphrases, credentials, tokens, cookies, or environment files;
- PFX, P12, JKS, keystore, or PKCS #8 key containers;
- certificate signing requests or dashboard leaf certificates;
- endpoint names, identifiers, inventories, logs, or manager configuration.

If private material is exposed, revoke the affected certificate or CA according to the approved incident plan, rotate the credential, and report the incident privately. Deleting a Git commit is not sufficient remediation.
