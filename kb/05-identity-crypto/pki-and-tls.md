# PKI and TLS

## What
**Public Key Infrastructure** binds identities to public keys through X.509 certificates issued by Certificate Authorities (root CA → intermediate CA → leaf). **TLS** uses those certificates to authenticate servers (and, with mTLS, clients) and to encrypt traffic.

## Why it matters
- Expired certificates cause outages.
- Mis-issued or stolen keys allow impersonation.
- Weak TLS configuration allows interception.
- Internal PKI (e.g., AD CS) is a frequent domain-escalation path.

## Attacks
- Disabled certificate validation in code (`verify=False`, `InsecureSkipVerify: true`, `rejectUnauthorized: false`) enables MITM.
- Mis-issuance via weak domain validation or DNS hijack, and rogue/compromised CAs.
- Private key theft from servers, repos or CI.
- Downgrade to legacy protocols or ciphers (SSLv3/TLS 1.0, RC4, export ciphers) and SSL stripping when HSTS is missing.
- **AD CS abuse** (ESC1–ESC15): misconfigured templates let low-privileged users request certificates for domain admins.
- Wildcard certificate reuse across many hosts widens the blast radius of one key compromise.

## Defenses
1. **TLS configuration**:
   - TLS 1.3 preferred, 1.2 minimum, everything older disabled.
   - AEAD ciphers only (AES-GCM, ChaCha20-Poly1305) with ECDHE forward secrecy.
   - Use the Mozilla SSL Configuration Generator ("intermediate" or "modern").
2. **HSTS** with preload; redirect HTTP to HTTPS.
3. **Automate the certificate lifecycle**:
   - ACME (Let's Encrypt, cert-manager, Caddy) with short-lived certificates.
   - Public TLS certificate maximum lifetime drops in steps from 398 days toward 47 days by 2029 (CA/B Forum), so automation is mandatory.
   - Monitor expiry.
4. **Protect keys**:
   - Generate keys on the host, HSM or KMS; never email them or commit them.
   - Restrict file permissions to `0600` and rotate on suspicion.
   - Prefer ECDSA P-256 or RSA ≥ 2048 (3072 for long-lived keys).
5. **CAA DNS records** to restrict which CAs may issue for your domain. Monitor **Certificate Transparency** logs (crt.sh, Cert Spotter) for unexpected certificates.
6. **Never disable verification** in code. For internal services, trust a private CA explicitly. Pin only with a backup pin and a rotation plan.
7. **Internal PKI**:
   - Keep the offline root in an HSM; use intermediates for issuance.
   - Short-lived workload certificates (SPIFFE/SPIRE, service mesh mTLS).
   - Audit AD CS templates (remove `ENROLLEE_SUPPLIES_SUBJECT` plus Client Authentication for low-privileged groups).
8. **Revocation**: OCSP stapling. Short-lived certificates reduce reliance on revocation.

## How to verify
- `testssl.sh host:443` or the SSL Labs server test (target A/A+).
- `openssl s_client -connect host:443 -servername host -showcerts` to inspect the chain and expiry.
- Grep code for disabled verification: `verify=False|InsecureSkipVerify|rejectUnauthorized:\s*false|CURLOPT_SSL_VERIFYPEER, 0`.
- `dig CAA example.com` · check crt.sh for your domain.
- AD CS: `Certify`/`Certipy find -vulnerable` (authorized, own domain) or PingCastle.

## References
- Mozilla Server Side TLS & SSL Config Generator
- NIST SP 800-52r2 (TLS guidelines) · NIST SP 800-57 (key management)
- CA/Browser Forum Baseline Requirements
- SpecterOps "Certified Pre-Owned" (AD CS)
- See also `kb/05-identity-crypto/cryptography.md`, `kb/10-emerging/post-quantum-cryptography.md`
