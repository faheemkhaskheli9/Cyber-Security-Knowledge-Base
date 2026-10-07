# Post-Quantum Cryptography (PQC)

## What
A large fault-tolerant quantum computer running Shor's algorithm would break RSA, Diffie-Hellman and elliptic-curve cryptography. Grover's algorithm roughly halves the effective strength of symmetric keys and hashes. PQC replaces public-key algorithms with quantum-resistant ones. NIST standardized these in 2024:
- **ML-KEM** (FIPS 203, ex-Kyber): key encapsulation
- **ML-DSA** (FIPS 204, ex-Dilithium): signatures
- **SLH-DSA** (FIPS 205, ex-SPHINCS+): hash-based signatures

**FN-DSA** (Falcon) and **HQC** are in progress as further additions.

## Why it matters
- **Harvest now, decrypt later**: traffic recorded today can be decrypted once quantum capability exists. Data that must stay secret for 10+ years is already at risk.
- Migrating cryptography across an organization takes years. NIST plans to deprecate RSA/ECC around 2030 and disallow them around 2035, and NSA CNSA 2.0 sets similar timelines.

## Attacks
- Shor's algorithm breaks RSA, DH, ECDSA, ECDH and Ed25519 (future).
- Grover's algorithm speeds up brute force on symmetric keys. AES-128 drops to ~64-bit security, so prefer AES-256.
- Near-term risk comes from implementation flaws in new PQC libraries (side channels), not from quantum computers.

## Defenses
1. **Inventory your cryptography (CBOM)**: find where RSA/ECC is used (TLS, SSH, code signing, VPN, JWT, PKI, HSMs, firmware).
2. **Crypto-agility**: centralize crypto in well-maintained libraries, and avoid hard-coded algorithms and key sizes so you can swap them later.
3. **Hybrid key exchange now**: X25519 + ML-KEM-768 (`X25519MLKEM768`). Supported in current Chrome, Firefox, Cloudflare, OpenSSL 3.5+, BoringSSL and OpenSSH 10 (`mlkem768x25519-sha256` default). Hybrid stays secure as long as either component holds.
4. **Symmetric**: use AES-256 and SHA-384/512 for long-lived secrets.
5. **Signatures**: plan PQC or hybrid for long-lived roots (firmware, code signing). Use stateful hash-based signatures (LMS/XMSS) only where their state management is controlled.
6. Prioritize systems by data lifetime and exposure.

## How to verify
- TLS: inspect the negotiated group in browser devtools (Security tab) or with `openssl s_client -groups X25519MLKEM768 -connect host:443`.
- SSH: `ssh -Q kex | grep -i mlkem` and check the server `KexAlgorithms`.
- Track CBOM coverage and the % of external endpoints offering hybrid key exchange.

## References
- NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography
- NIST IR 8547 (transition timeline)
- NSA CNSA 2.0 FAQ
- Open Quantum Safe: https://openquantumsafe.org
- See also `kb/05-identity-crypto/cryptography.md`, `kb/05-identity-crypto/pki-and-tls.md`
