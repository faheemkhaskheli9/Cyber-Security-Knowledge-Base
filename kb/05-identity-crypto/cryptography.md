# Cryptography Essentials

## What
Practical use of cryptographic primitives (encryption, hashing, MACs, signatures, key exchange, randomness) to provide confidentiality, integrity and authenticity. The goal is to pick vetted algorithms and libraries and use them correctly, not to design new schemes.

## Why it matters
- Most crypto failures are misuse, not broken math: ECB mode, reused nonces, unsalted fast password hashes, hard-coded keys, disabled certificate checks.
- OWASP Top 10 lists Cryptographic Failures as A02 (2021).
- Encrypted data stolen today may be decrypted later ("harvest now, decrypt later"), which drives post-quantum planning.

## Attacks
- **ECB mode** leaks plaintext patterns (identical blocks → identical ciphertext).
- **Nonce/IV reuse**: with AES-GCM or ChaCha20-Poly1305, reusing a nonce under the same key reveals the XOR of plaintexts and lets attackers forge tags (GCM authentication key recovery). With CTR it is a two-time pad.
- **Static or predictable IV** in CBC; **unauthenticated CBC** → padding oracle attacks.
- **Weak hashes**: MD5/SHA-1 collisions (SHAttered); fast unsalted password hashes cracked offline at billions of guesses per second with GPU tools (authorized password audits only).
- **Length extension** on `SHA256(secret || message)` used as a MAC → use HMAC.
- **Timing side channels**: `==` comparison of MACs/tokens leaks bytes → constant-time compare.
- **Weak randomness**: `rand()`, `Math.random()`, time-seeded PRNGs make keys, tokens and nonces predictable.
- **Key exposure**: keys in source, config, logs or images; same key used for many purposes.
- **Algorithm confusion/downgrade**: JWT `alg: none` or RS256→HS256 confusion; legacy TLS ciphers.
- Detection: code review/SAST rules (Semgrep, CodeQL crypto queries), secret scanning, TLS scanners.

## Defenses

### Algorithm choices
| Need | Use | Avoid |
|------|-----|-------|
| Symmetric encryption | AES-256-GCM, ChaCha20-Poly1305 (AEAD) | DES/3DES, RC4, ECB mode, unauthenticated CBC/CTR |
| Hashing (integrity) | SHA-256/SHA-3/BLAKE2 | MD5, SHA-1 |
| Password hashing | Argon2id, bcrypt, scrypt | plain/fast hashes (MD5, SHA-*, even salted) |
| Signatures | Ed25519, ECDSA P-256, RSA-3072+ (PSS) | RSA-1024, DSA, PKCS#1 v1.5 for new designs |
| Key exchange | X25519/ECDH, (hybrid PQ: ML-KEM) | static DH small groups, RSA key transport |
| MAC | HMAC-SHA-256 | home-grown MACs, `hash(key‖msg)` |
| Key derivation | HKDF (from keys), Argon2id/PBKDF2 (from passwords) | raw hash of a password as a key |
| Randomness | OS CSPRNG (`secrets`, `/dev/urandom`, `crypto.randomBytes`) | `rand()`, `Math.random()` |

### Rules
1. **Don't roll your own crypto**: use vetted, misuse-resistant libraries (libsodium/PyNaCl, Google Tink, Go `crypto/*`, Java via Tink, .NET `System.Security.Cryptography`). Prefer high-level APIs (`crypto_secretbox`, Tink `Aead`) over raw primitives.
2. **Authenticated encryption** (AEAD) always; bind context with associated data (e.g., record ID, tenant).
3. **Unique nonces**: 96-bit random nonces for AES-GCM are fine up to about 2^32 messages per key, then rotate; or use XChaCha20-Poly1305 (192-bit nonce) or AES-GCM-SIV for nonce-misuse resistance.
4. **Password hashing**: Argon2id with OWASP minimums (e.g., m=19 MiB, t=2, p=1; tune higher if latency allows), or bcrypt cost ≥ 10 (72-byte input limit), or scrypt N=2^17, r=8, p=1; PBKDF2-HMAC-SHA256 with 600,000 iterations where FIPS is required. Unique salt per password (libraries do this); optional pepper kept in a KMS/HSM.
5. **CSPRNG** for keys, tokens, nonces, session IDs: Python `secrets.token_bytes(32)`, Node `crypto.randomBytes(32)`, Go `crypto/rand`, Java `SecureRandom`.
6. **Constant-time comparisons**: `hmac.compare_digest`, `crypto.timingSafeEqual`, `subtle.ConstantTimeCompare`, `MessageDigest.isEqual`.
7. **Key management**: keys in KMS/HSM, rotate, separate from data, one key per purpose, least-privilege access to decrypt.
   - **Envelope encryption**: a data encryption key (DEK) encrypts data; a key encryption key (KEK) in KMS encrypts the DEK; store the wrapped DEK next to the ciphertext. Rotating the KEK only rewraps DEKs.
   - Key versioning in ciphertext headers so old data stays decryptable during rotation; crypto-shredding by destroying keys.
   - Follow NIST SP 800-57 cryptoperiods.
8. **Transport**: TLS 1.2+ (prefer 1.3) with modern ciphers; HSTS; certificate automation (ACME/Let's Encrypt); PKI basics (root/intermediate CA, revocation OCSP/CRL, Certificate Transparency). Details in `kb/05-identity-crypto/pki-and-tls.md`.
9. **Crypto agility and post-quantum**: inventory algorithms and keys (CBOM), keep algorithms configurable, plan migration to NIST ML-KEM (FIPS 203) and ML-DSA (FIPS 204), hybrid key exchange first. See `kb/10-emerging/post-quantum-cryptography.md`.

### Example (Python, libsodium via PyNaCl)
```python
import nacl.secret, nacl.utils
key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)  # store in KMS, not code
box = nacl.secret.SecretBox(key)
ct = box.encrypt(b"data")      # random 24-byte nonce generated and prepended
pt = box.decrypt(ct)           # raises on tampering
```

## How to verify
- Grep for weak primitives: `grep -rnE 'MD5|SHA1|sha1\(|DES|RC4|ECB|Math\.random|random\.random|InsecureSkipVerify|verify=False' src/`.
- SAST: Semgrep (`p/secrets`, crypto rules), CodeQL `security-extended` queries, Bandit (Python), gosec (Go).
- Check password hashes in the DB start with `$argon2id$` or `$2b$`, and parameters meet the minimums above.
- Confirm nonces are generated per encryption (never constant) and keys come from KMS/secret manager, not code.
- `testssl.sh host:443` for TLS; secret scanning for leaked keys.
- Unit tests: tampered ciphertext must fail to decrypt; token comparison uses constant-time functions.

## References
- OWASP Cryptographic Storage Cheat Sheet and Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/
- NIST SP 800-57 Part 1 (key management) · NIST SP 800-38D (GCM) · NIST SP 800-132 (PBKDF) · NIST SP 800-90A (DRBGs)
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA): https://csrc.nist.gov
- RFC 9106 (Argon2) · RFC 5869 (HKDF) · RFC 8439 (ChaCha20-Poly1305)
- libsodium: https://doc.libsodium.org · Google Tink: https://developers.google.com/tink
- See also `kb/05-identity-crypto/pki-and-tls.md`, `kb/05-identity-crypto/secrets-management.md`, `kb/10-emerging/post-quantum-cryptography.md`, `kb/03-application/owasp-top10.md`
