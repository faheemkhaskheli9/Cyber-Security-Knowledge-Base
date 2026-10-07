# Cryptography Essentials

| Need | Use | Avoid |
|------|-----|-------|
| Symmetric encryption | AES-256-GCM, ChaCha20-Poly1305 | DES/3DES, RC4, ECB mode |
| Hashing (integrity) | SHA-256/SHA-3/BLAKE2 | MD5, SHA-1 |
| Password hashing | Argon2id, bcrypt, scrypt | plain/fast hashes |
| Signatures | Ed25519, ECDSA P-256, RSA-3072+ (PSS) | RSA-1024, DSA |
| Key exchange | X25519/ECDH, (hybrid PQ: ML-KEM) | static DH small groups |
| MAC | HMAC-SHA-256 | home-grown MACs |
| Randomness | OS CSPRNG (`secrets`, `/dev/urandom`, `crypto.randomBytes`) | `rand()`, `Math.random()` |

**Rules**: don't roll your own crypto; use vetted libraries (libsodium, Tink); unique nonces; authenticated encryption; keys in KMS/HSM, rotate, separate from data; TLS 1.2+ (prefer 1.3) with modern ciphers; HSTS; certificate automation (ACME/Let's Encrypt); PKI basics (root/intermediate CA, revocation OCSP/CRL, Certificate Transparency); post-quantum migration planning (NIST ML-KEM/ML-DSA).
