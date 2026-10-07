# Mobile & Client-Side Security

**OWASP MASVS/MASTG** are the standards. Key points:
- Store secrets in Keychain/Keystore, never in code, prefs or logs; no hardcoded API keys.
- Certificate pinning (with a rotation plan); TLS only.
- Protect against reverse engineering (obfuscation is delay, not security), root/jailbreak detection as signal only.
- Validate deep links/intents, WebViews (disable JS bridges unless needed).
- Biometric auth bound to crypto keys; secure local DB (SQLCipher).
- Backend must enforce all authZ – never trust the app.

**Browser/client**: CSP, SRI for CDN scripts, avoid `eval`, sanitize DOM (DOMPurify), `postMessage` origin checks, no secrets in JS bundles or localStorage tokens when avoidable (prefer HttpOnly cookies), third-party script risk (Magecart).
