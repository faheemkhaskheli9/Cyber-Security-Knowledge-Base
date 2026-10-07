# Mobile & Client-Side Security

## What
Security of code that runs on devices the attacker controls: iOS/Android apps, desktop apps (Electron, Tauri, native) and browser clients. **OWASP MASVS/MASTG** are the standards: MASVS (Mobile Application Security Verification Standard) defines requirements, MASTG (Mobile Application Security Testing Guide) defines how to test them. MASVS v2 control groups: `MASVS-STORAGE`, `-CRYPTO`, `-AUTH`, `-NETWORK`, `-PLATFORM`, `-CODE`, `-RESILIENCE`, `-PRIVACY`.

## Why it matters
- The binary ships to the attacker: anything in it (keys, endpoints, logic) can be extracted, and any client-side check can be patched out.
- Devices are lost, rooted, backed up to cloud and shared; data at rest leaks unless protected.
- Desktop apps built on web tech turn an XSS into local code execution if hardening is off.
- Backend must enforce all authZ – never trust the app.

## Attacks
*Testing techniques are for authorized targets only (your own apps, written-scope assessments).*

### OWASP Mobile Top 10 (2024)
| # | Risk | Typical example |
|---|------|-----------------|
| M1 | Improper Credential Usage | Hardcoded API keys or service-account creds in the APK/IPA |
| M2 | Inadequate Supply Chain Security | Malicious or vulnerable third-party SDKs (ads, analytics) |
| M3 | Insecure Authentication/Authorization | Auth decided client-side; offline PIN bypassable |
| M4 | Insufficient Input/Output Validation | SQLi in local DB, injection via deep link params |
| M5 | Insecure Communication | Cleartext HTTP, trust-all `TrustManager`, ignored cert errors |
| M6 | Inadequate Privacy Controls | Excess permissions, PII in logs/analytics |
| M7 | Insufficient Binary Protections | Easy repackaging, tampering, secret extraction |
| M8 | Security Misconfiguration | `android:debuggable="true"`, `allowBackup`, exported components |
| M9 | Insecure Data Storage | Tokens in SharedPreferences/NSUserDefaults/SQLite in plaintext |
| M10 | Insufficient Cryptography | Hardcoded keys, ECB, custom crypto |

### Specific attack paths
- **Secret extraction**: `apktool`/`jadx` on the APK or `strings` on the IPA reveals keys and hidden endpoints.
- **Insecure storage**: reading app sandbox on a rooted device or from unencrypted backups; sensitive data in screenshots, keyboard cache, clipboard, logs (`adb logcat`).
- **TLS interception**: user-installed CA plus a proxy reads traffic if the app accepts it; runtime hooks (Frida) bypass pinning.
- **Deep links / intents**: `myapp://reset?token=...` hijacked by another app registering the same scheme; exported Activities/ContentProviders reachable by any app; intent redirection; iOS universal link misconfig.
- **WebView**: `addJavascriptInterface` exposing native methods to injected JS; `setAllowFileAccess` plus file URL loading; loading attacker URLs in an in-app WebView.
- **Tampering**: repackaged app with ads/malware; patched-out license, root or jailbreak checks.
- **Electron/desktop**: XSS + `nodeIntegration: true` = RCE; opening arbitrary URLs with `shell.openExternal`; unsigned or HTTP auto-updates; DLL search-order hijacking.
- **Browser client**: tokens in `localStorage` stolen via XSS, Magecart-style third-party scripts.

## Defenses

### Core mobile controls (MASVS)
- Store secrets in Keychain/Keystore, never in code, prefs or logs; no hardcoded API keys.
- Certificate pinning (with a rotation plan); TLS only.
- Protect against reverse engineering (obfuscation is delay, not security), root/jailbreak detection as signal only.
- Validate deep links/intents, WebViews (disable JS bridges unless needed).
- Biometric auth bound to crypto keys; secure local DB (SQLCipher).

### Storage
- iOS: Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; Data Protection class `NSFileProtectionComplete`.
- Android: Android Keystore (StrongBox where available) to hold keys that encrypt local data; `android:allowBackup="false"` or backup rules excluding sensitive files; `FLAG_SECURE` on sensitive screens.
- Store as little as possible; clear on logout; no tokens or PII in logs (strip logging in release builds).

### Secrets in apps
- Any key shipped in the app is public. Use a backend proxy that holds third-party secrets; give the app only short-lived, user-scoped tokens.
- If a client key is unavoidable (e.g., maps), restrict it by app signature/bundle ID and API, and monitor usage.
- Use App Attest (iOS) / Play Integrity (Android) to raise the cost of scripted abuse; verify verdicts server-side.

### Network and certificate pinning trade-offs
- Android: Network Security Config with `cleartextTrafficPermitted="false"`; don't trust user CAs in release. iOS: keep App Transport Security on, no `NSAllowsArbitraryLoads`.
- Pinning blocks interception with rogue/user CAs but risks outages on cert rotation. If you pin: pin the SPKI public key (not the cert), include at least one backup key, set an expiry, and have a remote kill-switch/forced-update path. Pinning does not stop an attacker on their own rooted device.

### Root/jailbreak detection limits
- Detection is bypassable (Frida, Magisk hide modules); use it as a risk signal to the backend, not a security boundary. Don't break the app for legitimate users on custom ROMs unless risk requires it.

### Deep links, intents and WebView
- Android: `android:exported="false"` by default (required to be explicit since API 31), permission-protect exported components, use App Links (`autoVerify`) and validate all parameters; use explicit intents; `PendingIntent.FLAG_IMMUTABLE`.
- iOS: universal links over custom schemes; validate URL host/path/params; never perform sensitive actions from a link without user confirmation and re-auth.
- WebView: JavaScript off unless needed; `setAllowFileAccess(false)`, `setAllowContentAccess(false)`; load only allowlisted HTTPS origins; open other links in the system browser or Custom Tabs/`SFSafariViewController`; on iOS use `WKWebView` (not `UIWebView`). Expose JS bridges only to trusted origins with minimal methods.

### Desktop / Electron hardening
```js
new BrowserWindow({ webPreferences: {
  contextIsolation: true,      // default since Electron 12
  nodeIntegration: false,      // default since Electron 5
  sandbox: true,               // default for renderers since Electron 20
  webSecurity: true,
  preload: path.join(__dirname, 'preload.js')  // expose narrow APIs via contextBridge
}});
```
- Strict CSP; load only local or HTTPS content; no `remote` module; validate IPC sender and arguments; allowlist URLs in `will-navigate`/`setWindowOpenHandler`; validate protocols before `shell.openExternal`.
- Electron Fuses: disable `RunAsNode` and `EnableNodeCliInspectArguments`; enable ASAR integrity.
- Signed builds and signed updates over HTTPS (code signing + notarization on macOS); keep Electron current (Chromium CVEs).

### Browser/client
CSP, SRI for CDN scripts, avoid `eval`, sanitize DOM (DOMPurify), `postMessage` origin checks, no secrets in JS bundles or localStorage tokens when avoidable (prefer HttpOnly cookies), third-party script risk (Magecart). Details: `kb/03-application/browser-client-side.md`.

### Supply chain and build
- Inventory SDKs and their permissions/data collection; pin versions; SCA on Gradle/CocoaPods/SPM. Release builds: R8/ProGuard, no debug flags, signing keys in a HSM/managed service (Play App Signing).

## How to verify
*Use only on apps you own or are authorized to test.*
- **Static**: MobSF (`docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf`) on the APK/IPA; `jadx`, `apktool d app.apk`; grep for keys: `grep -rEi "api[_-]?key|secret|AKIA" decompiled/`; secrets scanners (gitleaks, trufflehog) on the source.
- **Manifest/plist**: check `debuggable`, `allowBackup`, `exported`, `usesCleartextTraffic`, ATS exceptions.
- **Dynamic**: Frida and objection on a test device: `objection -g com.example.app explore`, then `android sslpinning disable` (to confirm pinning exists and how the backend reacts), `env`, `android keystore list`, `ios keychain dump` to inspect what is stored.
- **Storage**: inspect `/data/data/<pkg>/` (rooted test device) and backups for plaintext tokens; check logcat for PII.
- **Network**: Burp/mitmproxy with a test CA; confirm release builds reject the user CA.
- **Deep links**: `adb shell am start -W -a android.intent.action.VIEW -d "myapp://path?x=test" com.example.app`; drozer for exported components.
- **Electron**: Electronegativity (`electronegativity -i ./app`) for insecure `webPreferences`; check fuses with `npx @electron/fuses read --app <path>`.
- Map results to MASVS controls; use MASTG test cases as the checklist.

## References
- OWASP MAS (MASVS, MASTG, MAS Checklist): https://mas.owasp.org/
- OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/
- Electron Security checklist: https://www.electronjs.org/docs/latest/tutorial/security
- Android Developers – Security best practices and Network Security Configuration (developer.android.com)
- Apple Platform Security Guide (support.apple.com)
- MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF · Frida: https://frida.re · objection: https://github.com/sensepost/objection
- See also `kb/03-application/api-security.md`, `kb/05-identity-crypto/secrets-management.md`, `kb/05-identity-crypto/pki-and-tls.md`
