# Browser Extension Security

## What
Browser extensions (Chrome/Edge Manifest V3, Firefox WebExtensions, Safari Web Extensions) are code that runs inside the browser with privileges web pages lack: reading and changing every page a user visits, reading cookies, intercepting requests, capturing tabs and screenshots, reading the clipboard, and talking to local programs through native messaging. This file covers two sides: **organizations** controlling which extensions run on managed browsers, and **developers** building and publishing extensions safely. MITRE ATT&CK tracks attacker use as T1176 (browser extensions as a persistence technique).

## Why it matters
- **The browser is where sessions live**: an extension with `<all_urls>` host access sees SSO portals, admin consoles, webmail and SaaS data after MFA, and can read or act within those sessions. Phishing-resistant MFA does not help once the session is in the browser.
- **Supply chain with auto-update**: extensions update silently from the store. A legitimate extension becomes malicious when its developer account is phished or the extension is sold to a new owner; every installed copy then runs the new code. In December 2024 attackers phished a Chrome Web Store developer at Cyberhaven and pushed a malicious version that targeted session data, as part of a wider campaign against several extensions. The Great Suspender was removed by Google as malware in 2021 after an ownership change.
- **Shadow IT**: users install extensions without review, often with broad permissions, and they are rarely in software inventories (`kb/04-cloud-infra/saas-security.md`).
- **Malware persistence**: malware force-installs extensions through browser policy or launches the browser with `--load-extension` to inject ads, redirect searches or steal data.
- **Developer liability**: a bug in a popular extension (message handlers trusting any page, XSS in extension pages) is a vulnerability in every user's browser.

## Attacks
*For authorized testing only. Each pattern lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Overbroad permissions | Extension requests `<all_urls>`, `cookies`, `webRequest`, `scripting`, `tabs`, `clipboardRead`, `nativeMessaging` for a narrow feature | Org: review permissions before allowlisting; block high-risk permissions by policy. Dev: least privilege, `activeTab`, `optional_permissions` |
| Malicious update after takeover | Developer store account phished (including OAuth consent phishing) or extension sold; new version exfiltrates cookies or page data | Org: allowlist plus re-review on permission changes, pin or block on incident. Dev: strong MFA on store and publishing accounts, few publishers, signed/verified uploads where the store supports them |
| Malicious extension from the store | Clone of a popular tool, fake AI chatbot or "productivity" extension with hidden data collection | Deny by default; allowlist only reviewed extension IDs |
| Policy-based sideloading | Malware writes `ExtensionInstallForcelist` registry/plist entries or edits browser preference files to force-install its extension | Managed policy from MDM/GPO overrides local values; EDR rules on browser policy key changes; alert on unknown force-installed IDs |
| Command-line loading | Browser launched with `--load-extension=<path>` (used by ChromeLoader-style malware) | Detect browser processes with `--load-extension` outside developer machines; block developer-mode loading on managed devices |
| Untrusted page messages | Content script or `onMessageExternal` handler acts on `window.postMessage` or external messages from any site (e.g., "fetch this URL with your privileges") | Validate `event.origin` / `sender.url` / `sender.id` and message schema; restrict `externally_connectable` `matches` |
| Content script data leak | Content script injects UI or data into the page DOM, where page scripts can read it | Keep secrets in the service worker, not the page; use extension pages or Shadow DOM for UI; never trust the page DOM |
| XSS in extension pages | Popup or options page renders data from web pages with `innerHTML` | MV3 CSP (no remote code, no `eval`); encode output; sanitize with DOMPurify if HTML is needed |
| Web-accessible resource abuse | Resources exposed to all sites allow fingerprinting the user's extensions or clickjacking extension UI | Expose as few resources as possible, limit `matches`, use `use_dynamic_url` |
| Native messaging host abuse | Extension forwards page-controlled input to a local native host that runs commands | Native host validates every message, allows only its own extension ID in `allowed_origins`, runs with least privilege |
| Credential and token storage | API tokens stored in `chrome.storage.local` or `localStorage`, readable by malware on disk or by content scripts | Short-lived tokens; `chrome.storage.session` for in-memory data; keep tokens out of content scripts |

## Defenses

### 1. Organization: control what runs
- **Deny by default, allowlist by ID**. Chrome and Edge `ExtensionSettings` policy; Firefox `ExtensionSettings` in `policies.json` or GPO. Example Chrome/Edge policy (placeholder ID):

```json
{
  "*": {
    "installation_mode": "blocked",
    "blocked_permissions": ["nativeMessaging", "debugger", "proxy"],
    "runtime_blocked_hosts": ["*://*.idp.example.com", "*://admin.example.com"],
    "blocked_install_message": "Request extensions through the IT portal."
  },
  "abcdefghijklmnopabcdefghijklmnop": {
    "installation_mode": "allowed",
    "runtime_blocked_hosts": ["*://*.idp.example.com"]
  }
}
```

- `runtime_blocked_hosts` keeps allowed extensions off the identity provider, admin consoles and other crown-jewel sites.
- Force-install (`installation_mode: force_installed`) only the extensions the business requires (password manager, security tooling), from the official store update URL.
- Block installation from outside the store and restrict developer-mode loading on managed devices; apply policy through MDM or GPO so local changes are overridden.
- Require a managed browser profile (browser management or enterprise browser) for access to sensitive SaaS through conditional access (`kb/01-foundations/zero-trust-architecture.md`).

### 2. Organization: review and monitor
- Review requests: publisher identity, permissions and host access vs. stated purpose, privacy policy, update history, install base, whether it was recently transferred; prefer vendor-published extensions. Record owner and business reason, as for third-party apps (`kb/09-governance/third-party-risk-management.md`).
- Inventory installed extensions across devices from the browser management console or EDR; diff against the allowlist.
- Re-review when an allowed extension requests new permissions (Chrome disables an updated extension that asks for new permissions until the user approves; on managed devices make that an IT decision).
- Detect: new force-install policy entries not from MDM, `--load-extension` command lines, extension IDs on threat-intel block lists, and unusual traffic from browser processes to new domains (`kb/08-defensive/soc-detection-ir.md`).
- Incident: remove or block the ID by policy everywhere, then revoke sessions and tokens for affected users and rotate credentials the extension could see; removing the extension does not invalidate stolen cookies.

### 3. Developer: build with least privilege
- Request the minimum: `activeTab` instead of `<all_urls>`, specific `host_permissions`, `optional_permissions` requested at the moment of use.
- Manifest V3: no remotely hosted code, no `eval`; bundle all scripts; keep the default extension CSP or tighten it.
- Treat everything from content scripts and web pages as untrusted. In `runtime.onMessage` and `onMessageExternal`, check `sender.id`, `sender.origin`/`sender.url` and the message schema; never fetch or execute arbitrary URLs or code on a page's request.
- Restrict `externally_connectable` to your own domains; minimize `web_accessible_resources`.
- Render with `textContent` or a framework with auto-escaping; never inject page-derived HTML into extension pages.
- Store secrets in the service worker or `chrome.storage.session`, not in content scripts or the page; use short-lived tokens and the browser's identity APIs for OAuth.
- Dependencies: pin and scan them like any app (`kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`); build in CI and publish from CI rather than laptops.

### 4. Developer: protect publishing
- Phishing-resistant MFA on store developer accounts and on any Google/Microsoft/Mozilla account with publishing rights; minimal set of publishers; review third-party OAuth apps granted access to those accounts.
- Use the store's options to require signed or verified uploads where available, and alert on any version published outside the release pipeline.
- Publish a security contact (`SECURITY.md`, `templates/`) and a disclosure process.

## How to verify
- On a managed test device, try to install an extension not on the allowlist from the store and from a local folder; both must be blocked. Check `chrome://policy` (or `edge://policy`, `about:policies`) shows `ExtensionSettings` applied from the management source, not from the user.
- Check an allowed extension cannot run on a host in `runtime_blocked_hosts` (its content script does not inject there).
- Export the extension inventory from the management console; every installed ID must be on the allowlist with an owner; investigate any unknown ID.
- Run a detection test: launch the browser with `--load-extension` and add a local force-install policy entry on a test host; both must alert.
- For your own extension: review `manifest.json` permissions against features; run a page that sends crafted `postMessage` and `runtime.sendMessage` messages and confirm handlers refuse them; check extension pages for unsafe sinks with Semgrep or ESLint (`eslint-plugin-no-unsanitized`).
- Confirm store developer accounts enforce MFA and list only current publishers.

## References
- Chrome for Developers, Stay secure (extensions): https://developer.chrome.com/docs/extensions/develop/security-privacy/stay-secure
- Chrome for Developers, Declare permissions: https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions
- Chrome for Developers, Message passing: https://developer.chrome.com/docs/extensions/develop/concepts/messaging
- Chrome for Developers, Manifest V3 overview: https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3
- Chrome Enterprise policy list (ExtensionSettings, ExtensionInstallForcelist): https://chromeenterprise.google/policies/
- Microsoft Edge browser policy reference: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies
- Mozilla Firefox enterprise policy templates (ExtensionSettings): https://mozilla.github.io/policy-templates/
- MDN, Browser extensions (WebExtensions): https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions
- MITRE ATT&CK T1176, browser extensions: https://attack.mitre.org/techniques/T1176/
- See also `kb/03-application/browser-client-side.md`, `kb/04-cloud-infra/saas-security.md`, `kb/04-cloud-infra/os-hardening.md`, `kb/09-governance/third-party-risk-management.md`, `kb/08-defensive/insider-threat.md`
