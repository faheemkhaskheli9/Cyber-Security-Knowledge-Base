# SaaS Security (Tenant Configuration and Integrations)

## What
Securing the software-as-a-service applications an organization subscribes to: productivity suites (Microsoft 365, Google Workspace), CRM (Salesforce), code hosting (GitHub, GitLab), data platforms (Snowflake), chat, HR and finance tools. The provider secures the platform; the customer owns identities, tenant settings, sharing, data, and every third-party integration connected to the tenant. **SSPM** (SaaS Security Posture Management) is the tool category that checks these settings continuously. Vendor due diligence and contracts are in `kb/09-governance/grc-compliance-privacy.md`, `kb/05-identity-crypto/oauth-oidc-security.md`, `kb/09-governance/third-party-risk-management.md`; this file covers the technical controls inside each tenant.

## Why it matters
- Most business data now lives in SaaS, reached from any network with a browser, so identity and tenant configuration are the main controls.
- Breaches commonly come from customer-side gaps rather than provider flaws. Examples: the 2024 Snowflake customer-tenant thefts used credentials stolen by infostealers against accounts without MFA (Mandiant, UNC5537); in the Midnight Blizzard intrusion disclosed by Microsoft in January 2024, a password spray hit a legacy test tenant account without MFA and the attacker then abused OAuth applications; in 2022 stolen OAuth tokens issued to Heroku and Travis CI were used to download private GitHub repositories.
- Integrations (OAuth apps, API tokens, connected apps) keep access after password resets and MFA changes and are rarely reviewed.
- Default settings often favor collaboration: external sharing, user consent to apps, guest invitations, and long sessions.

## Attacks
*For authorized testing only. Each pattern lists its main defense.*

| Attack | Example | Defense |
|---|---|---|
| Credential stuffing / spray on local logins | SaaS account not behind SSO, or a legacy account excluded from MFA | SSO enforced for all users, local passwords disabled except break-glass |
| Session / token theft | Infostealer copies browser cookies or refresh tokens; AitM phishing proxies the login | Phishing-resistant MFA, short sessions, device-bound or compliant-device conditional access, revoke sessions on incident |
| Consent phishing | User grants a malicious app `Mail.Read` / `offline_access` or Drive scopes | Restrict user consent, admin-consent workflow, review grants |
| Compromised integration | A trusted vendor's OAuth tokens or API keys are stolen and used against every customer tenant | Least-privilege scopes, IP-restricted tokens where supported, integration inventory, alerts on unusual API volume |
| Social-engineered app authorization | Vishing caller talks a user into authorizing an attacker-controlled "connected app" or device code | Only admins can authorize connected apps; block device code flow where not needed; user training |
| Legacy protocols | IMAP/POP/SMTP AUTH with basic authentication bypasses MFA | Disable legacy and basic authentication |
| Oversharing | "Anyone with the link" files, public Salesforce Experience Cloud guest access, public repositories | Internal-only sharing defaults, expiring links, guest-user profile review |
| Persistence | Mail forwarding rules, new app credentials or service principals, new admin, personal access tokens | Alerts on these changes, block external auto-forwarding, PAT policies |
| Audit blind spots | Logs not enabled, retained briefly, or never exported | Enable and export audit logs to the SIEM |

## Defenses

### 1. Inventory
- Build the SaaS inventory from SSO app lists, OAuth grant reports, expense and procurement records, DNS/proxy logs and browser-extension inventories. Record owner, data classification, users, admins and integrations for each app.
- Tier apps by the data they hold and the access their integrations have; high tiers get the controls below first.

### 2. Identity
- Every app behind the corporate IdP (SAML/OIDC) with **SSO enforced**; disable local password login, keeping only monitored break-glass accounts (`kb/05-identity-crypto/identity-access.md`).
- Phishing-resistant MFA (FIDO2/passkeys) at the IdP, required for admins; conditional access on device compliance and risk.
- **SCIM** provisioning so leavers lose access everywhere at once, plus session and token revocation on offboarding.
- Minimize admin roles; use scoped admin roles and just-in-time elevation where the platform supports it.

### 3. Integrations and tokens
- **Microsoft Entra ID**: restrict user consent (disable, or allow only verified publishers and low-impact permissions) and enable the admin consent workflow; review enterprise apps and service principal credentials.
- **Google Workspace**: in API controls, restrict or block unconfigured third-party apps and mark only reviewed apps as trusted; limit high-risk scopes (Gmail, Drive).
- **GitHub**: require approval for fine-grained personal access tokens and restrict classic PATs at the organization or enterprise level; require token expiration; use GitHub Apps with minimal permissions instead of user tokens; enforce SSO authorization for tokens.
- **Salesforce and similar**: only admins can install or authorize connected apps; restrict API access to approved apps; use IP restrictions for integration users.
- Grant each integration the narrowest scope and a dedicated, non-human integration account; record an owner; review grants quarterly and remove unused ones.

### 4. Data sharing and configuration
- External sharing defaults to internal-only or specific people; external links expire; guest access is limited and reviewed.
- Disable legacy/basic authentication protocols and block automatic external mail forwarding (`kb/02-network/email-security.md`).
- Apply a published secure-configuration baseline and track drift: **CISA SCuBA** baselines for Microsoft 365 and Google Workspace (checked with ScubaGear and ScubaGoggles), CIS Microsoft 365 and Google Workspace Foundations Benchmarks, and vendor security guides. CISA BOD 25-01 (December 2024) requires US federal civilian agencies to inventory their cloud tenants, run CISA's assessment tools and implement the mandatory SCuBA policies for every tenant that has a finalized SCuBA baseline (Microsoft 365 at issue; CISA can add products).
- Use an SSPM tool or scheduled baseline scans once the app count makes manual review impractical.

### 5. Logging and detection
- Enable and export audit logs: Microsoft 365 Unified Audit Log and Entra sign-in/audit logs, Google Workspace audit and investigation logs, GitHub enterprise audit log streaming, Salesforce Event Monitoring, Snowflake `ACCOUNT_USAGE` login and query history.
- Retention in the SIEM meets the incident-response need, not the SaaS default.
- Alert on: new OAuth grants with high-risk scopes, new app credentials, admin role changes, MFA or SSO settings changed, mailbox forwarding rules, mass downloads or exports, logins from anonymizing infrastructure, impossible travel (`kb/08-defensive/soc-detection-ir.md`).

### 6. Resilience and exit
- Know each provider's retention and restore limits; back up critical SaaS data (mail, files, CRM, repositories) where native recovery does not meet RPO/RTO.
- On contract end, export data, revoke integrations and SSO, and confirm deletion.

## How to verify
- Run the baseline tools and track pass rates over time: ScubaGear (`Invoke-SCuBA` in PowerShell) for Microsoft 365, ScubaGoggles for Google Workspace.
- Accounts that bypass SSO or MFA: export users from each high-tier app and compare against the IdP; any local-login account other than break-glass is a finding.
- OAuth grants: in Microsoft Graph PowerShell, `Get-MgOauth2PermissionGrant -All` and review enterprise apps with high-privilege delegated or application permissions; in the Google Admin console, Security > API controls > Manage third-party app access.
- GitHub: organization settings show PAT approval required and classic PATs restricted; `gh api orgs/<ORG>/personal-access-tokens` lists approved fine-grained tokens (requires an org owner and a GitHub App or appropriate token).
- Offboarding test: disable a test user at the IdP and confirm access and refresh tokens stop working in each tier-1 app within the agreed time.
- Sharing: report externally shared and "anyone with the link" files; confirm count trends down.
- Detection test: create a forwarding rule or a consent grant in a test tenant and confirm the SIEM alert fires.

## References
- CISA Secure Cloud Business Applications (SCuBA) and baselines: https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project
- CISA BOD 25-01, Implementing Secure Practices for Cloud Services: https://www.cisa.gov/news-events/directives/bod-25-01-implementing-secure-practices-cloud-services
- ScubaGear: https://github.com/cisagov/ScubaGear · ScubaGoggles: https://github.com/cisagov/ScubaGoggles
- Microsoft Learn, Configure how users consent to applications: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent
- Google Workspace Admin Help, Control which third-party and internal apps access Workspace data: https://support.google.com/a/answer/7281227
- GitHub Docs, Setting a personal access token policy for your organization: https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization
- CIS Benchmarks (Microsoft 365, Google Workspace): https://www.cisecurity.org/cis-benchmarks
- Mandiant, UNC5537 targets Snowflake customer instances (2024): https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
- Microsoft Security Response Center, Midnight Blizzard nation-state attack (2024): https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/
- GitHub Blog, Security alert: Attack campaign involving stolen OAuth user tokens issued to two third-party integrators (April 2022): https://github.blog/2022-04-15-security-alert-stolen-oauth-user-tokens/
- MITRE ATT&CK T1528 (Steal Application Access Token), T1550.001 (Application Access Token), T1078.004 (Cloud Accounts)
- See also `kb/05-identity-crypto/identity-access.md`, `kb/04-cloud-infra/cloud-security.md`, `kb/02-network/email-security.md`, `kb/09-governance/grc-compliance-privacy.md`
