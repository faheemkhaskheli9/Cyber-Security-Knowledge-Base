# Cloud Provider Security Baselines (AWS / Azure / GCP)

## What
Concrete, provider-specific baselines for a new or inherited cloud estate, side by side for AWS, Azure and GCP. This is the hands-on companion to `kb/04-cloud-infra/cloud-security.md`, which covers the generic concepts (shared responsibility, IAM principles, network and data controls). Here the focus is *which switch to flip in which provider*.

Resource hierarchy, for orientation:

| Level | AWS | Azure | GCP |
|---|---|---|---|
| Top | Organization (management account) | Entra ID tenant + root management group | Organization (tied to a Cloud Identity / Workspace domain) |
| Grouping | Organizational units (OUs) | Management groups | Folders |
| Billing / isolation unit | Account | Subscription (+ resource groups) | Project |
| Guardrail engine | SCPs, RCPs, declarative policies | Azure Policy (deny / audit / modify / deployIfNotExists) | Organization Policy constraints |
| Highest identity | Root user of each account | Global Administrator (can elevate to User Access Administrator at root `/`) | Super Admin (Cloud Identity) + Organization Administrator |

## Why it matters
- Defaults differ per provider and many important controls are **off by default**: GCP Data Access audit logs (except BigQuery), Azure resource diagnostic logs, AWS GuardDuty and Security Hub, Azure Defender plans beyond the free tier.
- Guardrails applied at the top of the hierarchy are the only controls a compromised workload admin cannot remove; per-account settings can be undone by whoever holds that account.
- Most incidents follow a short list of provider-specific paths (below). A day-one baseline closes most of them before workloads land.

## Attacks
*For authorized testing only. Generic descriptions are in `kb/04-cloud-infra/cloud-security.md`; this table maps each pattern to the provider-specific mechanism.*

| Pattern | AWS | Azure | GCP |
|---|---|---|---|
| Leaked long-lived credentials | IAM user access keys (`AKIA...`) in git, CI logs, images | App registration client secrets, storage account keys, SAS tokens | Service account JSON key files, HMAC keys for Cloud Storage |
| SSRF to metadata service | `169.254.169.254`; IMDSv1 needs no token, returns role credentials | IMDS at `169.254.169.254` needs `Metadata: true`; returns managed identity tokens | `metadata.google.internal` needs `Metadata-Flavor: Google`; returns service account tokens |
| Public storage | S3 bucket policy `Principal: "*"`, legacy ACLs, public snapshots/AMIs | Blob container anonymous access, long-lived account SAS | `allUsers` / `allAuthenticatedUsers` on buckets, public images/datasets |
| Privilege escalation via identity hand-off | `iam:PassRole` + `ec2:RunInstances` / `lambda:CreateFunction`; `iam:CreatePolicyVersion`; `iam:AttachUserPolicy` | Assigning a privileged managed identity (`.../userAssignedIdentities/assign/action`) to a VM you control; VM Run Command on a VM with a privileged identity; `roleAssignments/write` | `iam.serviceAccounts.actAs` + `compute.instances.create`; `iam.serviceAccounts.getAccessToken` / `signJwt` (Token Creator); `setIamPolicy` on a project |
| Cross-tenant / consent abuse | Confused deputy: third-party role trust with no `sts:ExternalId`; overly broad OIDC trust (`sub` wildcard) | Illicit consent grant: users consent to a malicious multi-tenant app with mail/files scopes; abused guest/B2B access | Third-party OAuth apps granted Workspace scopes; external identities bound via IAM when domain restriction is off; broad WIF pool with no attribute condition |
| Disabling logging | `cloudtrail:StopLogging`, `DeleteTrail`, `PutEventSelectors`; `guardduty:DeleteDetector` | Deleting diagnostic settings; disabling Defender plans | Deleting log sinks, adding exclusions to `_Default`, removing Data Access `auditConfigs` |
| Crypto-mining after compromise | GPU instances in unused regions; GuardDuty `CryptoCurrency:*` findings | VM scale sets / Batch in new regions; Defender for Cloud mining alerts | GPU VMs in new projects/regions; SCC Event Threat Detection cryptomining findings |

Typical chain: leaked key or SSRF yields credentials, attacker enumerates IAM, escalates through the hand-off permission, disables logging, then exfiltrates data or launches miners.

## Defenses

### Control matrix

| Control area | AWS | Azure | GCP |
|---|---|---|---|
| Org structure and guardrails | AWS Organizations with OUs (Security, Infrastructure, Workloads, Sandbox); SCPs deny leaving org, unused regions, logging/GuardDuty changes, root actions; RCPs to restrict resource access to your org (`aws:PrincipalOrgID`); Control Tower optional | Management group hierarchy; Azure Policy assigned at management group: allowed locations, deny public network access, require diagnostic settings (deployIfNotExists); Microsoft cloud security benchmark initiative | Folders per environment; Org Policy constraints: `iam.disableServiceAccountKeyCreation`, `iam.allowedPolicyMemberDomains`, `storage.publicAccessPrevention`, `storage.uniformBucketLevelAccess`, `compute.vmExternalIpAccess`, `compute.requireOsLogin`, `gcp.resourceLocations`, `compute.skipDefaultNetworkCreation`, `iam.automaticIamGrantsForDefaultServiceAccounts` |
| Root and break-glass | Hardware MFA on management account root, no root access keys; use centralized root access management to remove member-account root credentials; break-glass IAM role in a dedicated account, alarmed | Two cloud-only emergency access accounts with FIDO2 keys, excluded from Conditional Access only as needed, sign-ins alerted; Global Admin count kept small; PIM for eligible (not standing) admin roles | 2+ dedicated Super Admin accounts with security keys, not used for daily work; Organization Administrator granted to a group, not individuals; alert on Super Admin sign-in |
| SSO, MFA, workload identity | IAM Identity Center federated to IdP; no IAM users for humans; IRSA / EKS Pod Identity, instance profiles; GitHub/GitLab OIDC to `sts:AssumeRoleWithWebIdentity` with `sub` condition | Entra ID with Conditional Access requiring phishing-resistant MFA (Azure enforces MFA for portal/CLI sign-in); managed identities; federated identity credentials on app registrations/user-assigned identities for CI | Cloud Identity / Workspace or federation from external IdP; 2-Step Verification enforced; attached service accounts; Workload Identity Federation pools with `attribute.condition` restricting repo/branch; GKE Workload Identity |
| Audit logging | Organization CloudTrail, multi-region, log file validation, delivered to S3 in a Log Archive account with Object Lock; data events for sensitive buckets; AWS Config recorder in all used regions | Activity Log exported via subscription diagnostic settings; Entra sign-in and audit logs exported; per-resource diagnostic settings (Key Vault, Storage, SQL) enforced by policy; Log Analytics workspace in a security subscription | Admin Activity logs (always on); enable Data Access logs at org level for critical services; aggregated org sink to a locked Cloud Storage bucket or log bucket with retention lock in a logging project |
| Threat detection | GuardDuty in all regions via delegated admin, auto-enable for new accounts; S3, EKS, runtime and malware protection as needed | Defender for Cloud workload plans (Servers, Storage, Key Vault, Containers, Resource Manager) on every subscription; Sentinel for SIEM | Security Command Center (Premium or Enterprise for Event Threat Detection and Container Threat Detection) activated at org level |
| Posture | Security Hub with AWS Foundational Security Best Practices and CIS standards, aggregated to delegated admin; IAM Access Analyzer (external and unused access) | Defender CSPM (secure score, attack paths); Azure Policy compliance; regulatory compliance dashboard | SCC Security Health Analytics, Cloud Asset Inventory; IAM Recommender for excess permissions |
| Storage public-access blocks | S3 Block Public Access at account level (all four settings), SCP denying `s3:PutAccountPublicAccessBlock`; Object Ownership `BucketOwnerEnforced`; block public EBS snapshot and AMI sharing | `allowBlobPublicAccess=false` and `allowSharedKeyAccess=false` on storage accounts (enforce via policy); `publicNetworkAccess=Disabled` where private endpoints exist | Org Policy `storage.publicAccessPrevention` + `storage.uniformBucketLevelAccess`; domain restriction stops `allUsers` grants |
| KMS | Customer managed keys for sensitive data, automatic rotation, key policies separating admins from users; EBS encryption by default per region; alert on `ScheduleKeyDeletion` / `DisableKey` | Key Vault with RBAC permission model, soft delete and purge protection on; customer managed keys for storage/SQL where required; Managed HSM for high-assurance | Cloud KMS CMEK with rotation period; keys in a dedicated project; `KMS CryptoKey Encrypter/Decrypter` granted to service agents only; Org Policy to require CMEK for chosen services |
| Network | IMDSv2 required (account default + SCP on `ec2:MetadataHttpTokens`), hop limit 1; VPC endpoints for S3, STS, KMS, Secrets Manager with endpoint policies; no `0.0.0.0/0` on 22/3389; VPC Flow Logs | Private Endpoints for PaaS; NSGs deny by default; Azure Bastion or JIT VM access instead of public RDP/SSH; IMDS header requirement plus egress filtering | Private Google Access / Private Service Connect; VPC Service Controls perimeter around data projects; IAP for SSH/RDP; firewall rules deny ingress by default; VPC Flow Logs |
| Secrets | Secrets Manager with rotation; Parameter Store SecureString for config; no secrets in Lambda env vars or user data | Key Vault references from App Service/Functions accessed by managed identity; no secrets in app settings | Secret Manager with per-secret IAM; mounted via service account, not baked into images or env files |

### Guarding identity hand-off and cross-tenant trust

| Risk | AWS | Azure | GCP |
|---|---|---|---|
| Hand-off permission | Scope `iam:PassRole` to specific role ARNs with `iam:PassedToService`; permission boundaries on roles that create roles | Grant Managed Identity Operator only on specific identities; limit Virtual Machine Contributor where VMs carry privileged identities | Grant Service Account User / Token Creator on individual service accounts, never at project level |
| Third-party access | Require `sts:ExternalId` for vendor roles; `aws:SourceAccount` / `aws:SourceArn` in service resource policies | Restrict user consent; review enterprise app permissions; Cross-tenant access settings for B2B | Domain restricted sharing; Workspace API controls for third-party OAuth apps |
| CI federation trust | Pin `token.actions.githubusercontent.com:sub` to repo and branch/environment | Federated credential subject pinned to repo and environment | `attribute.condition` on the provider pinned to repo and ref |

Baseline alerts on every provider: break-glass/root sign-in, new long-lived credential, role or policy grant at top scope, logging or detector disabled, public storage created, activity in an unused region.

Secret handling patterns in general: `kb/05-identity-crypto/secrets-management.md`. CI federation: `kb/06-secure-sdlc/cicd-security.md`.

### AWS first day
1. Create the Organization; move workloads out of the management account; create Security (audit, delegated admin) and Log Archive accounts.
2. Lock root: hardware MFA on the management account root, delete any root access keys, enable centralized root access management for member accounts.
3. Enable IAM Identity Center with your IdP and MFA; delete or disable human IAM users and their access keys.
4. Attach baseline SCPs: deny unused regions, deny leaving the org, deny CloudTrail/Config/GuardDuty changes, deny disabling S3 Block Public Access, require IMDSv2.
5. Organization CloudTrail (multi-region, log validation) to the Log Archive bucket with Object Lock.
6. GuardDuty and Security Hub org-wide via delegated admin, auto-enabled for new accounts; IAM Access Analyzer at org scope.
7. Account-level S3 Block Public Access, EBS encryption by default, IMDSv2 as the account default.
8. Budgets and anomaly alerts to catch mining.

### Azure first day
1. Build the management group hierarchy (platform, landing zones, sandbox, decommissioned); move subscriptions under it.
2. Create two emergency access accounts with FIDO2 keys; alert on their use; move admins to PIM eligible assignments.
3. Conditional Access: phishing-resistant MFA for admins, MFA for all users, block legacy authentication.
4. Restrict user consent to apps (verified publishers and low-risk permissions only) and enable the admin consent workflow.
5. Assign Azure Policy at the top management group: allowed locations, deny storage public blob access and shared key, require diagnostic settings, require Key Vault purge protection.
6. Export Activity Log and Entra sign-in/audit logs to a Log Analytics workspace in a security subscription.
7. Enable Defender for Cloud plans (including Defender CSPM) on every subscription; connect Sentinel.
8. Audit who holds Owner and User Access Administrator, and who can elevate access at root scope.

### GCP first day
1. Verify the organization resource exists; create folders per environment and dedicated logging and security projects.
2. Secure Super Admin accounts with security keys; grant Organization Administrator to a group; remove the default broad grants (Project Creator and Billing Account Creator to the whole domain) if not wanted.
3. Set Org Policy constraints: disable service account key creation and upload, domain restricted sharing, public access prevention, uniform bucket-level access, no external IPs, OS Login, resource locations, no default network, no automatic Editor grants for default service accounts.
4. Enable Data Access audit logs at org level for critical services; create an aggregated org log sink to a retention-locked bucket.
5. Activate Security Command Center at org level.
6. Replace service account keys with attached service accounts and Workload Identity Federation for CI.
7. Put data projects inside a VPC Service Controls perimeter; use IAP for admin access.
8. Review OAuth app access controls in the Workspace / Cloud Identity admin console.

## How to verify

### Scanners (concept level)
- **Prowler**: open-source CLI that runs hundreds of checks per provider and maps results to compliance frameworks, including the CIS Foundations benchmarks. Run with read-only credentials (AWS `SecurityAudit` + `ViewOnlyAccess`, Azure Reader, GCP Viewer / Security Reviewer).
- **ScoutSuite**: multi-cloud auditor that snapshots configuration and renders an offline HTML report; good for a one-off assessment.
- **Steampipe**: exposes cloud APIs as SQL tables; compliance benchmarks (CIS and others) run through its Powerpipe mods. Useful for custom queries across many accounts.
- Native posture tools (Security Hub, Defender CSPM, SCC) give continuous scoring; scanners give a second, independent view.

### AWS CLI
```bash
aws iam get-account-summary --query 'SummaryMap.[AccountMFAEnabled,AccountAccessKeysPresent]'  # want 1, 0
aws s3control get-public-access-block --account-id 111122223333
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws cloudtrail describe-trails --query 'trailList[].[Name,IsOrganizationTrail,IsMultiRegionTrail,LogFileValidationEnabled]'
aws cloudtrail get-trail-status --name <TRAIL_NAME>      # IsLogging must be true
aws guardduty list-detectors                             # run per region
aws securityhub get-enabled-standards
aws ec2 get-ebs-encryption-by-default
```
IMDSv2: query `describe-instances` for `MetadataOptions.HttpTokens` not equal to `required` (example in `kb/04-cloud-infra/cloud-security.md`).

### Azure CLI
```bash
az account list --output table
az role assignment list --all --query "[?roleDefinitionName=='Owner'].{who:principalName,scope:scope}"
az ad app list --all --query "[].{name:displayName,appId:appId}"     # review apps and their credentials
az policy assignment list --output table
az security pricing list --output table                              # Defender plan tiers
az storage account list --query "[].{name:name,public:allowBlobPublicAccess,sharedKey:allowSharedKeyAccess}"
```
Also check, in the portal or via Microsoft Graph: enterprise app consent grants and user consent settings, Conditional Access policies, and that subscription-level diagnostic settings export the Activity Log.

### GCP CLI
```bash
gcloud organizations list
gcloud org-policies list --organization=<ORG_ID>
gcloud logging sinks list --organization=<ORG_ID>
gcloud projects get-iam-policy <PROJECT_ID> --format=json   # inspect bindings and auditConfigs
gcloud iam service-accounts keys list --iam-account=<SA_EMAIL> --managed-by=user   # want none
gcloud asset search-all-iam-policies --scope=organizations/<ORG_ID> --query="policy:allUsers"
```
SCC findings can be listed with `gcloud scc findings list`; check the current docs for the required parent and location arguments.

### Benchmarks
- **CIS Amazon Web Services Foundations Benchmark**: IAM, logging, monitoring alarms, networking, storage.
- **CIS Microsoft Azure Foundations Benchmark**: Entra ID, Defender, storage, logging, networking, Key Vault.
- **CIS Google Cloud Platform Foundation Benchmark**: IAM, logging, networking, VMs, storage, Cloud SQL, BigQuery.
- Pick the current version in your scanner, record a baseline score, track deviations as exceptions with an owner and expiry.

### Detection tests (sandbox account only)
Trigger a benign `StopLogging` attempt, a root/Super Admin/break-glass sign-in, and a public-bucket creation; confirm the guardrail blocks or the alert fires. See `kb/08-defensive/soc-detection-ir.md`.

## References
- CIS Benchmarks (AWS, Azure, GCP Foundations): https://www.cisecurity.org/cis-benchmarks
- AWS Security Reference Architecture; AWS Organizations SCP/RCP docs; IMDSv2 and Block Public Access docs (docs.aws.amazon.com)
- Microsoft cloud security benchmark; Azure landing zone guidance; "Manage emergency access accounts in Microsoft Entra ID"; illicit consent grant detection and remediation (learn.microsoft.com)
- Google Cloud enterprise foundations blueprint; Organization Policy constraints list; Cloud Audit Logs docs (cloud.google.com)
- Prowler: https://github.com/prowler-cloud/prowler · ScoutSuite: https://github.com/nccgroup/ScoutSuite · Steampipe: https://steampipe.io
- Rhino Security Labs research on AWS and GCP IAM privilege escalation paths
- See also `kb/04-cloud-infra/cloud-security.md`, `kb/04-cloud-infra/containers-kubernetes-iac.md`, `kb/05-identity-crypto/identity-access.md`
