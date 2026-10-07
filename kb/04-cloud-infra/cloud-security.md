# Cloud Security (AWS / Azure / GCP)

## What
Securing workloads, data and identities in public cloud (IaaS, PaaS, SaaS control planes). **Shared responsibility**: provider secures the cloud; you secure what you put in it (IAM, data, config, workloads). The split shifts by service model:

| Layer | IaaS (EC2/VM) | PaaS (Lambda/App Service/Cloud Run) | SaaS |
|---|---|---|---|
| Physical, hypervisor, network fabric | Provider | Provider | Provider |
| OS patching, runtime | **You** | Provider | Provider |
| App code, dependencies | **You** | **You** | Provider |
| IAM, data, config, network rules | **You** | **You** | **You** (users, sharing, settings) |

## Why it matters
- Most cloud breaches are customer misconfiguration and identity compromise, not provider failures: exposed storage, leaked keys, overprivileged roles.
- The control plane is internet-reachable: one leaked credential can delete or exfiltrate everything, or spin up costly compute.
- Example: Capital One 2019 (SSRF to EC2 metadata, overprivileged role, S3 exfiltration).

## Attacks
*For authorized testing only; each item is paired with prevention/detection.*

### Top risks
Public storage buckets, over-privileged IAM, exposed management ports (22/3389), leaked access keys, unencrypted data, no logging, metadata service SSRF (use IMDSv2), unpatched VMs, open security groups, missing MFA on root/admin.

| Attack | How it works | Prevent / detect |
|---|---|---|
| Leaked keys | `AKIA...` keys committed to git, in CI logs, Docker images or mobile apps; bots scan public GitHub within minutes | No long-lived keys, secret scanning push protection; GuardDuty/Defender alerts on anomalous API use |
| SSRF to metadata | App fetches `http://169.254.169.254/...` and returns role credentials | IMDSv2 required, hop limit 1, SSRF allowlist; alert on instance creds used outside the instance |
| Misconfigured storage | Public bucket/container or "anyone with link" ACLs; listing exposes backups and PII | Org-wide block public access, deny policies, CSPM alerts |
| Overprivileged roles | `*:*` policies, `iam:PassRole` + compute create = privilege escalation | Least privilege, Access Analyzer, permission boundaries |
| Cryptomining | Stolen creds launch GPU instances in unused regions | Region-deny SCP, service quotas, budget alerts, GuardDuty `CryptoCurrency` findings |
| Log tampering | `StopLogging` / `DeleteTrail` to blind defenders | SCP denying logging changes, logs in separate account with object lock |
| Exposed services | Public DB, Kubernetes API, Redis, 22/3389 open to `0.0.0.0/0` | Private subnets, bastion-less access (SSM/IAP/Bastion), SG reviews |
| Persistence | New IAM users/keys, cross-account trust added, OIDC trust too broad | Alert on IAM changes; restrict trust policies by `sub`/audience |

## Defenses

### Baseline
- Root/owner account: MFA, no daily use, no access keys.
- IAM: least privilege, roles over long-lived keys, SSO, permission boundaries/SCPs, regular access reviews.
- Logging: CloudTrail/Activity Log/Audit Logs → central immutable store; GuardDuty/Defender/SCC enabled.
- Network: private subnets, security groups default-deny, no public DBs, VPC endpoints.
- Data: encrypt at rest (KMS/CMK) and in transit, block public access org-wide, backups + tested restore.
- Config: CSPM (Prowler, ScoutSuite, Steampipe, Checkov), CIS Benchmarks.
- Secrets: Secrets Manager / Key Vault / Secret Manager.

### Identity
1. Centralized SSO (IAM Identity Center / Entra ID / Cloud Identity) with phishing-resistant MFA; break-glass accounts with hardware keys, monitored.
2. **No long-lived keys**: workloads use instance profiles/managed identities/service account attachment; CI uses OIDC federation (`kb/06-secure-sdlc/cicd-security.md`); humans use short-lived SSO sessions. Disable GCP service-account key creation via org policy `iam.disableServiceAccountKeyCreation`.
3. Least privilege: start from managed read-only, generate policies from access activity (IAM Access Analyzer policy generation), remove unused permissions; avoid `Action: "*"` and `Resource: "*"`; guard `iam:PassRole`, `sts:AssumeRole` trust policies and `iam:CreateAccessKey`.

### Organization guardrails (SCPs / Azure Policy / GCP Org Policy)
- Separate accounts/subscriptions/projects per environment; security tooling and logs in dedicated accounts.
- Example SCP denials: leaving the org, disabling CloudTrail/GuardDuty/Config, regions not in use, root user actions, creating IAM users with access keys, disabling S3 Block Public Access.
```json
{"Effect":"Deny","Action":["cloudtrail:StopLogging","cloudtrail:DeleteTrail","guardduty:DeleteDetector"],"Resource":"*"}
```
- GCP org policies: `storage.publicAccessPrevention`, `compute.requireOsLogin`, `compute.vmExternalIpAccess`, `iam.allowedPolicyMemberDomains`. Azure Policy: deny public blob access, require private endpoints, allowed locations.

### Logging and detection
- AWS: org-wide multi-region CloudTrail (+ data events for sensitive buckets), log file validation, S3 Object Lock; Config recorder; GuardDuty, Security Hub.
- Azure: Activity Log + Entra ID sign-in/audit logs + resource diagnostic settings to Log Analytics; Defender for Cloud; Sentinel.
- GCP: Admin Activity (always on) + Data Access audit logs enabled; aggregated sinks to a locked bucket; Security Command Center.
- Alerts: root login, IAM policy changes, new access keys, logging disabled, public resource created, unusual regions. See `kb/08-defensive/soc-detection-ir.md`.

### Storage and data
- S3 Block Public Access at account and org level; `BucketOwnerEnforced` (ACLs disabled); bucket policy `aws:SecureTransport` deny; Azure `allowBlobPublicAccess=false`; GCP uniform bucket-level access + public access prevention.
- KMS: customer-managed keys for sensitive data, key policies separating admin vs. use, automatic rotation, alert on `ScheduleKeyDeletion`/`DisableKey`. See `kb/05-identity-crypto/cryptography.md`.
- Backups in a separate account with immutability (AWS Backup Vault Lock, Azure immutable vaults) against ransomware.

### Compute and metadata
- **IMDSv2** required on all EC2 (`HttpTokens=required`, `HttpPutResponseHopLimit=1` unless containers need 2); set account default and enforce with SCP condition `ec2:MetadataHttpTokens`. Azure IMDS and GCP metadata require the `Metadata: true` / `Metadata-Flavor: Google` header, which blocks simple SSRF but not header-controllable SSRF.
- Patch via SSM Patch Manager / Azure Update Manager / OS Config; golden images; no SSH keys baked in; SSM Session Manager / Azure Bastion / IAP instead of open 22/3389. See `kb/04-cloud-infra/os-hardening.md`.

### Network
- Private subnets for workloads and data; egress via NAT with filtering; no `0.0.0.0/0` on admin ports.
- Private endpoints (VPC endpoints/PrivateLink, Azure Private Link, GCP Private Service Connect) for storage, KMS and secrets; endpoint policies restricting to your org (`aws:PrincipalOrgID`, `aws:ResourceOrgID`).
- WAF in front of public apps; VPC Flow Logs enabled. See `kb/02-network/network-security.md`.

### Service equivalents
| Function | AWS | Azure | GCP |
|---|---|---|---|
| Org guardrails | Organizations SCPs/RCPs | Management groups + Azure Policy | Org Policy Service |
| Identity / SSO | IAM, IAM Identity Center | Entra ID, RBAC | Cloud IAM, Cloud Identity |
| Workload identity | Instance profiles, IRSA/EKS Pod Identity | Managed identities | Attached service accounts, Workload Identity Federation |
| Audit logs | CloudTrail | Activity Log, Entra logs | Cloud Audit Logs |
| Threat detection | GuardDuty | Defender for Cloud | Security Command Center |
| Posture / config | Security Hub, Config | Defender CSPM, Azure Policy | SCC, Asset Inventory |
| Keys | KMS, CloudHSM | Key Vault, Managed HSM | Cloud KMS, Cloud HSM |
| Secrets | Secrets Manager | Key Vault | Secret Manager |
| Private access | VPC endpoints / PrivateLink | Private Link / Private Endpoints | Private Service Connect |
| Firewall rules | Security groups, NACLs | NSGs | VPC firewall rules |
| Storage public block | S3 Block Public Access | `allowBlobPublicAccess=false` | Public access prevention |

Containers, Kubernetes and IaC scanning: `kb/04-cloud-infra/containers-kubernetes-iac.md`. Secrets handling: `kb/05-identity-crypto/secrets-management.md`.

## How to verify
- CSPM scans: `prowler aws` (also `prowler azure`, `prowler gcp`; `--compliance cis_3.0_aws` style frameworks), `scout suite` (`scout aws`, `scout azure --cli`, `scout gcp --user-account`), CIS benchmark scans, IAM Access Analyzer, review public resources. IaC: `checkov -d .`, `trivy config .`.
- AWS CLI checks:
  ```bash
  aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'   # must be 0 (root keys)
  aws iam generate-credential-report && aws iam get-credential-report --query Content --output text | base64 -d
  aws s3control get-public-access-block --account-id <ACCOUNT_ID>
  aws ec2 describe-instances --query 'Reservations[].Instances[?MetadataOptions.HttpTokens!=`required`].InstanceId'
  aws cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail,LogFileValidationEnabled]'
  aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0 --query 'SecurityGroups[].GroupId'
  aws accessanalyzer list-findings --analyzer-arn <ANALYZER_ARN>
  ```
- Azure: `az storage account list --query "[].{n:name,public:allowBlobPublicAccess}"`, `az policy state summarize`.
- GCP: `gcloud asset search-all-iam-policies --scope=organizations/<ORG_ID> --query="policy:allUsers"`, `gcloud iam service-accounts keys list --iam-account=<SA>`.
- Detection test: confirm alerts fire for a simulated root login or a `StopLogging` attempt in a sandbox account.

## References
- AWS Shared Responsibility Model: https://aws.amazon.com/compliance/shared-responsibility-model/
- AWS Security Reference Architecture and IMDSv2 docs (docs.aws.amazon.com) · Microsoft cloud security benchmark (learn.microsoft.com) · Google Cloud security foundations / best practices (cloud.google.com)
- CIS Benchmarks (AWS, Azure, GCP Foundations): https://www.cisecurity.org/cis-benchmarks
- NIST SP 800-210 (General Access Control Guidance for Cloud Systems), NIST SP 800-144 (Security and Privacy in Public Cloud Computing)
- CISA Secure Cloud Business Applications (SCuBA) and Cloud Security Technical Reference Architecture
- Prowler: https://github.com/prowler-cloud/prowler · ScoutSuite: https://github.com/nccgroup/ScoutSuite
- See also `kb/04-cloud-infra/containers-kubernetes-iac.md`, `kb/05-identity-crypto/identity-access.md`
