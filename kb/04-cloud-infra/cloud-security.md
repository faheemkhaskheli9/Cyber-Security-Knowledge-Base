# Cloud Security (AWS / Azure / GCP)

**Shared responsibility**: provider secures the cloud; you secure what you put in it (IAM, data, config, workloads).

## Top risks
Public storage buckets, over-privileged IAM, exposed management ports (22/3389), leaked access keys, unencrypted data, no logging, metadata service SSRF (use IMDSv2), unpatched VMs, open security groups, missing MFA on root/admin.

## Baseline
- Root/owner account: MFA, no daily use, no access keys.
- IAM: least privilege, roles over long-lived keys, SSO, permission boundaries/SCPs, regular access reviews.
- Logging: CloudTrail/Activity Log/Audit Logs → central immutable store; GuardDuty/Defender/SCC enabled.
- Network: private subnets, security groups default-deny, no public DBs, VPC endpoints.
- Data: encrypt at rest (KMS/CMK) and in transit, block public access org-wide, backups + tested restore.
- Config: CSPM (Prowler, ScoutSuite, Steampipe, Checkov), CIS Benchmarks.
- Secrets: Secrets Manager / Key Vault / Secret Manager.

## Verify
`prowler aws`, `scout suite`, CIS benchmark scans, IAM Access Analyzer, review public resources.
