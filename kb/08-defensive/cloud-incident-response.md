# Cloud Incident Response

## What
Incident response for IaaS/PaaS accounts (AWS, Azure, Google Cloud) and the identities that control them. The NIST SP 800-61 lifecycle still applies (prepare, detect, analyze, contain, eradicate, recover, learn), but the evidence and the levers differ from on-premises IR:
- The **control plane is an API**: most attacks are authenticated API calls with stolen credentials, so the main evidence is the provider's audit log (AWS CloudTrail, Azure Activity Log and Microsoft Entra ID sign-in/audit logs, Google Cloud Audit Logs), not disk images.
- **Containment is identity work**: deactivate keys, revoke sessions and tokens, detach trust relationships, apply deny policies.
- **Resources are ephemeral**: an autoscaled instance or container may be gone before anyone looks; snapshots and log retention must be arranged in advance.
- **Shared responsibility**: the provider investigates its own infrastructure; you own your accounts, identities, configurations and workloads (`kb/04-cloud-infra/cloud-security.md`).

SaaS tenants (Microsoft 365, Google Workspace, Salesforce) follow the same principles; see `kb/04-cloud-infra/saas-security.md`. General IR process and roles are in `kb/08-defensive/soc-detection-ir.md`.

## Why it matters
- Leaked long-term access keys, stolen session tokens and over-permissive roles turn into full account compromise within minutes; attackers script reconnaissance and persistence.
- Without preparation the evidence does not exist: data-plane events (object reads, secret reads, function invocations) are usually not logged by default, and default retention windows are short (for example AWS CloudTrail Event history covers the last 90 days of management events; Google Cloud Data Access audit logs are off by default for most services).
- Impact is often financial and fast: crypto-mining across all regions, data theft from storage buckets, deleting backups, or encrypting objects with attacker-held keys for ransom.
- The responders' own access is a target: if the attacker holds an administrator role, they can watch, revert or lock out the response.

## Attacks
*Common attack paths, mapped to MITRE ATT&CK where an ID exists, with the main detection or defense.*

| Attack | How it works | Detection / defense |
|---|---|---|
| Leaked long-term keys (T1078.004) | Access keys in a public repo, container image, CI log or laptop are used from attacker infrastructure | Secret scanning (`kb/05-identity-crypto/secrets-management.md`); no long-term user keys, use SSO and workload identity federation; alert on key use from new ASNs or countries |
| Instance metadata credential theft (T1552.005) | SSRF or code execution on a workload reads role credentials from the metadata service and uses them elsewhere | IMDSv2 required; GuardDuty-style findings for instance credentials used outside the instance; least-privilege instance roles |
| Persistence with new credentials (T1098.001) | Attacker creates an IAM user, access key, login profile, service account key or app registration secret | Alert on `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `iam.serviceAccountKeys.create`, new credentials on Entra app registrations; block key creation by policy (SCP, Organization Policy) |
| Privilege escalation | `iam:PassRole` plus compute creation, policy version changes, role trust edits (`kb/04-cloud-infra/cloud-provider-baselines.md`) | Permission boundaries and SCPs; alert on policy and trust-policy changes; regular privilege path analysis |
| Disabling logging (T1562.008) | `StopLogging`, `DeleteTrail`, `PutEventSelectors`, deleting GuardDuty detectors, changing diagnostic settings or log sinks | Organization-level trail and sinks that member accounts cannot change; deny these actions by SCP/Policy except for a break-glass role; alert on any attempt, including failures |
| Resource hijacking (T1496) | Large or GPU instances launched in unused regions for mining | Deny unused regions by SCP/Organization Policy; quotas; billing anomaly alerts; alert on instance launches in new regions |
| Exfiltration to an attacker account (T1537) | Snapshots or images shared with an external account (`ModifySnapshotAttribute`), bucket policies opened, data copied out | Block public and cross-organization sharing by policy; alert on sharing changes and unusual egress; data events on sensitive buckets |
| Storage ransom and destruction (T1485, T1486) | Objects deleted or overwritten, backups removed, or objects re-encrypted with a customer-supplied key the victim does not hold | Object lock and versioning on critical buckets, backups in a separate account (`kb/08-defensive/ransomware-resilience.md`); restrict or block SSE-C where not needed; alert on mass deletes and encryption changes |
| Cloud admin command execution (T1651) | Attacker uses SSM Run Command, Azure Run Command or serial console to run code on VMs without network access | Restrict these permissions; log and alert on their use |
| Federation and identity provider abuse | Attacker adds an identity provider or federated domain, or edits an OIDC trust (for example a CI trust allowing any repository) | Alert on IdP and federation changes; scope CI trusts to repository and branch (`kb/06-secure-sdlc/cicd-security.md`) |

## Defenses

### 1. Prepare (before any incident)
- **Logging**: organization-wide audit logging into a separate log-archive account or project that workload admins cannot modify, with object lock or retention locks. Enable data events for sensitive buckets, secrets and keys; enable VPC/VNet flow logs and DNS query logs on important networks. Set retention to cover your detection gap plus investigation time (example: at least one year, longer if regulation requires).
- **Detection**: GuardDuty / Microsoft Defender for Cloud / Security Command Center (or a CNAPP) on in every account and region, findings sent to the SIEM (`kb/06-secure-sdlc/security-logging-and-monitoring.md`).
- **IR access**: pre-created responder roles (read-only investigation, and a separate containment role) reachable through break-glass accounts with phishing-resistant MFA that do not depend on the possibly compromised IdP. Test them quarterly.
- **Forensic account**: an isolated account/project with tooling where snapshots can be shared, mounted read-only and analyzed.
- **Inventory and tags**: owner and data classification tags so responders know what a resource is and whom to call.
- **Playbooks** for the common cases: leaked access key, compromised workload, compromised console user, logging disabled, public data exposure, ransom of storage.

### 2. Detect and analyze
- Identify the principal: access key ID, role session name, source IP, user agent; follow `AssumeRole` chains back to the original identity.
- Build the timeline from audit logs across all regions and accounts, starting from the first use of the credential, not from the alert.
- Typical first attacker calls: `sts:GetCallerIdentity`, listing IAM, buckets and secrets, `ec2:DescribeRegions`. Many `AccessDenied` errors in a short time suggest enumeration with a stolen credential.
- Scope: which other credentials could the attacker have read (secrets managers, environment variables, instance roles, CI variables)? Treat all of them as compromised.

### 3. Contain
Order matters: preserve evidence, then cut access in a way the attacker cannot undo.
- **AWS**: deactivate (do not yet delete) the access key: `aws iam update-access-key --user-name <user> --access-key-id <id> --status Inactive`. For roles, use "Revoke active sessions", which attaches a deny policy for sessions issued before the current time; temporary credentials otherwise stay valid until they expire. Attach a deny-all policy or a quarantine SCP to the affected principal or account if the scope is unclear.
- **Azure / Entra ID**: disable the user, revoke refresh tokens and sessions (`Revoke-MgUserSignInSession -UserId <id>`), reset credentials, remove attacker-added app credentials, consents and role assignments; consider Continuous Access Evaluation-aware apps for faster effect.
- **Google Cloud**: disable the service account key (`gcloud iam service-accounts keys disable <key-id> --iam-account <sa-email>`) or the service account, remove IAM bindings, and check Organization Policy for changes.
- **Workloads**: before stopping, snapshot disks and capture memory where possible; isolate with a security group or firewall rule that allows only the forensic host (note that existing tracked connections may survive a security group change on some platforms, so verify); remove the instance from load balancers and autoscaling so it is not replaced and destroyed.
- Check for attacker persistence everywhere before declaring containment: new users, keys, roles, trust policies, Lambda/Function triggers, scheduled jobs, IdP or federation changes, and resources in unused regions.

### 4. Eradicate and recover
- Rotate every credential in scope, including secrets the compromised principal could read, then delete the deactivated keys after evidence is captured.
- Rebuild workloads from known-good images and IaC rather than cleaning them (`kb/04-cloud-infra/containers-kubernetes-iac.md`).
- Restore data from backups in the separate account; verify integrity.
- Remove the root cause: the leaked key's source, the SSRF, the overbroad trust policy; add a preventive guardrail (SCP, policy, CI check) so the same path fails next time.
- If personal data or regulated systems were involved, run the notification process with legal (`kb/09-governance/grc-compliance-privacy.md`).

### Triage helper
Flag high-risk events in exported CloudTrail JSON (standard library; extend the list for your environment):

```python
import json

HIGH_RISK = {
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteDetector",
    "CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
    "AttachUserPolicy", "PutUserPolicy", "CreatePolicyVersion", "UpdateAssumeRolePolicy",
    "ModifySnapshotAttribute", "ModifyImageAttribute", "PutBucketPolicy", "DeleteBucketPolicy",
    "PutBucketPublicAccessBlock", "CreateOpenIDConnectProvider", "CreateSAMLProvider",
}

def triage(records: list[dict]) -> list[str]:
    hits = []
    for r in records:
        name = r.get("eventName", "")
        who = r.get("userIdentity", {}).get("arn", "?")
        no_mfa = name == "ConsoleLogin" and r.get("additionalEventData", {}).get("MFAUsed") == "No"
        if name in HIGH_RISK or no_mfa:
            status = r.get("errorCode", "ok")
            hits.append(f'{r.get("eventTime")} {r.get("awsRegion")} {name} by {who} from {r.get("sourceIPAddress")} [{status}]')
    return sorted(hits)

sample = json.loads("""{"Records": [
  {"eventTime": "2026-10-24T10:02:00Z", "awsRegion": "us-east-1", "eventName": "CreateAccessKey",
   "userIdentity": {"arn": "arn:aws:iam::111122223333:user/ci-deploy"}, "sourceIPAddress": "203.0.113.7"},
  {"eventTime": "2026-10-24T10:00:00Z", "awsRegion": "us-east-1", "eventName": "ListBuckets",
   "userIdentity": {"arn": "arn:aws:iam::111122223333:user/ci-deploy"}, "sourceIPAddress": "203.0.113.7"},
  {"eventTime": "2026-10-24T10:05:00Z", "awsRegion": "eu-west-1", "eventName": "StopLogging",
   "userIdentity": {"arn": "arn:aws:iam::111122223333:user/ci-deploy"}, "sourceIPAddress": "203.0.113.7",
   "errorCode": "AccessDenied"}
]}""")
for line in triage(sample["Records"]):
    print(line)
assert len(triage(sample["Records"])) == 2
```

## How to verify
- Confirm logging cannot be turned off from a member account: in a sandbox account, try `StopLogging` on the organization trail (or delete a log sink) as an account admin; it must be denied and alerted.
- Game day in a sandbox: plant a canary access key (`kb/08-defensive/deception-and-honeytokens.md`) or simulate a leaked key, then measure time to detect, time to deactivate and time to confirm no persistence.
- Run Stratus Red Team or similar cloud attack emulation in a dedicated test account (with approval) for credential creation, log tampering, snapshot sharing and IMDS credential use; each should raise an alert.
- Check that break-glass and responder roles work without the primary IdP, and that their use pages the security team.
- Check retention: query the log archive for an event older than your stated retention minimum; check data events are on for the sensitive buckets and secrets you listed.
- After each real or simulated incident, verify that every credential in scope was rotated and that a preventive guardrail was added.

## References
- NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- AWS Security Incident Response Guide: https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html
- AWS CloudTrail User Guide: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html
- Microsoft incident response playbooks: https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks
- Google Cloud Audit Logs overview: https://cloud.google.com/logging/docs/audit
- MITRE ATT&CK Cloud matrix (IaaS, Identity Provider, SaaS): https://attack.mitre.org/matrices/enterprise/cloud/
- MITRE ATT&CK T1562.008, Impair Defenses: Disable or Modify Cloud Logs: https://attack.mitre.org/techniques/T1562/008/
- Stratus Red Team (cloud attack emulation): https://github.com/DataDog/stratus-red-team
- CISA Untitled Goose Tool (Microsoft cloud evidence collection): https://github.com/cisagov/untitledgoosetool
- Invictus IR Microsoft-Extractor-Suite: https://github.com/invictus-ir/Microsoft-Extractor-Suite
- See also `kb/08-defensive/soc-detection-ir.md`, `kb/04-cloud-infra/cloud-security.md`, `kb/04-cloud-infra/cloud-provider-baselines.md`, `kb/04-cloud-infra/serverless-security.md`, `kb/08-defensive/dfir-malware-threat-intel.md`, `kb/05-identity-crypto/secrets-management.md`
