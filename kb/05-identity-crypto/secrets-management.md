# Secrets Management

## What
Handling credentials that grant access (API keys, database passwords, cloud keys, tokens, private keys, signing keys) across their lifecycle: creation, storage, distribution to workloads, rotation, revocation and leak detection.

## Why it matters
- Leaked secrets in public repos are found and abused within minutes by automated scanners.
- A single long-lived cloud key or CI token can grant production access (see Codecov, `tj-actions/changed-files` in `kb/06-secure-sdlc/cicd-security.md`).
- Secrets persist in git history, container layers, logs, crash dumps and Terraform state long after they are "deleted".

## Attacks
- Scraping public and leaked private repos, gists, package tarballs and images for keys.
- Reading secrets from CI logs, build artifacts, `.env` files served by misconfigured web servers, or `docker history`.
- Infostealer malware harvesting developer machines (`~/.aws/credentials`, browser sessions, `.npmrc`).
- Abusing overly broad keys (one key for all environments) for lateral movement.
- Reading Kubernetes Secrets (base64, not encryption) via overbroad RBAC.
- Detection: secret scanning, cloud audit logs (unusual API calls, new regions), canary tokens.

## Defenses

### Core rules
- Never commit secrets; use env vars injected at runtime or a vault (HashiCorp Vault, AWS/GCP/Azure secret managers, SOPS, Doppler, 1Password CLI). Prefer mounted files or SDK fetch over env vars where possible (env vars leak into child processes and crash dumps).
- Prefer short-lived credentials (OIDC federation for CI, IAM roles, workload identity).
- Separate secrets per environment; least-privilege scoped keys; `.env` in `.gitignore`; provide `.env.example` only.
- Never print, log or echo secrets; mask them in CI; redact in error trackers.
- Rotate on a schedule and automatically where supported; every secret has an owner and an expiry.

### Tooling comparison
| Tool | Best for | Notes |
|------|----------|-------|
| HashiCorp Vault / OpenBao | Multi-cloud, dynamic secrets, PKI | Self-hosted ops burden; strong policy model |
| AWS Secrets Manager / SSM Parameter Store | AWS workloads | Native rotation (Lambda), IAM policies |
| GCP Secret Manager | GCP workloads | IAM per secret, versioning |
| Azure Key Vault | Azure workloads | Keys, secrets, certs; RBAC + managed identity |
| SOPS (+ age/KMS) | Encrypted secrets in git (GitOps) | Values encrypted, keys visible for diffs |
| Doppler / 1Password CLI / Infisical | Developer and small-team secret sync | SaaS trust; easy local injection (`op run`, `doppler run`) |
| Kubernetes External Secrets Operator / CSI Secrets Store | Syncing the above into pods | Still encrypt etcd at rest |

### Dynamic secrets (Vault database engine)
Credentials are generated per request with a TTL and revoked automatically.
```bash
vault secrets enable database
vault write database/config/appdb plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@db.internal:5432/app?sslmode=verify-full" \
  allowed_roles="app-ro" username="vault_admin" password="$VAULT_DB_ADMIN_PASSWORD"
vault write database/roles/app-ro db_name=appdb default_ttl=1h max_ttl=4h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
vault read database/creds/app-ro   # returns a unique, expiring username/password
```
Rotate the root credential after setup (`vault write -f database/rotate-root/appdb`). Authenticate apps with Kubernetes/cloud IAM auth methods, not static tokens.

### CI OIDC instead of stored keys
```yaml
permissions: { id-token: write, contents: read }
steps:
  - uses: aws-actions/configure-aws-credentials@<sha> # pin to commit SHA
    with:
      role-to-assume: arn:aws:iam::111122223333:role/deploy-prod
      aws-region: eu-west-1
```
Scope the cloud trust policy `sub` claim to the repo and branch/environment (e.g., `repo:org/app:environment:prod`). See `kb/06-secure-sdlc/cicd-security.md`.

### Pre-commit and CI scanning
- Scan: `gitleaks`, `trufflehog`, GitHub secret scanning + push protection, pre-commit hook.
- Copy `templates/pre-commit-config.yaml` (gitleaks + `detect-private-key`) to `.pre-commit-config.yaml`, then `pre-commit install`; run `pre-commit run --all-files` once.
- Add `templates/gitleaks.yml` as a GitHub workflow for server-side enforcement (hooks can be skipped locally).
- Keep an allowlist (`.gitleaks.toml`) for test fixtures rather than disabling rules.

### Leak-response runbook
**If leaked**: revoke/rotate immediately → check logs for misuse → remove from code → (optionally) purge history. Rotation is mandatory; history purge is not enough.
1. **Contain**: revoke or rotate the secret at the issuer now (cloud console, provider dashboard, Vault lease revoke). Assume it is compromised the moment it was public.
2. **Deploy** the new secret from the vault; confirm services are healthy.
3. **Investigate**: review provider/cloud audit logs (e.g., CloudTrail) from the first commit time onward for use from unknown IPs, new resources, data access.
4. **Remove** from code and config; move to the secret manager.
5. **History** (optional, needs confirmation as it is destructive): `git filter-repo` or BFG, force-push, ask GitHub support to purge cached views; forks and clones keep copies, which is why step 1 is mandatory.
6. **Prevent**: add the pattern to scanning, enable push protection, write a short post-incident note.

### Detection: canary tokens
- Plant decoy credentials (e.g., Thinkst Canarytokens AWS keys, fake DB passwords in config) in repos, wikis and servers; any use alerts you of a breach or leak.
- Alert on cloud API calls by keys tagged as canaries and on secret reads from unusual principals.

## How to verify
- `gitleaks detect --source . --log-opts="--all"` (full history) · `trufflehog git file://. --only-verified`.
- `git check-ignore .env` returns `.env`; `git ls-files | grep -E '\.env$|\.pem$|id_rsa'` returns nothing.
- `docker history --no-trunc <image>` and `trivy image --scanners secret <image>`.
- CI: no long-lived cloud keys in repository/org secrets once OIDC is in place; GitHub secret scanning and push protection enabled.
- Vault: `vault list sys/leases/lookup/database/creds/app-ro` shows short TTLs; audit device enabled.
- Inventory: every secret has an owner, scope, environment and last-rotated date.

## References
- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- NIST SP 800-57 Part 1 (key management)
- HashiCorp Vault database secrets engine: https://developer.hashicorp.com/vault/docs/secrets/databases
- GitHub docs: secret scanning and push protection; "Configuring OpenID Connect in cloud providers"
- Gitleaks: https://github.com/gitleaks/gitleaks · TruffleHog: https://github.com/trufflesecurity/trufflehog · SOPS: https://github.com/getsops/sops
- Canarytokens: https://canarytokens.org
- See also `kb/06-secure-sdlc/cicd-security.md`, `kb/05-identity-crypto/cryptography.md`, `kb/04-cloud-infra/containers-kubernetes-iac.md`, `templates/pre-commit-config.yaml`, `templates/gitleaks.yml`
