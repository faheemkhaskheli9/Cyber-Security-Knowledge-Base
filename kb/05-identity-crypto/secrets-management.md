# Secrets Management

- Never commit secrets; use env vars injected at runtime or a vault (HashiCorp Vault, AWS/GCP/Azure secret managers, SOPS, Doppler, 1Password CLI).
- Scan: `gitleaks`, `trufflehog`, GitHub secret scanning + push protection, pre-commit hook.
- **If leaked**: revoke/rotate immediately → check logs for misuse → remove from code → (optionally) purge history. Rotation is mandatory; history purge is not enough.
- Prefer short-lived credentials (OIDC federation for CI, IAM roles, workload identity).
- Separate secrets per environment; least-privilege scoped keys; `.env` in `.gitignore`; provide `.env.example` only.
