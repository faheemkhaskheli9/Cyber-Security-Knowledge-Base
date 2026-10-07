# Containers, Kubernetes & Infrastructure as Code

## Docker
Minimal/distroless base images, pin by digest, non-root `USER`, read-only FS, drop capabilities, no `--privileged`, never mount docker.sock, no secrets in image layers/ENV, scan with Trivy/Grype, multi-stage builds, `.dockerignore`.

## Kubernetes
RBAC least privilege, disable default SA token automount, Pod Security Standards (restricted), NetworkPolicies default-deny, secrets via external manager/KMS encryption, admission control (Kyverno/OPA Gatekeeper), no public API server/kubelet, audit logs, runtime detection (Falco), image signing (cosign), CIS Kubernetes Benchmark (`kube-bench`).

## IaC (Terraform, CloudFormation, Helm)
Scan in CI (Checkov, tfsec/Trivy, KICS), remote state encrypted + locked, no secrets in state/code, policy as code, peer review, drift detection.
