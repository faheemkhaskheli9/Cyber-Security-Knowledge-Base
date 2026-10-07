# Containers, Kubernetes & Infrastructure as Code

## What
- **Containers** (Docker, containerd, Podman): processes isolated by Linux namespaces, cgroups, capabilities and seccomp. They share the host kernel, so a container is not a security boundary in the way a VM is.
- **Kubernetes**: orchestrator whose control plane (API server, etcd, scheduler, kubelet on each node) decides what runs where, with which identity and network reach.
- **Infrastructure as Code** (Terraform, CloudFormation, Helm, Pulumi): declarative definitions of cloud and cluster resources. A misconfiguration in code is replicated to every environment.

## Why it matters
- A single privileged pod, `docker.sock` mount or `hostPath: /` usually means full node compromise, then cluster compromise.
- Exposed API servers, kubelets and dashboards are scanned for continuously and abused for cryptomining and data theft.
- Overprivileged service accounts turn one compromised app into cluster-admin.
- Terraform state stores resource attributes (often secrets) in plaintext, and IaC mistakes (public buckets, `0.0.0.0/0` rules) ship at scale.

## Attacks
- **Container escape**: `--privileged`, `CAP_SYS_ADMIN`, host PID/network namespaces, writable `hostPath` mounts, `docker.sock` mounts, or kernel/runtime CVEs (e.g., runc CVE-2019-5736, "Leaky Vessels" CVE-2024-21626). Defense: restricted pod security, seccomp `RuntimeDefault`, patched runtime and kernel, gVisor/Kata for untrusted workloads.
- **Exposed control plane**: anonymous API server access, kubelet on 10250 with `--anonymous-auth=true`, public Kubernetes Dashboard, unauthenticated etcd (2379). Defense: private endpoints, authN on every component, firewall.
- **Overprivileged service accounts**: auto-mounted tokens with `create pods`, `get secrets`, wildcard verbs or `cluster-admin` bindings allow lateral movement. Defense: no automount, scoped Roles.
- **Secrets in images**: credentials baked into layers or `ENV` remain retrievable with `docker history` even after "deletion" in a later layer.
- **Malicious or vulnerable images**: typosquatted public images, unpinned `latest` tags swapped upstream.
- **Lateral movement** in flat pod networks; access to cloud metadata (169.254.169.254) to steal node IAM credentials.
- **IaC/state**: secrets read from state files in shared buckets; malicious modules/providers; drift introduced by manual console changes.
- Detection: Kubernetes audit logs (exec into pods, new ClusterRoleBindings, secret reads), Falco alerts. Offensive testing with tools such as `kube-hunter`/`peirates` is for authorized clusters only.

## Defenses

### Docker images
Minimal/distroless base images, pin by digest, non-root `USER`, multi-stage builds, `.dockerignore`, no secrets in image layers/ENV (use BuildKit secret mounts), scan with Trivy/Grype.
```dockerfile
# syntax=docker/dockerfile:1
FROM golang:1.23@sha256:<digest> AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=secret,id=netrc,target=/root/.netrc go mod download   # secret never stored in a layer
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
COPY --from=build /app /app
USER 65532:65532
ENTRYPOINT ["/app"]
```

### Docker runtime
```bash
docker run --read-only --tmpfs /tmp \
  --cap-drop=ALL --security-opt no-new-privileges:true \
  --user 65532:65532 --pids-limit 200 --memory 512m \
  image@sha256:<digest>
```
Never use `--privileged`, never mount `/var/run/docker.sock`, avoid `--net=host`/`--pid=host`. Consider rootless Docker/Podman and user namespace remapping.

### Kubernetes workloads
```yaml
apiVersion: v1
kind: Pod
metadata: { name: app, namespace: prod }
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: app
      image: registry.example.com/app@sha256:<digest>
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
      resources:
        limits: { cpu: "500m", memory: "256Mi" }
```
- **Pod Security Admission (restricted)** per namespace: `kubectl label ns prod pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest`.
- **RBAC least privilege**: namespaced `Role`s with explicit verbs/resources, no wildcards, no `cluster-admin` for apps or humans by default; disable default SA token automount; one SA per workload.
- **NetworkPolicies default-deny**, then allow specific flows (requires a CNI that enforces them, e.g., Calico, Cilium); block egress to the metadata endpoint.
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny, namespace: prod }
spec: { podSelector: {}, policyTypes: [Ingress, Egress] }
```
- **Secrets**: enable encryption at rest (`EncryptionConfiguration` with a KMS v2 provider), or use an external manager (External Secrets Operator, Vault, CSI Secrets Store); restrict `get/list secrets`.
- **Admission control** (Kyverno/OPA Gatekeeper): require digests, signed images, non-root, resource limits; deny `hostPath`, `privileged`, `hostNetwork`.
- **Image signing (cosign)** in CI; verify at admission (Kyverno `verifyImages`, Sigstore policy-controller).
- **Control plane**: no public API server/kubelet (private endpoint or IP allowlist), kubelet `--anonymous-auth=false` and `--authorization-mode=Webhook`, no Dashboard exposure, etcd with mTLS, audit logs shipped to SIEM.
- **Runtime detection (Falco)**: shell in container, writes to `/etc`, unexpected outbound connections, reads of SA tokens.
- Benchmarks: CIS Kubernetes Benchmark (`kube-bench`), managed-cluster equivalents (EKS/GKE/AKS).

### IaC (Terraform, CloudFormation, Helm)
- Scan in CI (Checkov, tfsec/Trivy, KICS) and block on high findings; policy as code (OPA/Conftest, Sentinel).
- Remote state encrypted + locked (e.g., S3 with SSE-KMS and versioning plus locking, or Terraform Cloud), access restricted to the pipeline role; no secrets in state/code (mark `sensitive = true`, fetch from a secrets manager at apply).
- Pin provider and module versions and commit `.terraform.lock.hcl`; peer review every plan; apply only from CI with OIDC credentials.
- Drift detection (scheduled `terraform plan -detailed-exitcode`) and alerts on console changes.

## How to verify
- `trivy image --severity HIGH,CRITICAL image@sha256:<digest>` · `grype image`.
- `docker history --no-trunc image` and `trivy image --scanners secret` to find secrets in layers.
- `docker inspect --format '{{.HostConfig.Privileged}} {{.HostConfig.CapAdd}} {{.Config.User}}' <ctr>`.
- `kube-bench run` · `kubectl auth can-i --list --as=system:serviceaccount:prod:default`.
- `kubectl get ns -L pod-security.kubernetes.io/enforce` · `kubectl get networkpolicy -A`.
- `kubectl get clusterrolebindings -o wide | grep cluster-admin`.
- `trivy k8s --report summary cluster` or Kubescape for cluster posture.
- `checkov -d .` · `trivy config .` · `kics scan -p .`.
- `cosign verify --certificate-identity <id> --certificate-oidc-issuer <issuer> image@sha256:<digest>`.
- From outside: confirm `curl -k https://<node>:10250/pods` is refused and the API server is not internet-reachable.

## References
- Kubernetes docs, Pod Security Standards: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Kubernetes docs, Security Checklist: https://kubernetes.io/docs/concepts/security/security-checklist/
- CIS Docker and Kubernetes Benchmarks: https://www.cisecurity.org/cis-benchmarks
- NSA/CISA Kubernetes Hardening Guide
- NIST SP 800-190 (Application Container Security Guide)
- OWASP Docker Security Cheat Sheet and Kubernetes Security Cheat Sheet: https://cheatsheetseries.owasp.org/
- CNCF Cloud Native Security Whitepaper · Falco: https://falco.org · Kyverno: https://kyverno.io · Sigstore: https://sigstore.dev
- See also `kb/04-cloud-infra/cloud-security.md`, `kb/06-secure-sdlc/cicd-security.md`, `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`, `kb/05-identity-crypto/secrets-management.md`
