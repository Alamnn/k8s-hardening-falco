# k8s-hardening-falco: Kubernetes Workload Hardening & Falco Runtime Security Lab

**Problem:** Misconfigured Kubernetes workloads running as `root` with `privileged: true`, `hostPath` mounts, auto-mounted ServiceAccount tokens bound to `cluster-admin`, and no `NetworkPolicy` allow trivial container escape and cluster takeover. This lab provides a 1-control-plane, 1-worker `kind` cluster config, compares `manifests/vulnerable/` vs. `manifests/hardened/` across 12 CIS/NSA-CISA/Trivy KSV security controls, and enforces runtime threat detection with custom **Falco** rules (`falco/custom_rules.yaml`).

## Before vs. After Static Audit Compliance Table (`reports/audit_comparison.md`)

| Metric | `manifests/vulnerable/` | `manifests/hardened/` | Improvement |
|---|---|---|---|
| **Controls Audited (Trivy KSV / Kubescape)** | 12 | 12 | — |
| **Failed Controls** | **12 / 12** (4 CRITICAL, 7 HIGH, 1 MEDIUM) | **0 / 12** | **-12 misconfigurations** |
| **Compliance Score** | **0.0%** | **100.0%** | **+100.0%** |

| Control ID | Severity | Vulnerable (`payments-vuln`) | Hardened (`payments-hardened`) | Remediation Applied |
|---|---|---|---|---|
| `KSV001` | **CRITICAL** | `FAIL` (`allowPrivilegeEscalation: true`) | **`PASS`** | `allowPrivilegeEscalation: false` |
| `KSV005` | **CRITICAL** | `FAIL` (`privileged: true`) | **`PASS`** | `privileged: false` |
| `KSV006` | **CRITICAL** | `FAIL` (`hostPath: /` mounted at `/host`) | **`PASS`** | Replaced `hostPath` with ephemeral `emptyDir` at `/tmp` |
| `KSV008` | **HIGH** | `FAIL` (`hostPID: true`) | **`PASS`** | `hostPID: false` |
| `KSV009` | **HIGH** | `FAIL` (`hostNetwork: true`) | **`PASS`** | `hostNetwork: false` |
| `KSV012` | **HIGH** | `FAIL` (`runAsUser: 0` / root) | **`PASS`** | `runAsNonRoot: true`, `runAsUser: 10001` |
| `KSV014` | **HIGH** | `FAIL` (`readOnlyRootFilesystem: false`) | **`PASS`** | `readOnlyRootFilesystem: true` |
| `KSV022` | **HIGH** | `FAIL` (default Linux capabilities kept) | **`PASS`** | `capabilities: { drop: ["ALL"] }` |
| `KSV030` | **MEDIUM** | `FAIL` (no Seccomp profile) | **`PASS`** | `seccompProfile: { type: RuntimeDefault }` |
| `KSV036` | **HIGH** | `FAIL` (`automountServiceAccountToken: true`) | **`PASS`** | Dedicated `payment-api-sa` with `automountServiceAccountToken: false` |
| `KSV041` | **CRITICAL** | `FAIL` (`ClusterRoleBinding` to `cluster-admin`) | **`PASS`** | Namespace-scoped `Role` (`get`/`list` on 1 ConfigMap only) |
| `KSV050` | **HIGH** | `FAIL` (no `NetworkPolicy`) | **`PASS`** | `default-deny-all` + `allow-gateway-to-payment-api` (`:8080` ingress, DNS `:53` egress) |

## Custom Falco Runtime Detection Rules (`falco/custom_rules.yaml`)

| Falco Rule Name | Priority | MITRE ATT&CK | Condition Summary |
|---|---|---|---|
| `K8s Interactive Shell Spawned in Container` | `WARNING` | `T1609` | `spawned_process and container and proc.name in (sh, bash, ash, zsh, dash)` |
| `K8s Container Read Sensitive Shadow File` | `CRITICAL` | `T1003.008` | `open_read and container and fd.name = /etc/shadow` |
| `K8s Unexpected Outbound Connection from Payment Pod` | `ERROR` | `T1071` | `outbound and container and k8s.pod.label.app = "payment-api" and not fd.dport = 53` |

## Visual Proof

![k8s-audit](docs/screenshots/01_k8s_audit.png)

## Quick Start & Makefile Usage

```bash
# Run static manifest security audit and populate reports/
make audit

# Optional: Launch kind cluster and deploy manifests
make cluster-up
make deploy-vuln
make deploy-hardened
```
