#!/usr/bin/env bash
# Runs Trivy config (if installed) and the deterministic KSV/Kubescape manifest audit comparator
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if command -v trivy >/dev/null 2>&1; then
  trivy config manifests/vulnerable/ > reports/trivy_vulnerable.txt || true
  trivy config manifests/hardened/ > reports/trivy_hardened.txt || true
fi

python3 scripts/audit_k8s.py
