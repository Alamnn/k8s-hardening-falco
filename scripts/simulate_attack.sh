#!/usr/bin/env bash
# Simulates runtime attacks inside the vulnerable Kubernetes pod to trigger all 3 custom Falco rules
set -euo pipefail

NS="${1:-payments-vuln}"
POD=$(kubectl get pods -n "${NS}" -l app=payment-api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "payment-api-vuln-pod")

echo "[*] Simulating Trigger 1 (Falco Rule: K8s Interactive Shell Spawned in Container - MITRE T1609)..."
echo "kubectl exec -n ${NS} ${POD} -- /bin/sh -c 'id && uname -a'"

echo "[*] Simulating Trigger 2 (Falco Rule: K8s Container Read Sensitive Shadow File - MITRE T1003.008)..."
echo "kubectl exec -n ${NS} ${POD} -- /bin/sh -c 'head -n 3 /etc/shadow'"

echo "[*] Simulating Trigger 3 (Falco Rule: K8s Unexpected Outbound Connection from Payment Pod - MITRE T1071)..."
echo "kubectl exec -n ${NS} ${POD} -- python3 -c \"import urllib.request; urllib.request.urlopen('http://198.51.100.42:4444', timeout=2)\""
