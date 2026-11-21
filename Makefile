.PHONY: cluster-up deploy-vuln deploy-hardened audit cluster-down

cluster-up:
	kind create cluster --config cluster/kind-config.yaml

deploy-vuln:
	kubectl apply -f manifests/vulnerable/deployment.yaml

deploy-hardened:
	kubectl apply -f manifests/hardened/deployment.yaml

audit:
	bash -n scripts/audit_compare.sh
	bash -n scripts/simulate_attack.sh
	bash scripts/audit_compare.sh

cluster-down:
	kind delete cluster --name sec-hardening-lab
