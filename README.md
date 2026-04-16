# ZTA Operator (Kopf/Python)

Operator custom pentru `ZeroTrustApplication` cu:
- Supply-chain validation condus de `SupplyChainAttestation` (Cosign keyless + Trivy)
- Workload hardening
- Istio AuthorizationPolicy + WasmPlugin
- NetworkPolicy
- Falco custom rules
- Falco Talon integration prin patch pe ConfigMap (`falco-talon-rules` / `rules.yaml`)
- ZeroTrustSecret lifecycle cu `applicationRef` si `requireVerifiedStatus` (Vault + ESO delegation + mutating injection + rolling restart)
- SupplyChainAttestation ca policy centrala (SBOM + provenance + vulnerability policy + continuous compliance)

## Structură

- `src/zta_operator/operator.py` — reconcile loop + status management
- `src/zta_operator/supply_chain.py` — verificări GHCR/Cosign/Trivy
- `src/zta_operator/resources.py` — manifest builders și apply logic
- `src/zta_operator/talon.py` — patch/add/remove reguli Talon în ConfigMap
- `src/zta_operator/zerotrust_secret.py` — controller pentru CRD ZeroTrustSecret
- `deploy/crd/` — CRD
- `deploy/rbac/` — SA/ClusterRole/Binding
- `deploy/operator/` — deployment operator
- `helm/zta-operator/` — Helm chart complet (CRD + RBAC + Deployment)
- `.github/workflows/zta-operator-ci.yaml` — CI cu helm lint/template + build/push imagine GHCR + push chart Helm OCI în GHCR

## Decizii tehnice aplicate

- Registry permis: doar `ghcr.io`
- Tag `latest` interzis
- `ZeroTrustApplication.spec.securityPolicyRef.name` este referinta explicita catre politica
- `ZeroTrustSecret.spec.applicationRef.name` este referinta explicita catre aplicatie pentru trust gating
- `SupplyChainAttestation.spec.sourceValidation.trustedIssuers` este sursa de adevar pentru identitatile Cosign
- `SupplyChainAttestation.spec.vulnerabilityPolicy` este sursa de adevar pentru pragurile Trivy
- `runtimeEnforcement.onVulnerabilityFound` decide intre `Alert` si `Kill` cand scanarea Trivy gaseste probleme peste prag
- `ZeroTrustApplication` nu mai expune campuri locale de supply-chain; politica este definita exclusiv in `SupplyChainAttestation`
- `WasmPlugin`: `extensions.istio.io/v1alpha1`
- Talon fără CRD: integrare exclusiv ConfigMap patch

## Cerință runtime critică

Operatorul execută `cosign verify` și `trivy image` în reconciliere.
Imaginea operatorului trebuie să conțină binarele `cosign` și `trivy`.
`Dockerfile` din acest folder le instalează explicit.

## Rulare locală (dev)

1. Instalează dependențe:

```bash
pip install -r requirements.txt
```

2. Rulează operatorul:

```bash
PYTHONPATH=src kopf run --all-namespaces -m zta_operator.operator
```

## Deploy în cluster

Aplică în ordine:

```bash
kubectl apply -f deploy/crd/zerotrustapplication-crd.yaml
kubectl apply -f deploy/crd/zerotrustsecret-crd.yaml
kubectl apply -f deploy/crd/supplychainattestation-crd.yaml
kubectl apply -f deploy/rbac/serviceaccount.yaml
kubectl apply -f deploy/rbac/clusterrole.yaml
kubectl apply -f deploy/rbac/clusterrolebinding.yaml
kubectl apply -f deploy/rbac/falco-talon-role.yaml
kubectl apply -f deploy/rbac/falco-talon-rolebinding.yaml
kubectl apply -f deploy/operator/deployment.yaml
```

Sample resources:

```bash
kubectl apply -f deploy/samples/zta-sample.yaml
kubectl apply -f deploy/samples/zts-sample.yaml
kubectl apply -f deploy/samples/sca-sample.yaml
```

## Deploy cu Helm (recomandat)

```bash
cd /home/sabinghosty19/Desktop/LICENTA/customCRD/zta-operator
helm upgrade --install zta-operator ./helm/zta-operator \
	--namespace devsecops-system \
	--create-namespace
```

Upgrade:

```bash
helm upgrade zta-operator ./helm/zta-operator -n devsecops-system
```

Validare locală chart:

```bash
helm lint ./helm/zta-operator
helm template zta-operator ./helm/zta-operator -n devsecops-system >/tmp/zta-operator.yaml
```
