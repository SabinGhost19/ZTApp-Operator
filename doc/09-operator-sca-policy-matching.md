# 09 — Operator: SCA matching și poarta de provenance

## §9.1 Analogie: două chei pentru a deschide o ușă blindată

O ușă blindată are două încuietori, ținute de două persoane diferite. Niciuna
singură nu poate deschide. Doar când ambele sunt prezente simultan, ușa se
deschide. Acesta e principiul *separation of duties* aplicat la admiterea
unei aplicații în cluster:

- **Cheia 1** — `zta-operator` verifică SCA-ul (există? politica permite?
  imaginea respectă regulile?).
- **Cheia 2** — `provenance-enforcer` verifică VBBI voucher-ul (lanțul HMAC
  e valid? Merkle root match?).

Niciun operator singur nu poate aproba. Doar când ambele scriu în starea
ZTA-ului independent, aplicarea continuă.

## §9.2 Match: cum găsește operatorul SCA-ul potrivit

```python
# zta-operator/src/zta_operator/supply_chain_attestation.py:607-619
def _get_matching_policy(
    custom: client.CustomObjectsApi,
    namespace: str,
    app_name: str,
    labels: dict[str, str],
    app_spec: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    referenced_policy = _get_policy_by_reference(custom, app_spec)
    if referenced_policy is not None:
        return referenced_policy
    if _security_policy_ref_name(app_spec):
        return None
    raise SupplyChainPolicyError("ZeroTrustApplication.spec.securityPolicyRef.name is required")
```

Algoritmul:

1. **Dacă** ZTA-ul declară `spec.securityPolicyRef.name` și SCA-ul cu acel
   nume **există** → returnează SCA-ul.
2. **Dacă** numele e declarat dar SCA-ul **nu există încă** → returnează
   `None`. Această stare e tratată mai jos ca *missing*, nu ca eroare
   permanentă (retry pentru self-healing GitOps).
3. **Dacă** numele nu e declarat deloc → `raise SupplyChainPolicyError`
   (config invalid, eșec permanent).

**Observație importantă**: nu există *label-based selectors* sau alte forme
de matching. Match-ul este **exclusiv prin nume**, deterministic. Acest
design simplifică auditarea: pentru un ZTA dat, există exact un SCA candidat
(numele declarat), iar prezența/absența SCA-ului este o întrebare binară.

## §9.3 Politica efectivă

```python
# supply_chain_attestation.py:684-705
def resolve_effective_supply_chain_policy(policy: dict[str, Any] | None, app_spec: dict[str, Any]) -> dict[str, Any]:
    if not policy:
        raise SupplyChainPolicyError("ZeroTrustApplication.spec.securityPolicyRef must reference an existing SupplyChainAttestation")

    source_validation = ((policy or {}).get("spec", {}) or {}).get("sourceValidation", {}) or {}
    vulnerability_policy = ((policy or {}).get("spec", {}) or {}).get("vulnerabilityPolicy", {}) or {}
    runtime_enforcement = ((policy or {}).get("spec", {}) or {}).get("runtimeEnforcement", {}) or {}

    trusted_issuers = [
        str(item).strip()
        for item in (source_validation.get("trustedIssuers", []) or [])
        if str(item).strip()
    ]
    max_allowed = str(vulnerability_policy.get("maxAllowedSeverity", "")).strip() or "Medium"

    return {
        "requireSignature": bool(source_validation.get("enforceCosign", True)),
        "trustedIdentities": trusted_issuers,
        "maxAllowedSeverity": max_allowed,
        "failOnFixable": bool(vulnerability_policy.get("failOnFixable", False)),
        "onVulnerabilityFound": str(runtime_enforcement.get("onVulnerabilityFound", "Alert") or "Alert"),
    }
```

Această funcție extrage un *contract reduced* din SCA-ul complet — doar
câmpurile relevante pentru `verify_supply_chain`. Restul (sbomPolicy,
policyBinding, slsaProvenancePolicy, etc.) sunt citite separat în
`validate_admission_with_attestations`.

**Defensive defaults:**

- `enforceCosign` default `True` — dacă SCA-ul uită explicit câmpul, cosign
  e impus.
- `maxAllowedSeverity` default `Medium` — comportament conservator.
- `onVulnerabilityFound` default `Alert` — nu Kill. Un default mai puțin
  agresiv face SCA-uri minimale tractabile pentru dev.

## §9.4 Poarta de provenance

```python
# supply_chain_attestation.py:708-712
def requires_provenance_verification(policy: dict[str, Any] | None) -> bool:
    if not policy:
        return False
    provenance = ((policy.get("spec", {}) or {}).get("provenance", {}) or {})
    return bool(provenance.get("requireVoucher", False))
```

Determină dacă verificarea VBBI e obligatorie pe baza SCA-ului. Dacă da,
`zta-operator` **se oprește** și așteaptă:

```python
# operator.py:384-401
if requires_provenance_verification(matched_policy) and trust_level != "Verified":
    provenance_status = current_status.get("provenance", {}) or {}
    pending_message = "Waiting for provenance verification by Provenance-Enforcer"
    if trust_level == "UntrustedProvenance":
        pending_message = str(provenance_status.get("reason", "Provenance verification failed"))
    _status_patch(
        custom,
        namespace,
        name,
        {
            "phase": "Pending",
            "lastError": pending_message if trust_level == "UntrustedProvenance" else "",
            "securityState": current_status.get("securityState", "PendingProvenance"),
            "provenance": provenance_status,
        },
    )
    adapter.info("Waiting for provenance verification before provisioning", extra={"event": "provenance-pending"})
    return
```

Trei stări posibile:

| `trust_level` | Sursă | Acțiune `zta-operator` |
|---|---|---|
| `Untrusted` | default la creație | `phase=Pending`, return; așteaptă enforcer |
| `UntrustedProvenance` | enforcer a respins | `phase=Pending` cu mesaj din `provenance.reason`; return |
| `Verified` | enforcer a aprobat | continuă cu pașii următori (supply-chain) |

**Nu există timeout** pe această așteptare. Operatorul rămâne în `Pending`
indefinit dacă enforcer-ul nu emite vreodată un verdict. Justificare: un
verdict greșit (timeout → fail-open) ar fi mai periculos decât un workload
care nu se mai provisionează niciodată.

Re-trezirea operatorului: `@kopf.on.field(field="status.trustLevel")` din
`operator.py:818-819` (vezi §8.2) — fiecare scriere a enforcer-ului pe
`status.trustLevel` re-aprinde `_reconcile_impl`.

## §9.5 Diagnostic pentru SCA missing

Când SCA-ul lipsește (`_get_matching_policy` returnează `None`),
documentul colectează un *raport de diagnostic*:

```python
# supply_chain_attestation.py:651-670
def _collect_policy_match_diagnostics(
    custom: client.CustomObjectsApi,
    namespace: str,
    app_name: str,
    labels: dict[str, str],
    app_spec: dict[str, Any] | None = None,
) -> dict[str, Any]:
    items = custom.list_cluster_custom_object(group=GROUP, version=VERSION, plural=SCA_PLURAL).get("items", []) or []
    evaluations = [
        _explain_policy_target_match(item, namespace=namespace, app_name=app_name, labels=labels, app_spec=app_spec)
        for item in items
    ]
    return {
        "namespace": namespace,
        "appName": app_name,
        "labels": labels,
        "securityPolicyRef": _security_policy_ref_name(app_spec),
        "candidateCount": len(evaluations),
        "candidates": evaluations,
    }
```

Listează **toate** SCA-urile din cluster și explică pentru fiecare de ce nu
se potrivește (`_explain_policy_target_match` la linia 622). Acest payload
este scris în `status.policyMatchDebug` și consumat de UI pentru a oferi
mesaje de eroare utile ("SCA-ul `foo-policy` nu există; cele 3 SCA-uri
prezente sunt: ...").

## §9.6 Eroare temporară vs permanentă

```python
# operator.py:769-785 (catch handler)
except SupplyChainPolicyMissingError as exc:
    # Declarative recovery: SCA may be applied after ZTA (Helm/ArgoCD
    # don't guarantee order). Surface a Pending state and retry every
    # 15s so the system self-heals when the SCA appears.
    _status_patch(...)
    raise kopf.TemporaryError(str(exc), delay=15) from exc
```

`SupplyChainPolicyMissingError` se ridică în
`get_matching_policy_for_application` când SCA-ul declarat nu există. E
*tranzient*: Helm/ArgoCD nu garantează ordinea aplicării, deci SCA-ul poate
apărea ulterior. Retry la 15s permite auto-recovery.

Contrast: dacă `spec.securityPolicyRef.name` lipsește complet, se ridică
`SupplyChainPolicyError` (fără sufix `Missing`), care este `PermanentError`.

## §9.7 Ce urmează

Dacă SCA-ul există și `trust_level=Verified`, operatorul intră în faza de
supply-chain verification. Vezi `10-operator-cosign-trivy.md`.
