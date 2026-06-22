# 16 — Operatorul satelit `provenance-enforcer`

## §16.1 Analogie: vama financiară independentă

Două instituții supraveghează importul: vama propriu-zisă (verifică
documente comerciale, taxe) și vama financiară (verifică originea fondurilor,
spălare de bani). Sunt instituții *separate*, cu **propriile RBAC-uri**.
Niciuna nu poate emite singură decizia finală — un import e admis doar
dacă **ambele** au pus ștampila.

`zta-operator` e vama; `provenance-enforcer` e vama financiară. Operatorii
*nu se apelează unul pe altul*. Comunică **exclusiv prin câmpul
`status.trustLevel`** al CR-ului ZTA. Acest design e numit
**publish/subscribe via CRD status** și e idiom standard în Kubernetes
multi-operator systems.

## §16.2 Arhitectura

```
                ZeroTrustApplication CR
                          │
            ┌─────────────┴─────────────┐
            │                           │
            ▼                           ▼
    zta-operator                provenance-enforcer
    (write spec)                (read spec)
    (read status)               (write status.trustLevel)
    (write status.*)            (write status.provenance.*)
    (block deploy if            (verify VBBI voucher
     trustLevel != Verified)     independently)
            │                           │
            ▼                           ▼
    Deployments, Services,      Read OCI attestations
    NetworkPolicies, etc.       Verify HMAC chain
                                Verify Merkle root
```

Două operatori, două namespace-uri de execuție diferite, două
ServiceAccount-uri diferite. RBAC-ul fiecăruia e descris în
`00-arhitectura-de-ansamblu.md` §0.4.

## §16.3 Punctele de intrare

```python
# provenance-enforcer/src/provenance_enforcer/operator.py:32-48
@kopf.on.create(GROUP, "v1", PLURAL)
@kopf.on.field(GROUP, "v1", PLURAL, field="spec")
def reconcile_provenance(spec: dict, name: str, namespace: str, body: dict, **_: Any) -> None:
    # keep the entrypoint thin and forward to the service layer.
    api_client = client.ApiClient()
    custom = client.CustomObjectsApi(api_client)
    reconcile_application(custom, namespace, name, body)


@kopf.on.create(GROUP, "v1", SCA_PLURAL)
@kopf.on.field(GROUP, "v1", SCA_PLURAL, field="spec")
def reconcile_policy_change(body: dict, **_: Any) -> None:
    # reevaluate applications when the policy changes.
    api_client = client.ApiClient()
    custom = client.CustomObjectsApi(api_client)
    reconcile_policy_change_service(custom, body)
```

Doi watchers:
1. **Pe ZTA** — verifică provenance când se aplică/modifică un ZTA.
2. **Pe SCA** — re-evaluează **toate** ZTA-urile când o politică SCA se
   schimbă. Permite tightening retroactiv ("acum cerem SLSA L4; re-evaluez
   toate aplicațiile existente").

## §16.4 Setup kopf (mirror la zta-operator)

```python
# provenance-enforcer/operator.py:15-29
@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_: Any) -> None:
    # Isolate kopf bookkeeping from other operators (e.g. zta-operator) that
    # reconcile the same ZeroTrustApplication CR. Without distinct prefixes,
    # the default StatusProgressStorage + last-handled annotation collide,
    # producing "Patching failed with inconsistencies" and reconcile loops.
    settings.persistence.finalizer = "provenance-enforcer.devsecops.licenta.ro/finalizer"
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(
        prefix="provenance-enforcer.devsecops.licenta.ro",
    )
    settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix="provenance-enforcer.devsecops.licenta.ro",
        key="last-handled-configuration",
    )
    load_kubernetes_config()
```

Prefixe distincte pentru kopf bookkeeping — vezi §8.3 pentru explicația
incidentului rezolvat.

## §16.5 Reconcile per aplicație

```python
# provenance-enforcer/services/reconcile.py:29-49
def reconcile_application(custom: client.CustomObjectsApi, namespace: str, name: str, body: dict[str, Any]) -> None:
    image = str(((body.get("spec", {}) or {}).get("image", "")) or "").strip()
    try:
        evaluate_application(custom, body)
    except ProvenanceVerificationError as exc:
        logger.warning(
            "Provenance verification failed %s",
            format_context(**log_context(namespace=namespace, name=name, image=image), error=str(exc)),
        )
        set_failure_status(custom, namespace, name, PLURAL, str(exc))
    except ApiException as exc:
        reason = f"Kubernetes API error while reconciling provenance: status={exc.status} reason={exc.reason}"
        logger.exception("%s %s", reason, format_context(...))
        set_failure_status(custom, namespace, name, PLURAL, reason)
        raise kopf.TemporaryError(reason, delay=30) from exc
    except Exception as exc:
        reason = f"Unexpected provenance verification error: {type(exc).__name__}: {exc}"
        logger.exception("%s %s", reason, format_context(...))
        set_failure_status(custom, namespace, name, PLURAL, reason)
        raise kopf.TemporaryError(reason, delay=30) from exc
```

Pattern „handler thin → service":
- `reconcile_application` doar dispecerizează către `evaluate_application`
  și gestionează excepțiile.
- Trei categorii: `ProvenanceVerificationError` (verdict negativ),
  `ApiException` (K8s problem, retry), `Exception` (catch-all, retry).
- Toate scriu `set_failure_status` → `trustLevel=UntrustedProvenance` cu
  `reason` populat.

## §16.6 `evaluate_application` — flow-ul de validare

În `services/evaluation.py` (lungime mare, sumar conceptual):

```
1. Resolve SCA policy (același mecanism ca în zta-operator)
2. Dacă policy.provenance.requireVoucher == false → exit fără validare
3. Fetch VBBI attestation:
     cosign verify-attestation --type https://devsecops.licenta.ro/VBBI/v1
4. Validează policy:
     - SLSA level >= minSlsaLevel
     - build_context.repository ∈ trustedRepositories
     - subject == imaginea curentă
5. Verifică lanțul HMAC:
     for step in hmac_chain.steps:
         expected = HMAC(secret, metadata_hash || previous_hmac)
         assert step.hmac_result == expected
6. Verifică Merkle root (negociere de versiune):
     leaves = [step.hmac_result for step in steps]
     # version >= 2 sau algorithm == "rfc6962-sha256" → RFC 6962 (domain-separated);
     # altfel (legacy/version 1) → SHA-256 plain prin concatenare.
     root = compute_merkle_root(leaves, rfc6962=(version>=2 or alg=="rfc6962-sha256"))
     assert root == merkle_tree.root_hash
7. Dacă toate trec:
     patch_status(trustLevel=Verified, provenance.verifiedAt=now,
                  provenance.hmacChain.verified=true,
                  provenance.merkle={verified:true, computedRoot, leafCount,
                                     merkleVersion, merkleAlgorithm}, ...)
   Altfel:
     raise ProvenanceVerificationError(reason)
```

Codul real e split între `services/evaluation.py` și `voucher.py` (logica
criptografică). Acest doc nu intră în detaliu pe HMAC/Merkle Python — e
oglindire fidelă a `04-pipeline-vbbi-voucher.md` (același algoritm aplicat
invers).

## §16.7 Comunicarea: scriere pe `status`

```python
# provenance-enforcer/k8s/status.py:10-49
def patch_status(custom: client.CustomObjectsApi, namespace: str, name: str, plural: str, patch: dict[str, Any]) -> None:
    custom.patch_namespaced_custom_object_status(
        group=GROUP,
        version="v1",
        namespace=namespace,
        plural=plural,
        name=name,
        body={"status": patch},
    )


def default_provenance_state(required: bool) -> dict[str, Any]:
    return {
        "required": required,
        "verifiedAt": None,
        "attestationType": "https://devsecops.licenta.ro/VBBI/v1",
        "hmacMode": VBBI_HMAC_MODE,
    }


def set_failure_status(
    custom: client.CustomObjectsApi,
    namespace: str,
    name: str,
    plural: str,
    reason: str,
    provenance_patch: dict[str, Any] | None = None,
) -> None:
    patch = {
        "trustLevel": TRUST_UNTRUSTED_PROVENANCE,
        "lastError": reason,
        "provenance": {
            **default_provenance_state(True),
            "verifiedAt": None,
            "reason": reason,
        },
    }
    if provenance_patch:
        patch["provenance"].update(provenance_patch)
    patch_status(custom, namespace, name, plural, patch)
```

Două câmpuri scrise:

| Câmp | Valori | Citit de |
|---|---|---|
| `status.trustLevel` | `Untrusted` / `Verified` / `UntrustedProvenance` | `zta-operator` (poarta de provenance §9.4) |
| `status.provenance` | `{required, verifiedAt, hmacChain, merkle, voucher, reason}` | UI (`ReconcileFlow` stage 2 substeps) + `zta-operator` (idempotency check) |

**Observație importantă**: enforcer-ul scrie și `status.lastError`. Acest
câmp e folosit de zta-operator pentru afișare în UI. Două operatori care
scriu pe același câmp — gestionat prin disciplina: ultimul writer câștigă,
ZTA-operator nu suprascrie `lastError` dacă `trustLevel == UntrustedProvenance`.

## §16.8 Cum se trezește `zta-operator`

```python
# zta-operator/src/zta_operator/operator.py:818-819
@kopf.on.field(GROUP, VERSION, PLURAL, field="status.trustLevel")
async def reconcile_on_trust_level(
```

Watcher kopf pe câmpul `status.trustLevel`. Când enforcer-ul scrie noua
valoare, `zta-operator` se re-aprinde automat. Verifică `trust_level` din
`current_status`:

- `Verified` → continuă cu cosign/trivy/...
- `UntrustedProvenance` → `phase=Pending` cu `lastError = provenance.reason`
- `Untrusted` (default) → `phase=Pending` așteptând enforcer-ul

Acest mecanism elimină necesitatea unui mesaj direct între operatori (no
RPC, no shared bus). Statele tranzitorii sunt vizibile în CR-ul însuși →
auditabile prin `kubectl get zta -o yaml`.

## §16.9 Re-evaluare pe policy change

```python
# provenance-enforcer/services/reconcile.py:52-69 (selecție)
def reconcile_policy_change(custom: client.CustomObjectsApi, body: dict[str, Any], version: str = "v1") -> None:
    policy_name = str(((body.get("metadata", {}) or {}).get("name", "")) or "")
    logger.info("Reconciling policy change %s", format_context(policy=policy_name))

    ztas = custom.list_cluster_custom_object(group=GROUP, version=version, plural=PLURAL).get("items", []) or []
    for item in ztas:
        metadata = item.get("metadata", {}) or {}
        namespace = str(metadata.get("namespace", ""))
        name = str(metadata.get("name", ""))
        labels = metadata.get("labels", {}) or {}
        image = str((((item.get("spec", {}) or {}).get("image", "")) or "")).strip()

        if not policy_targets_zta(body, namespace=namespace, app_name=name, labels=labels, app_spec=(item.get("spec", {}) or {})):
            continue

        try:
            evaluate_application(custom, item)
        ...
```

Listează toate ZTA-urile cluster-wide, filtrează cele care folosesc
SCA-ul modificat, re-evaluează fiecare. Costul: O(N_ztas × cosign_time)
per policy change. Acceptabil pentru cluster-uri cu < 1000 ZTA-uri.

## §16.10 Configurarea HMAC mode (`VBBI_HMAC_MODE`)

Enforcer-ul suportă două moduri (oglindire la pipeline-ul VBBI):

- `shared-secret` — citește cheia HMAC dintr-un secret K8s
  (`provenance-enforcer-hmac-key`).
- `vault-transit` — apelează Vault Transit pentru fiecare HMAC step.

Detalii config: `provenance-enforcer/config.py`. Important: cheia nu trebuie
să fie aceeași cu cea folosită de pipeline — *cheia trebuie să fie aceeași
secret* (pentru shared-secret) sau **același key name** în Vault Transit
(pentru vault-transit).

## §16.11 Ce vede UI-ul

Backend serializează `status.provenance.*` ca `summary.merkle`,
`summary.voucher`, `summary.provenanceVerifiedAt`. Frontend (ReconcileFlow
stage 2) afișează:

- **Voucher substep** — `provenance.verifiedAt` set → success.
- **HMAC substep** — `provenance.hmacChain.verified=true` → success.
- **Merkle substep** — `provenance.merkle.verified=true` → success.

Dacă enforcer-ul respinge, oricare substep devine `failed` cu `reason`
populat.

## §16.12 Ce urmează

Următorul fișier acoperă observabilitatea: cum se compune
`status.verifications`, `status.errors`, evenimentele kopf, log-urile
structurate. Vezi `17-error-taxonomy-and-observability.md`.
