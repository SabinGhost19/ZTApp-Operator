# 08 — Operator: reconcile lifecycle

## §8.1 Analogie: triajul unui pacient la camera de gardă

Un pacient ajunge la urgență. Înainte de tratament, asistenta face un
**triaj**: măsoară parametrii vitali, verifică actele, citește dosarul (dacă
există), decide ordinea în care urmează examinările (cardiolog vs. ortoped
vs. neurolog). Nu toți pacienții parcurg toate examinările; ordinea depinde
de starea curentă.

Operatorul face același triaj atunci când `kopf` îl trezește: identifică
faza curentă a ZTA-ului, verifică dacă spec-ul s-a schimbat de la ultima
reconciliere, decide ce pași sunt necesari. Operatorul nu rulează toate
verificările de fiecare dată — multe sunt sărite via *idempotency*.

## §8.2 Punctele de intrare kopf

```python
# zta-operator/src/zta_operator/operator.py:808-819
@kopf.on.create(GROUP, VERSION, PLURAL)
async def reconcile_on_create(spec: dict, name: str, namespace: str, body: dict, patch: dict, **kwargs: Any) -> None:
    await _reconcile_impl(spec=spec, name=name, namespace=namespace, body=body, patch=patch, **kwargs)


@kopf.on.field(GROUP, VERSION, PLURAL, field="spec")
async def reconcile_on_spec(spec: dict, name: str, namespace: str, body: dict, patch: dict, **kwargs: Any) -> None:
    await _reconcile_impl(spec=spec, name=name, namespace=namespace, body=body, patch=patch, **kwargs)


@kopf.on.field(GROUP, VERSION, PLURAL, field="status.trustLevel")
async def reconcile_on_trust_level(
```

Trei trigger-e diferite, toate apelează aceeași implementare:

1. **`@kopf.on.create`** — un ZTA nou aplicat.
2. **`@kopf.on.field(field="spec")`** — orice modificare în `spec`.
3. **`@kopf.on.field(field="status.trustLevel")`** — modificare scrisă de
   `provenance-enforcer` (vezi `16-provenance-enforcer.md`).

Acest design **multi-trigger către aceeași logică** elimină race conditions:
indiferent ce a actualizat CR-ul, reconcile-ul rulează cu starea finală
post-update.

## §8.3 Setup kopf — separation de la provenance-enforcer

```python
# operator.py:258-272
@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_: Any) -> None:
    # Isolate kopf bookkeeping from other operators (e.g. provenance-enforcer)
    # that reconcile the same ZeroTrustApplication CR. Without distinct
    # prefixes, the default StatusProgressStorage + last-handled annotation
    # collide, producing "Patching failed with inconsistencies" and a
    # self-feeding reconcile loop on status.trustLevel.
    settings.persistence.finalizer = "zta-operator.devsecops.licenta.ro/finalizer"
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(
        prefix="zta-operator.devsecops.licenta.ro",
    )
    settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix="zta-operator.devsecops.licenta.ro",
        key="last-handled-configuration",
    )
```

Doi operator-i kopf care urmăresc același CR scriu independent în
adnotări/finalizers. Fără prefixe distincte, kopf consideră fiecare patch
al celuilalt operator ca un "diff necunoscut", emite un retry, care la
rândul lui generează alt patch, care la rândul lui... loop infinit.

Soluție: prefixe `zta-operator.devsecops.licenta.ro` vs.
`provenance-enforcer.devsecops.licenta.ro`. Comentariul din cod e explicit
despre incidentul rezolvat.

## §8.4 Idempotency short-circuit

```python
# operator.py:279-289
def _hash_desired_spec(desired_spec: dict[str, Any]) -> str:
    """Stable SHA256 of the spec used to detect "already-converged" state.

    Stops the reconcile loop when kopf re-fires `reconcile_on_trust_level`
    (or `reconcile_on_spec`) for an unchanged spec — without this guard,
    cosign + trivy were being re-run every 30s on a stable workload,
    burning CPU and racing with provenance-enforcer's status patches.
    """
    return hashlib.sha256(
        json.dumps(desired_spec or {}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
```

```python
# operator.py:318-338
spec_hash = _hash_desired_spec(desired_spec)
metadata = body.get("metadata", {}) or {}
annotations = metadata.get("annotations", {}) or {}
prev_hash = (
    str(current_status.get("specReconcileHash", "") or "").strip()
    or str(annotations.get("zta.devsecops/spec-reconcile-hash", "") or "").strip()
)
prev_phase = str(current_status.get("phase", "") or "").strip()
prev_trust = str(current_status.get("trustLevel", "") or "").strip()
has_error = bool(str(current_status.get("lastError", "") or "").strip())
if (
    prev_hash == spec_hash
    and prev_phase == "Running"
    and prev_trust == "Verified"
    and not has_error
):
    adapter.info(
        "ZTA already converged for this spec; skipping reconcile",
        extra={"event": "reconcile-skipped-idempotent", "spec_hash": spec_hash[:16]},
    )
    return
```

Patru condiții care **toate** trebuie să fie satisfăcute pentru skip:

1. Hash-ul `spec`-ului curent == hash-ul ultimului `spec` reconciliat cu
   succes.
2. Phase == `Running` (deployment-ul există și e healthy).
3. trustLevel == `Verified` (provenance OK).
4. Nicio eroare reziduală.

Dacă oricare e fals, reconcile-ul continuă. Idempotency nu e o optimizare
prematură — vezi nota din docstring: cosign + trivy rulau la fiecare 30s
înainte de această garanție.

**Stocare în două locuri (fallback):**

```python
# operator.py:231-255
def _write_spec_hash_annotation(...) -> None:
    """Persist the spec hash as a metadata annotation.

    Belt-and-braces with the schema-aware status.specReconcileHash field:
    annotations are always accepted by the API server even if the CRD
    schema wasn't upgraded to include the new status field. The metadata
    PATCH is on the main resource (not the status subresource).
    """
```

Adnotările sunt acceptate de API server fără validare de schemă, deci
funcționează chiar dacă CRD-ul nu a fost actualizat. Câmpul
`status.specReconcileHash` necesită upgrade de schemă (vezi
`18-status-fields-reference.md`).

## §8.5 Ordinea exactă a fazelor

În `_reconcile_impl` (`operator.py:292+`), după idempotency check, ordinea
este:

```
1. Validating       _status_patch(phase=Validating, lastError="")
2. SCA resolution   matched_policy = get_matching_policy_for_application(...)
                    effective_policy = resolve_effective_supply_chain_policy(...)
3. Provenance gate  if requires_provenance_verification(...) and trust_level != "Verified":
                       phase=Pending; return  (vezi 09)
4. Runtime drift    compliant, violations, sanction = check_runtime_drift(...)
                    if not compliant: phase=Degraded; raise PermanentError
5. Supply-chain     result = await verify_supply_chain(image, ...)
                    _record_verification(cosign, trivy, ...)
                    if not result.success: phase=Failed_SupplyChain (vezi 10)
6. Attestation      attestation_status = await validate_admission_with_attestations(...)
                    _record_verification(sbom, policyAttestation, slsa, openvex)
                    (vezi 11, 12)
7. Provisioning     _status_patch(phase=Provisioning, ...)
                    for obj in objects: apply_object(...)
                    upsert_talon_rule(...)
                    (vezi 13, 14)
8. Final            _status_patch(phase=Running, trustLevel=Verified,
                                  specReconcileHash=spec_hash)
9. GUAC async       executor.submit(ingest_to_guac_async)  (vezi 15)
```

Fiecare tranziție este un `_status_patch` separat, ceea ce înseamnă că UI-ul
(prin SSE stream) vede progresul incremental, nu doar tranziția finală.

## §8.6 Iterație vs convergență

Un operator Kubernetes nu garantează că o reconciliere atomică reușește în
prima încercare. Filosofia este *eventual consistency*:

- Dacă reconcile-ul ridică `kopf.TemporaryError`, kopf reaprinde după
  `delay=` secunde.
- Dacă ridică `kopf.PermanentError`, eroarea e persistată în
  `status.lastError` și CR-ul rămâne în starea de eșec până la o modificare
  manuală.
- Dacă reușește, scrie `phase=Running` și `specReconcileHash=...`.

Operatorul nostru folosește:

- `kopf.TemporaryError` pentru: SCA missing (ArgoCD race), eșec API K8s
  retryable, timeout, eroare necunoscută (catch-all).
- `kopf.PermanentError` pentru: violare policy, drift permanent, ValueError
  pe spec, ApiException non-retryable (403, 401, 422).

Detalii: vezi `17-error-taxonomy-and-observability.md`.

## §8.7 Ce urmează

Faza 2 din lista de mai sus — rezolvarea SCA-ului și poarta de provenance —
e cel mai delicat pas (interacționează cu un alt operator). Vezi
`09-operator-sca-policy-matching.md`.
