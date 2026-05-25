# 17 — Taxonomie de erori și observabilitate

## §17.1 Analogie: dosarul medical electronic

Un dosar medical bun nu listează doar "pacientul are febră". Conține:

- **Cod ICD-10** (taxonomie stabilă — `R50.9` = "Fever, unspecified").
- **Mesaj uman** ("febră 38.5°C, fără simptome respiratorii").
- **Faza** (diagnostic, tratament, urmărire).
- **Recoverable?** (acută vs cronică).
- **Timestamp**.
- **Detalii structurate** (analize, observații).

Această structurare permite query-uri ulterioare: "câți pacienți cu `R50.9`
au prezentat și `J06.9`?". O bază de date a operatorului fără taxonomie
permite doar `grep`.

`zta-operator` adoptă această discipline pentru toate verdictele.

## §17.2 Câmpurile structurate scrise în `status`

### `status.verifications.*` (per check ledger)

Scris de `_record_verification` (`operator.py:191-209` și
`supply_chain_attestation.py:518-540`).

```python
# operator.py:181-209
def _record_verification(
    custom: client.CustomObjectsApi,
    namespace: str,
    name: str,
    key: str,
    *,
    passed: bool,
    reason: str = "",
    **extra: Any,
) -> None:
    """Write a single check result into status.verifications.<key>.

    Merge-patch: only the named sub-key is overwritten, sibling
    verification entries are preserved by the API server.
    """
    from datetime import datetime, timezone

    entry: dict[str, Any] = {
        "passed": bool(passed),
        "reason": str(reason or ("ok" if passed else "failed")),
        "completedAt": datetime.now(timezone.utc).isoformat(),
    }
    for ekey, evalue in extra.items():
        if evalue is None:
            continue
        entry[ekey] = evalue
    try:
        _status_patch(custom, namespace, name, {"verifications": {key: entry}})
    except ApiException:
        # CRD may not yet have the field on older clusters; swallow so
        # the reconcile can continue. UI falls back to lastError regex.
        logger.debug("status.verifications.%s patch failed (older CRD?)", key)
```

Chei stabile populate: `cosign`, `trivy`, `sbom`, `policyAttestation`,
`slsaProvenance`, `openvex`. Fiecare entry are minim `{passed, reason,
completedAt, durationMs}`; extra fields per check (ex. `sbom.digest`,
`slsaProvenance.builderId`).

Merge-patch garantează că scrierea unei chei (`{"verifications": {"cosign":
{...}}}`) **nu** șterge celelalte (sbom, trivy, etc.).

### `status.errors[]` (ring buffer)

Scris de `_record_error` (`operator.py:135-178`).

```python
# operator.py:147-178
def _record_error(
    custom: client.CustomObjectsApi,
    namespace: str,
    name: str,
    *,
    code: str,
    message: str,
    phase: str = "",
    retryable: bool = True,
    details: dict[str, Any] | None = None,
) -> None:
    """Append a structured error entry to status.errors (ring buffer).

    Best-effort: failures here never abort the reconcile, but they are
    logged so the operator's own observability remains intact.
    """
    from datetime import datetime, timezone

    entry: dict[str, Any] = {
        "code": str(code or "unknown")[:128],
        "message": str(message or "")[:2048],
        "phase": str(phase or "")[:64],
        "retryable": bool(retryable),
        "occurredAt": datetime.now(timezone.utc).isoformat(),
    }
    if details:
        try:
            entry["details"] = json.loads(json.dumps(details, default=str))
        except Exception:
            entry["details"] = {"_raw": str(details)[:1024]}
    try:
        # Read-modify-write the ring buffer. JSON merge-patch on arrays
        # replaces the whole list, so we must fetch the current state.
        obj = custom.get_namespaced_custom_object(...)
        existing = list(((obj or {}).get("status", {}) or {}).get("errors", []) or [])
        existing.append(entry)
        if len(existing) > _ERROR_RING_BUFFER_MAX:
            existing = existing[-_ERROR_RING_BUFFER_MAX:]
        _status_patch(custom, namespace, name, {"errors": existing})
    except ApiException as patch_exc:
        logger.warning("status.errors patch failed", ...)
```

Două puncte non-triviale:

1. **`json.loads(json.dumps(details, default=str))`** — round-trip pentru a
   garanta că `details` e JSON-serializable. Obiecte Python complexe (ex.
   ApiException) au atribute non-JSON; `default=str` le convertește.
2. **Ring buffer** — limită la 20 entries (`_ERROR_RING_BUFFER_MAX`).
   Necesar pentru că `status.errors` e scris în etcd; o aplicație care
   eșuează 1000 de ori ar umfla CR-ul indefinit.
3. **JSON merge-patch pe arrays înlocuiește toată lista**, deci read-modify-write
   e obligatoriu. Compromis: o mică race condition între reconcile-uri
   concurrent (ar șterge entries scrise între read și write); acceptat
   pentru că operatorul nu rulează HA.

### Clasificarea ApiException

```python
# operator.py:115-132
def _classify_api_exception(exc: ApiException) -> tuple[str, bool]:
    """Map a Kubernetes ApiException to (code, retryable)."""
    status_code = int(getattr(exc, "status", 0) or 0)
    if status_code == 404:
        return "k8s-resource-not-found", True
    if status_code == 409:
        return "k8s-conflict", True
    if status_code == 403:
        return "k8s-forbidden", False
    if status_code == 401:
        return "k8s-unauthorized", False
    if status_code == 422:
        return "k8s-invalid-spec", False
    if 500 <= status_code < 600:
        return "k8s-server-error", True
    if status_code == 0:
        return "k8s-network", True
    return f"k8s-http-{status_code}", True
```

Tabel de decizie:

| HTTP status | Cod stabil | Retryable | Sens |
|---|---|---|---|
| 0 | `k8s-network` | Yes | Network failure / DNS / TCP |
| 401 | `k8s-unauthorized` | No | Token invalid; nu se va vindeca de la sine |
| 403 | `k8s-forbidden` | No | RBAC; admin trebuie să corecteze |
| 404 | `k8s-resource-not-found` | Yes | Resource poate apărea ulterior (GitOps race) |
| 409 | `k8s-conflict` | Yes | OCC conflict; refetch + retry |
| 422 | `k8s-invalid-spec` | No | Schema validation failed; spec invalid |
| 5xx | `k8s-server-error` | Yes | API server lent / restart |

## §17.3 Categorii de excepții în `_reconcile_impl`

```python
# operator.py:849-980 (selecție din cele 9 handler-e)
except SupplyChainPolicyMissingError as exc:
    ...
    _record_error(custom, namespace, name,
                  code="sca-policy-missing", message=str(exc),
                  phase="Validating", retryable=True)
    raise kopf.TemporaryError(str(exc), delay=15) from exc

except SupplyChainPolicyError as exc:
    ...
    _record_error(custom, namespace, name,
                  code="attestation-policy-violation", message=str(exc),
                  phase="Attestation", retryable=False)
    raise kopf.PermanentError(str(exc)) from exc

except ApiException as exc:
    code, retryable = _classify_api_exception(exc)
    ...
    _record_error(custom, namespace, name,
                  code=code, message=str(exc.reason or "Kubernetes API error"),
                  phase="K8sApi", retryable=retryable,
                  details={"status": int(getattr(exc, "status", 0) or 0),
                           "body": body_text})
    if not retryable:
        raise kopf.PermanentError(f"{code}: {exc.reason}") from exc
    raise kopf.TemporaryError(f"{code}: {exc.reason}", delay=30) from exc

except SupplyChainError as exc:
    ...
    _record_error(..., code="supply-chain-error", phase="SupplyChain", retryable=True)
    raise kopf.TemporaryError(str(exc), delay=30) from exc

except TalonConfigError as exc:
    ...
    _record_error(..., code="talon-config-error", phase="RuntimeEnforcement", retryable=True)
    raise kopf.TemporaryError(str(exc), delay=30) from exc

except ValueError as exc:
    ...
    _record_error(..., code="spec-validation-error", phase="Validating", retryable=False)
    raise kopf.PermanentError(str(exc)) from exc

except asyncio.TimeoutError as exc:
    ...
    _record_error(..., code="reconcile-timeout", phase="Unknown", retryable=True)
    raise kopf.TemporaryError(msg, delay=30) from exc

except kopf.TemporaryError:
    raise
except kopf.PermanentError:
    raise
except Exception as exc:  # noqa: BLE001 — defensive catch-all
    import traceback as _tb
    tb_excerpt = _tb.format_exc(limit=6)
    msg = f"unexpected error: {type(exc).__name__}: {exc}"
    ...
    _record_error(..., code="reconcile-unexpected",
                  phase="Unknown", retryable=True,
                  details={"exceptionType": type(exc).__name__,
                           "traceback": tb_excerpt[-1500:]})
    raise kopf.TemporaryError(msg, delay=60) from exc
```

**Categorii distincte, cod stabil pentru fiecare**:

| Excepție | Cod | Retryable | kopf escalation |
|---|---|---|---|
| `SupplyChainPolicyMissingError` | `sca-policy-missing` | Yes | `TemporaryError(delay=15)` |
| `SupplyChainPolicyError` | `attestation-policy-violation` | No | `PermanentError` |
| `ApiException` | (clasificat) | (clasificat) | (clasificat) |
| `SupplyChainError` | `supply-chain-error` | Yes | `TemporaryError(delay=30)` |
| `TalonConfigError` | `talon-config-error` | Yes | `TemporaryError(delay=30)` |
| `ValueError` | `spec-validation-error` | No | `PermanentError` |
| `asyncio.TimeoutError` | `reconcile-timeout` | Yes | `TemporaryError(delay=30)` |
| `Exception` (catch-all) | `reconcile-unexpected` | Yes | `TemporaryError(delay=60)` |

`kopf.TemporaryError`/`PermanentError` sunt re-raised neatinse — kopf le
procesează separat pentru retry logic.

## §17.4 Evenimente kopf (corev1.Event)

Helper centralizat:

```python
# supply_chain_attestation.py:439-477
def _emit_event(
    api_client: client.ApiClient,
    namespace: str,
    app_name: str,
    reason: str,
    message: str,
    *,
    event_type: str = "Normal",
    action: str = "Verification",
) -> None:
    """Emit a K8s Event on the ZTA object so `kubectl describe` and the
    UI's EventsTimelinePanel surface it. Best-effort — failures here must
    not abort the reconcile."""
    try:
        events_api = client.EventsV1Api(api_client)
        now = datetime.now(timezone.utc)
        event = client.EventsV1Event(
            metadata=client.V1ObjectMeta(
                generate_name=f"{app_name}-",
                namespace=namespace,
            ),
            event_time=now,
            reporting_controller="zta-operator",
            reporting_instance="zta-operator",
            action=action,
            reason=reason,
            note=message[:1024],
            type=event_type,
            regarding=client.V1ObjectReference(
                api_version=f"{GROUP}/{VERSION}",
                kind="ZeroTrustApplication",
                name=app_name,
                namespace=namespace,
            ),
        )
        events_api.create_namespaced_event(namespace=namespace, body=event)
    except Exception as exc:  # event emission is best-effort
        logger.warning(
            "Failed to emit K8s event",
            extra={"event": "audit-event-emit-failed", "reason": reason, "error": str(exc)},
        )
```

Emite `events.k8s.io/v1.Event` cu `regarding` = referința la ZTA. Vizibilă
prin `kubectl describe zta <name>` și prin SSE stream din UI
(`EventsTimelinePanel`).

Reason-uri stabile emise:
- `CosignVerified` / `CosignVerificationFailed`
- `TrivyScanPassed` / `TrivyScanRejected`
- `SbomAttestationVerified` / `SbomAttestationMissing`
- `PolicyAttestationVerified` / `PolicyAttestationMissing`
- `SlsaAttestationVerified` / `SlsaAttestationRejected` / `SlsaAttestationMissing`
- `OpenVexAttestationVerified` / `OpenVexAttestationRejected` / `OpenVexAttestationMissing`
- `ManifestHashDrift` (alert mode)
- `CelRuleAlert`

## §17.5 Loguri structurate

Folosim `LoggerAdapter` cu context per-reconcile:

```python
# operator.py:296
adapter = logging.LoggerAdapter(logger, ctx(name=name, namespace=namespace, uid=uid, reconcile_id=reconcile_id, phase="Validating"))
```

Și logging cu `extra=` în fiecare punct cheie:

```python
# Exemplu — operator.py:402-405
adapter.warning(
    "Supply-chain vulnerability policy exceeded but action is Alert",
    extra={"event": "supply-chain-vulnerability-alert", "reason": result.reason},
)
```

Trei tipuri de câmpuri `extra` standardizate:

- `event` — identifier stabil al evenimentului în pipeline (consumat de
  Loki/Promtail filters).
- `duration_ms` — timpul efectiv al pasului (consumat de SLO dashboards).
- `reason`, `error`, `image`, `zta_name`, etc. — context specific.

## §17.6 Timing (`durationMs`)

Pattern aplicat consistent în fiecare pas costisitor:

```python
# Pattern (exemplu din supply_chain_attestation.py:_verify_slsa_provenance)
import time
t0 = time.monotonic()
logger.info("SLSA provenance verification started", ...)
try:
    attestation = await _verify_attestation_by_type(...)
except Exception as exc:
    duration_ms = int((time.monotonic() - t0) * 1000)
    _record_verification(..., durationMs=duration_ms)
    ...
duration_ms = int((time.monotonic() - t0) * 1000)
_record_verification(..., durationMs=duration_ms)
logger.info("SLSA provenance verified", extra={..., "duration_ms": duration_ms, ...})
_emit_event(..., message=f"... ({duration_ms} ms)")
```

`time.monotonic()` (nu `time.time()`) — monotonic clock e imun la
modificări de wall-clock (NTP sync, leap seconds), corect pentru durații.

`durationMs` ajunge în trei locuri:
1. `status.verifications.<key>.durationMs` (UI display).
2. Log structurat (Loki).
3. Mesaj kopf event (auditor trail).

## §17.7 Stream-ul SSE și envelope-uri de eroare

Backend-ul SSE produce frames structurate, nu free text:

```python
# userInterfaceDashboard/backend/app/services/integrity_stream.py:25-35
def _sse_error(code: str, message: str, *, recoverable: bool = True,
               details: dict[str, Any] | None = None) -> str:
    """Build a structured SSE error frame the frontend can pattern-match
    on `code` rather than doing string analysis on `message`."""
    payload: dict[str, Any] = {
        "code": code,
        "message": message,
        "recoverable": bool(recoverable),
    }
    if details:
        payload["details"] = details
    return f"event: integrity.error\ndata: {json.dumps(payload, default=str)}\n\n"
```

Coduri stream stabile:
- `zta-not-found`, `k8s-api-error`, `k8s-server-error`, `k8s-unreachable`,
  `payload-encode-error`, `tick-unexpected`, `stream-giving-up`.

Frontend (`composables/useIntegrityStream.ts`) face match pe `code`, nu pe
`message`. Schimbarea mesajului uman nu strică UX-ul.

## §17.8 Backend FastAPI — handler global de excepții

Vezi `middleware/errors.py`. Acoperă (în ordine de detectare):

1. `ValidationError` / `RequestValidationError` → 422
2. `HTTPException` → status code-ul ridicat
3. `ApiException` (kubernetes-asyncio) → status code reflected
4. `asyncio.TimeoutError` → 504
5. `asyncio.CancelledError` → 499 (client closed request)
6. `ConnectionError`/`OSError` → 502
7. `JSONDecodeError` → 502
8. `PermissionError` → 403
9. `ZeroTrustException` → 400 (business logic)
10. Catch-all `Exception` → 500

Fiecare branch produce un `APIErrorDetails` consistent cu `trace_id`,
`error_code`, `message`, `technical_details`, `action_required`. Frontend
afișează `action_required` ca recomandare către user.

## §17.9 Ce urmează

Ultimul fișier — referință completă a fiecărui câmp din ZTA status. Vezi
`18-status-fields-reference.md`.
