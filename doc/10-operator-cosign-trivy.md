# 10 — Operator: cosign + trivy + VEX

## §10.1 Analogie: două filtre seriale la fabrica de mâncare

Materia primă trece prin două filtre:

1. **Filtrul vamal de origine** — verifică doar dacă producătorul are
   licență valabilă. Nu inspectează produsul, doar provincia.
2. **Filtrul laboratorului** — verifică contaminanții, dar acceptă exempții
   semnate de un toxicolog autorizat ("substanța X la concentrația Y nu e
   periculoasă pentru aplicația Z").

Ordinea contează. Dacă filtrul 1 respinge, filtrul 2 nu mai rulează —
economisim resurse. Dacă filtrul 1 trece, filtrul 2 e mai relaxat pentru
că originea e deja verificată.

Cosign = filtrul 1 (semnătura imaginii). Trivy + VEX = filtrul 2
(vulnerabilități).

## §10.2 Validarea referinței imaginii (preliminar)

```python
# zta-operator/src/zta_operator/supply_chain.py:47-56
def validate_image_reference(image: str) -> None:
    if not image.startswith("ghcr.io/"):
        raise SupplyChainError("Image must use ghcr.io registry.")
    if "@sha256:" in image:
        return
    if ":" not in image.rsplit("/", 1)[-1]:
        raise SupplyChainError("Image tag is required and must be immutable (e.g. v1.0.0).")
    tag = image.rsplit(":", 1)[-1]
    if tag.lower() == "latest":
        raise SupplyChainError("Tag 'latest' is forbidden.")
```

Trei reguli:
1. Doar `ghcr.io/...`.
2. Digest preferat (`@sha256:...`) — dacă există, acceptat necondiționat.
3. Fără `latest` (tag mutabil interzis).

## §10.3 Cosign verify keyless

```python
# supply_chain.py:59-76
async def verify_cosign_keyless(image: str, allowed_signer: str) -> VerificationResult:
    cmd = [
        COSIGN_BIN,
        "verify",
        image,
        "--certificate-identity",
        allowed_signer,
        "--certificate-oidc-issuer",
        DEFAULT_ISSUER,
    ]
    returncode, stdout, stderr = await _run_subprocess(cmd, timeout=VERIFY_TIMEOUT_SECONDS)
    if returncode != 0:
        return VerificationResult(
            success=False,
            reason="cosign-verification-failed",
            details={"stdout": stdout, "stderr": stderr, "returncode": returncode},
        )
    return VerificationResult(success=True, reason="ok", details={"stdout": stdout})
```

Apel subprocess către binarul cosign:
- `--certificate-identity` = identitatea atestată în cert Fulcio (URL-ul
  workflow-ului).
- `--certificate-oidc-issuer` = `https://token.actions.githubusercontent.com`
  (constanta `DEFAULT_ISSUER`).
- Timeout `VERIFY_TIMEOUT_SECONDS` (~60s default) protejează împotriva
  hang-urilor pe Rekor.

## §10.4 Cosign loop pe multiple identități

```python
# supply_chain.py:165-187 (selecție)
if require_signature:
    identities = [identity for identity in trusted_identities if str(identity).strip()]
    if not identities:
        raise SupplyChainError("At least one trusted identity is required when requireSignature is true.")
    last_result: VerificationResult | None = None
    for identity in identities:
        cosign_result = await verify_cosign_keyless(image=image, allowed_signer=str(identity).strip())
        if cosign_result.success:
            last_result = cosign_result
            break
        last_result = cosign_result
    if not last_result or not last_result.success:
        return last_result or VerificationResult(success=False, reason="cosign-verification-failed", details={})
```

**First-match-wins** peste lista `trustedIssuers` din SCA. Dacă imaginea e
semnată de oricare dintre identitățile permise → success. Dacă toate eșuează
→ last failure e returnat.

Acest design permite rotația identităților (re-folosesc workflow URL nou)
fără downtime — adminul adaugă noua identitate în SCA, lasă vechea, iar
imaginile vechi (semnate cu cea veche) continuă să fie acceptate.

## §10.5 Fetch VEX (înainte de Trivy)

```python
# supply_chain.py:189-204 (selecție)
if vex_statements is None:
    identities = [identity for identity in trusted_identities if str(identity).strip()]
    if identities:
        try:
            from .vex import fetch_vex_statements

            vex_statements = await fetch_vex_statements(image=image, trusted_issuers=identities)
        except Exception:
            vex_statements = []
```

VEX e *opt-in*. Eșecul fetch-ului (nu există atestare, Rekor lent etc.) →
listă vidă, **nu** eroare. Trivy va rula fără exempții.

```python
# vex.py:42-100 (selecție)
async def fetch_vex_statements(
    image: str,
    trusted_issuers: list[str],
) -> list[VexStatement]:
    """Fetch and parse the OpenVEX attestation for an image.

    Returns an empty list if no VEX is attached (best-effort: VEX is opt-in).
    """
    last_error = ""
    for identity in trusted_issuers:
        cmd = [
            COSIGN_BIN, "verify-attestation", image,
            "--type", "https://openvex.dev/ns/v0.2.0",
            "--certificate-identity", identity,
            "--certificate-oidc-issuer", DEFAULT_ISSUER,
        ]
        ...
        if (proc.returncode or 0) != 0:
            last_error = stderr_bytes.decode(...)
            continue

        stdout = stdout_bytes.decode(...)
        for line in stdout.splitlines():
            ...
            envelope = json.loads(line)
            payload_b64 = envelope.get("payload")
            ...
            statement = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
            predicate = statement.get("predicate") or {}
            return _parse_openvex_predicate(predicate)
```

Detaliu DSSE: cosign emite JSONL cu envelope `{payload, signatures, ...}`.
Payload-ul este base64-encoded JSON care conține `statement` (Subject + Type +
Predicate). Predicate-ul OpenVEX trăiește în `statement.predicate`.

## §10.6 Trivy scan

```python
# supply_chain.py:101-162 (selecție)
async def verify_trivy_threshold(
    image: str,
    max_vulnerabilities: str,
    fail_on_fixable: bool = False,
    vex_statements: list | None = None,
) -> VerificationResult:
    threshold = str(max_vulnerabilities).upper()
    if threshold not in SEVERITY_ORDER:
        raise SupplyChainError(f"Invalid maxVulnerabilities: {max_vulnerabilities}")

    cmd = [TRIVY_BIN, "image", "--format", "json", image]
    returncode, stdout, stderr = await _run_subprocess(cmd, timeout=TRIVY_TIMEOUT_SECONDS)
    if returncode != 0:
        return VerificationResult(
            success=False,
            reason="trivy-scan-failed",
            details={"stdout": stdout, "stderr": stderr, "returncode": returncode},
        )

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise SupplyChainError("Trivy output is not valid JSON.") from exc

    exempted_cves: list[str] = []
    if vex_statements:
        from .vex import filter_trivy_vulnerabilities

        payload, exempted_cves = filter_trivy_vulnerabilities(payload, vex_statements)

    highest = _max_found_severity(payload)
    if fail_on_fixable and _has_fixable_vulnerabilities(payload):
        return VerificationResult(
            success=False,
            reason="trivy-fixable-vulnerability-found",
            details={"threshold": threshold, "failOnFixable": True},
        )

    if highest is None:
        return VerificationResult(success=True, reason="ok", ...)

    if SEVERITY_ORDER[highest] > SEVERITY_ORDER[threshold]:
        return VerificationResult(
            success=False,
            reason="trivy-threshold-exceeded",
            details={"highest": highest, "threshold": threshold, "vexExempted": exempted_cves},
        )

    return VerificationResult(success=True, reason="ok", ...)
```

Trei verdict-uri posibile:

| Reason | Sens |
|---|---|
| `trivy-scan-failed` | Trivy a returnat exit code non-zero (binary lipsă, OCI inaccessible) |
| `trivy-fixable-vulnerability-found` | `failOnFixable=true` și există ≥1 CVE cu fix disponibil |
| `trivy-threshold-exceeded` | Cel mai sever CVE e peste `maxAllowedSeverity` |

VEX-ul filtrează **înainte** de evaluare. Dacă un CVE CRITICAL e marcat
`not_affected` în VEX, e eliminat din `payload` și nu mai contribuie la
`_max_found_severity()`.

## §10.7 `onVulnerabilityFound=Alert` vs `Kill`

Apelantul din operator decide ce face cu eșecul:

```python
# operator.py:367-401 (selecție)
if not result.success:
    vulnerability_action = str(effective_policy.get("onVulnerabilityFound", "Alert") or "Alert")
    is_vulnerability_failure = result.reason in VULNERABILITY_FAILURE_REASONS
    if is_vulnerability_failure and vulnerability_action == "Alert":
        vulnerability_violations = [f"VulnerabilityPolicyAlert: {result.reason}"]
        vulnerability_details = result.details
        adapter.warning(
            "Supply-chain vulnerability policy exceeded but action is Alert",
            extra={"event": "supply-chain-vulnerability-alert", "reason": result.reason},
        )
    else:
        state = "NonCompliant"
        active_violations = [result.reason]
        if is_vulnerability_failure and vulnerability_action == "Kill":
            state = apply_sanction(api_client=api_client, namespace=namespace, app_name=name, sanction="Kill")
            active_violations = [f"VulnerabilityPolicyKill: {result.reason}"]
        _status_patch(...)
        raise kopf.PermanentError(f"Supply chain verification failed: {result.reason}")
```

- **Alert** — log warning, dar continuă reconcile-ul. Workload-ul va fi
  deployed cu `securityState=Alert`. Util pentru dev cluster sau
  CVE-uri tolerate temporar.
- **Kill** — apelează `apply_sanction(sanction="Kill")` care șterge
  deployment-ul; ridică `PermanentError`.

Acest comportament e ortogonal față de `cosign-verification-failed` —
acela e **întotdeauna** un eșec terminal (signature missing/wrong nu poate
fi "alert-only").

## §10.8 Înregistrarea în `status.verifications`

Detaliile sunt în `17-error-taxonomy-and-observability.md` §17.3, dar pe
scurt: după `verify_supply_chain` operatorul scrie:

```python
# operator.py:349-403 (selecție)
_cosign_required = bool(effective_policy.get("requireSignature", True))
_is_cosign_failure = result.reason.startswith("cosign-")
if _cosign_required:
    _record_verification(custom, namespace, name, "cosign",
        passed=not _is_cosign_failure,
        reason=result.reason if _is_cosign_failure else "ok",
        durationMs=_sc_duration_ms)
if not _is_cosign_failure:
    _record_verification(custom, namespace, name, "trivy",
        passed=result.success, reason=result.reason,
        durationMs=_sc_duration_ms,
        highest=(result.details or {}).get("highest"),
        threshold=(result.details or {}).get("threshold"),
        vexExempted=(result.details or {}).get("vexExempted"))
```

Dezambiguare: cosign rulează primul, deci dacă `result.reason` începe cu
`cosign-`, atunci trivy *nu a rulat*. Doar înregistrăm cosign ca failed,
fără să atingem `status.verifications.trivy`.

## §10.9 Ce urmează

Cosign + trivy verifică **doar identitatea imaginii și conținutul ei
binar**. Pașii următori verifică **declarațiile despre imagine** — SBOM,
ZTA policy, SLSA, OpenVEX. Vezi `11-operator-attestation-verify.md`.
