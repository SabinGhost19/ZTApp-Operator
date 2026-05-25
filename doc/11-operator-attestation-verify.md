# 11 — Operator: SBOM + ZTA policy + SLSA + OpenVEX + manifest hash

## §11.1 Analogie: cinci documente la biroul notarial

Imaginea a trecut de filtrele vamale (cosign + trivy). Acum biroul notarial
îi cere cinci documente:

1. **Lista pachetelor** (SBOM) cu semnătura producătorului.
2. **Declarația de politică** (ZTA policy attestation), conține hash-ul
   contractului semnat.
3. **Provenienta build-ului** (SLSA v1.0) — declarație că laboratorul
   acreditat a executat producția.
4. **Statement-uri OpenVEX** semnate de auditor.
5. **Hash-ul manifestului GitOps** comparat cu hash-ul atestat.

Notarul nu testează produsele — testează **coerența documentelor**. Dacă
SBOM-ul declarat la fabricație diferă de cel atestat, sau dacă hash-ul
manifestului nu corespunde, refuză inregistrarea.

Toate aceste verificări sunt în `validate_admission_with_attestations`
(`supply_chain_attestation.py:738+`).

## §11.2 Punctul de extracție comun: `_verify_attestation_by_type`

```python
# supply_chain_attestation.py:168-198
async def _verify_attestation_by_type(image: str, attestation_type: str, trusted_issuers: list[str]) -> dict[str, Any]:
    last_error = ""
    for identity in trusted_issuers:
        cmd = [
            COSIGN_BIN,
            "verify-attestation",
            image,
            "--type",
            attestation_type,
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            DEFAULT_ISSUER,
        ]
        returncode, stdout, stderr = await _run_cosign(cmd, timeout=VERIFY_TIMEOUT_SECONDS)
        if returncode != 0:
            last_error = stderr or stdout
            continue

        for obj in _extract_json_objects(stdout):
            predicate_type, predicate = _decode_attestation_predicate(obj)
            if predicate is not None and predicate_type:
                return {
                    "predicateType": predicate_type,
                    "predicate": predicate,
                }
        last_error = "Attestation output could not be parsed"

    raise SupplyChainPolicyError(
        f"Unable to verify attestation type {attestation_type} with trusted issuers. Last error: {last_error}"
    )
```

Această funcție unică alimentează **toate** verificările de atestări (SBOM,
ZTA policy, SLSA, OpenVEX). Diferența între ele:

- `attestation_type` parametru.
- Parsing-ul specific al `predicate`-ului returnat.

DSSE envelope (`{payload, signatures, ...}`) → base64 decode →
`{predicateType, subject, predicate}` → returnează predicate-ul.

## §11.3 SBOM (spdxjson)

```python
# supply_chain_attestation.py (sbom block, ~875-905 după modificarea recentă)
if bool(sbom_policy.get("enforceSBOM", False)):
    import time as _time_sbom
    _t0_sbom = _time_sbom.monotonic()
    logger.info(
        "SBOM attestation verification started",
        extra={"event": "attestation-sbom-start", ...},
    )
    try:
        sbom_attestation = await _verify_attestation_by_type(
            image=resolved_image,
            attestation_type="spdxjson",
            trusted_issuers=trusted_issuers,
        )
    except Exception as exc:
        _duration_ms = int((_time_sbom.monotonic() - _t0_sbom) * 1000)
        _reason = f"sbom-attestation-missing: {exc}"
        _record_verification(custom, namespace, app_name, "sbom",
            passed=False, reason=_reason, durationMs=_duration_ms)
        _emit_event(api_client, namespace, app_name,
            reason="SbomAttestationMissing", message=_reason, event_type="Warning")
        raise
    sbom_predicate = sbom_attestation.get("predicate", {}) or {}
    sbom_packages = _extract_sbom_packages(sbom_predicate)
    sbom_digest = _hash_json(sbom_predicate)
    _record_verification(custom, namespace, app_name, "sbom",
        passed=True, reason="ok", durationMs=_duration_ms,
        digest=sbom_digest, packageCount=len(sbom_packages))
    _emit_event(api_client, namespace, app_name,
        reason="SbomAttestationVerified",
        message=f"{len(sbom_packages)} packages, digest={sbom_digest[:24]}... ({_duration_ms} ms)")
```

Apoi validarea `forbiddenPackages`:

```python
# supply_chain_attestation.py:_validate_sbom_against_policy (selecție conceptuală)
violations.extend(_validate_sbom_against_policy(sbom_packages, sbom_policy))
```

Funcția iterează `forbiddenPackages` din SCA. Pentru fiecare entry
`{name, maxVersion}`, caută în SBOM dacă există pachetul; dacă da, compară
versiunea cu `maxVersion` via `_version_leq()` (numeric tuple comparison).
Dacă găsit pachet ≥ maxVersion → violation.

## §11.4 ZTA policy attestation + `expected_infra_hash`

```python
# supply_chain_attestation.py (policy block, ~907-955)
if bool(policy_binding.get("enabled", False)):
    attestation_type = (
        str(policy_binding.get("requireAttestationType",
            "https://devsecops.licenta.ro/attestations/custom-zta-policy/v1")).strip()
        or "https://devsecops.licenta.ro/attestations/custom-zta-policy/v1"
    )
    ...
    try:
        policy_attestation = await _verify_attestation_by_type(
            image=resolved_image,
            attestation_type=attestation_type,
            trusted_issuers=trusted_issuers,
        )
    except Exception as exc:
        _record_verification(custom, namespace, app_name, "policyAttestation",
            passed=False, reason=f"policy-attestation-missing: {exc}", ...)
        raise
    policy_predicate = policy_attestation.get("predicate", {}) or {}
    policy_digest = _hash_json(policy_predicate)
    expected_infra_hash = str(policy_predicate.get("expected_infra_hash", "")).strip()
    _record_verification(custom, namespace, app_name, "policyAttestation",
        passed=True, reason="ok", ...,
        attestationType=attestation_type, digest=policy_digest,
        expectedInfraHash=expected_infra_hash)
```

Apoi recalculul hash-ului local și comparația:

```python
# supply_chain_attestation.py:_validate_manifest_hash (selecție conceptuală)
deny_hash, alert_hash, computed_infra_hash = _validate_manifest_hash(
    spec=spec,
    strict_manifest_hash=strict_manifest_hash,
    expected_hash=expected_infra_hash,
)
violations.extend(deny_hash)
alerts.extend(alert_hash)
```

`_validate_manifest_hash` aplică `_hash_spec_payload(spec)` (citată în §05),
compară cu `expected_hash`. Două moduri:

- `strict_manifest_hash.enforcementAction=Reject` → mismatch → `violations`
  (denial).
- `enforcementAction=Alert` → mismatch → `alerts` (continue, dar
  `securityState=Alert`).

## §11.5 SLSA v1.0 (nou)

```python
# supply_chain_attestation.py:_verify_slsa_provenance (selecție)
async def _verify_slsa_provenance(
    *, custom, api_client, namespace, app_name, image, trusted_issuers, policy,
) -> list[str]:
    import time
    t0 = time.monotonic()
    logger.info("SLSA provenance verification started", ...)
    try:
        attestation = await _verify_attestation_by_type(
            image=image,
            attestation_type="slsaprovenance1",
            trusted_issuers=trusted_issuers,
        )
    except Exception as exc:
        duration_ms = int((time.monotonic() - t0) * 1000)
        _record_verification(custom, ..., "slsaProvenance",
            passed=False, reason=f"slsa-attestation-missing: {exc}",
            durationMs=duration_ms)
        _emit_event(..., reason="SlsaAttestationMissing", event_type="Warning")
        return [f"slsa-attestation-missing: {exc}"]

    predicate = attestation.get("predicate", {}) or {}
    build_def = predicate.get("buildDefinition", {}) or {}
    run_details = predicate.get("runDetails", {}) or {}
    builder = (run_details.get("builder", {}) or {})
    build_type = str(build_def.get("buildType", "")).strip()
    builder_id = str(builder.get("id", "")).strip()

    failures: list[str] = []
    allowed_build_types = [str(x).strip() for x in (policy.get("allowedBuildTypes", []) or []) if str(x).strip()]
    if allowed_build_types and build_type not in allowed_build_types:
        failures.append(f"slsa-build-type-untrusted: {build_type or '<missing>'}")

    trusted_builders = [str(x).strip() for x in (policy.get("trustedBuilders", []) or []) if str(x).strip()]
    if trusted_builders and builder_id not in trusted_builders:
        failures.append(f"slsa-builder-untrusted: {builder_id or '<missing>'}")

    required_level = int(policy.get("requiredLevel", 0) or 0)
    if required_level >= 3 and not builder_id:
        failures.append("slsa-builder-missing-for-level-3")
    ...
```

Trei verificări pe predicate:
1. `buildType` în lista `allowedBuildTypes` (dacă SCA o declară).
2. `builder.id` în lista `trustedBuilders` (dacă SCA o declară).
3. `requiredLevel >= 3` implică `builder.id` non-vid.

Listele goale = no-op (skip). Permite SCA-uri minimale care doar cer
prezența SLSA, fără restricții pe builder.

## §11.6 OpenVEX ca atestare semnată (nou)

```python
# supply_chain_attestation.py:_verify_openvex_attestation (selecție)
async def _verify_openvex_attestation(...) -> list[str]:
    import time
    t0 = time.monotonic()
    logger.info("OpenVEX attestation verification started", ...)
    try:
        attestation = await _verify_attestation_by_type(
            image=image,
            attestation_type="https://openvex.dev/ns/v0.2.0",
            trusted_issuers=trusted_issuers,
        )
    except Exception as exc:
        ...
        return [f"openvex-attestation-missing: {exc}"]

    predicate = attestation.get("predicate", {}) or {}
    statements = predicate.get("statements", []) or []
    failures: list[str] = []
    if not isinstance(statements, list):
        failures.append("openvex-statements-not-a-list")
    if bool(policy.get("requireStatements", False)) and not statements:
        failures.append("openvex-no-statements")
    ...
```

**Important** — această verificare e **separată** de cea folosită pentru
filtrarea Trivy (`vex.py:fetch_vex_statements`). Diferența:

- `fetch_vex_statements` (în `supply_chain.py`) — best-effort, eșec = listă
  vidă. Folosit pentru exempții CVE.
- `_verify_openvex_attestation` (acesta) — strict, eșec = violation. Folosit
  pentru a impune existența unei atestări OpenVEX semnate ca artefact
  obligatoriu separat.

Decizie design: două apeluri cosign separate pe același predicate, cu
semantici diferite. Costul (un round-trip extra Rekor) este compensat de
claritatea separării.

## §11.7 Custom rules CEL

Vezi `12-operator-cel-rules.md` pentru CEL evaluation. Apelul:

```python
# supply_chain_attestation.py:898-925 (selecție)
custom_rules = global_spec.get("customRules", []) or []
if custom_rules:
    try:
        from .cel_eval import evaluate_custom_rules

        voucher_ctx: dict[str, Any] = {}
        vex_ctx: list[dict[str, Any]] = []
        try:
            zta_obj = custom.get_namespaced_custom_object(
                group=GROUP, version=VERSION, namespace=namespace, plural=PLURAL, name=app_name,
            )
            zta_status = (zta_obj.get("status", {}) or {})
            voucher_ctx = (zta_status.get("provenance", {}) or {}).get("voucher", {}) or {}
            vex_ctx = (zta_status.get("attestations", {}) or {}).get("vexStatements", []) or []
        except ApiException:
            pass

        cel_ctx = {
            "voucher": voucher_ctx,
            "image": resolved_image,
            "zta": spec,
            "vex": vex_ctx,
            "sbom": sbom_predicate,
        }
        cel_result = evaluate_custom_rules(custom_rules, cel_ctx)
        cel_evaluations = list(cel_result.evaluations)
        # Persist celEvaluations to the status subresource *before* any
        # downstream raise.
        try:
            _status_patch(custom, namespace, app_name,
                {"attestations": {"celEvaluations": cel_evaluations}})
        except ApiException:
            logger.debug("status.attestations.celEvaluations early-patch failed")
        ...
        violations.extend(cel_result.deny)
```

Notă bug-fix: `celEvaluations` se persistă **înainte** de orice `raise`
(vezi `12-operator-cel-rules.md` §12.5 pentru context complet).

## §11.8 Agregarea finală a violărilor

```python
# supply_chain_attestation.py:993-998 (după CEL)
if violations:
    raise SupplyChainPolicyError("; ".join(violations))
```

Toate violations colectate din SBOM, manifest hash, SLSA, OpenVEX, CEL sunt
join-uite și ridicate ca o singură `SupplyChainPolicyError` care e prinsă
în `_reconcile_impl` și transformată în `phase=Failed_SupplyChain` +
`PermanentError`.

Alerts (non-blocking) rămân în lista returnată ca
`attestations.activeViolations`:

```python
# supply_chain_attestation.py:1004-1025 (selecție)
security_state = "Compliant"
if alerts:
    security_state = "Alert"
    for msg in alerts:
        _emit_warning_event(...)

return {
    "securityState": security_state,
    "attestations": {
        "policyName": ...,
        "resolvedImage": resolved_image,
        "sbomDigest": sbom_digest,
        "policyDigest": policy_digest,
        "sbomPackages": sbom_packages,
        "policyPredicate": policy_predicate,
        "expectedInfraHash": expected_infra_hash,
        "computedInfraHash": computed_infra_hash,
        "celEvaluations": cel_evaluations,
    },
    "activeViolations": alerts,
    "lastVerified": datetime.now(timezone.utc).isoformat(),
}
```

## §11.9 Ce urmează

Următorul fișier intră în detaliu pe CEL: `12-operator-cel-rules.md`.
