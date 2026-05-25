import asyncio
import hashlib
import json
import logging
import re
from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import kopf
from kubernetes import client
from kubernetes.client.exceptions import ApiException

from .config import (
    COSIGN_BIN,
    DEFAULT_ISSUER,
    GROUP,
    PLURAL,
    SCA_PLURAL,
    SEVERITY_ORDER,
    VERIFY_TIMEOUT_SECONDS,
    VERSION,
)
from .logging_utils import configure_logging, ctx, new_reconcile_id


async def _run_cosign(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    """Run a cosign command without blocking the event loop."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise SupplyChainPolicyError(f"cosign command timed out after {timeout}s")
    return (
        proc.returncode or 0,
        stdout_bytes.decode("utf-8", errors="replace"),
        stderr_bytes.decode("utf-8", errors="replace"),
    )

logger = configure_logging()


class SupplyChainPolicyError(Exception):
    pass


class SupplyChainPolicyMissingError(SupplyChainPolicyError):
    """Referenced SCA does not yet exist in the cluster.

    Treated as a transient state by the reconciler (TemporaryError → retry)
    so the system is self-healing when SCA and ZTA are applied out of order
    (e.g. via Helm/ArgoCD where K8s does not guarantee apply order).
    """
    pass


@dataclass
class AppEvaluationResult:
    compliant: bool
    violations: list[str]


def _hash_json(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _to_jsonable(value: Any, seen: set[int] | None = None, depth: int = 0, max_depth: int = 32) -> Any:
    if seen is None:
        seen = set()

    if depth > max_depth:
        return "<max-depth>"

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    obj_id = id(value)
    if obj_id in seen:
        return "<recursive>"

    if isinstance(value, Mapping):
        seen.add(obj_id)
        return {str(k): _to_jsonable(v, seen, depth + 1, max_depth) for k, v in value.items()}

    if isinstance(value, Set):
        seen.add(obj_id)
        normalized = [_to_jsonable(item, seen, depth + 1, max_depth) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        seen.add(obj_id)
        return [_to_jsonable(item, seen, depth + 1, max_depth) for item in value]

    if hasattr(value, "to_dict"):
        seen.add(obj_id)
        return _to_jsonable(value.to_dict(), seen, depth + 1, max_depth)

    if hasattr(value, "__dict__"):
        seen.add(obj_id)
        return _to_jsonable(vars(value), seen, depth + 1, max_depth)

    return str(value)


def _hash_spec_payload(payload: dict[str, Any]) -> str:
    obj = _to_jsonable(payload)
    encoded = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_sha256(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized.startswith("sha256:"):
        return normalized.split(":", 1)[1]
    return normalized


def _parse_version(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version or "")
    if not parts:
        return (0,)
    return tuple(int(x) for x in parts[:6])


def _version_leq(left: str, right: str) -> bool:
    return _parse_version(left) <= _parse_version(right)


def _extract_json_objects(output: str) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                objects.append(parsed)
        except json.JSONDecodeError:
            continue
    return objects


def _decode_attestation_predicate(attestation_obj: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    payload_b64 = attestation_obj.get("payload")
    if not payload_b64:
        return None, None

    import base64

    decoded = base64.b64decode(payload_b64).decode("utf-8")
    statement = json.loads(decoded)
    predicate_type = statement.get("predicateType")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return predicate_type, None
    return predicate_type, predicate


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


async def _verify_slsa_provenance(
    *,
    custom: "client.CustomObjectsApi",
    api_client: client.ApiClient,
    namespace: str,
    app_name: str,
    image: str,
    trusted_issuers: list[str],
    policy: dict[str, Any],
) -> list[str]:
    """Verify SLSA v1.0 provenance attestation.

    Uses cosign `--type slsaprovenance1` (predicate type
    https://slsa.dev/provenance/v1). Writes
    status.verifications.slsaProvenance, emits a K8s event for the
    EventsTimelinePanel, and returns a list of policy violations
    (empty if passed).
    """
    import time
    t0 = time.monotonic()
    logger.info(
        "SLSA provenance verification started",
        extra={"event": "slsa-attestation-start", "zta_name": app_name, "zta_namespace": namespace, "image": image},
    )
    try:
        attestation = await _verify_attestation_by_type(
            image=image,
            attestation_type="slsaprovenance1",
            trusted_issuers=trusted_issuers,
        )
    except Exception as exc:
        duration_ms = int((time.monotonic() - t0) * 1000)
        reason = f"slsa-attestation-missing: {exc}"
        _record_verification(
            custom, namespace, app_name, "slsaProvenance",
            passed=False, reason=reason, durationMs=duration_ms,
        )
        logger.warning(
            "SLSA provenance attestation missing or invalid",
            extra={"event": "slsa-attestation-missing", "zta_name": app_name,
                   "zta_namespace": namespace, "duration_ms": duration_ms, "error": str(exc)},
        )
        _emit_event(api_client, namespace, app_name,
                    reason="SlsaAttestationMissing", message=reason, event_type="Warning")
        return [reason]

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

    duration_ms = int((time.monotonic() - t0) * 1000)
    if failures:
        reason = "; ".join(failures)
        _record_verification(
            custom, namespace, app_name, "slsaProvenance",
            passed=False, reason=reason, durationMs=duration_ms,
            buildType=build_type, builderId=builder_id,
            digest=_hash_json(predicate),
        )
        logger.warning(
            "SLSA provenance policy violations",
            extra={"event": "slsa-attestation-rejected", "zta_name": app_name,
                   "zta_namespace": namespace, "duration_ms": duration_ms,
                   "builder_id": builder_id, "build_type": build_type, "failures": failures},
        )
        _emit_event(api_client, namespace, app_name,
                    reason="SlsaAttestationRejected", message=reason, event_type="Warning")
        return failures

    _record_verification(
        custom, namespace, app_name, "slsaProvenance",
        passed=True, reason="ok", durationMs=duration_ms,
        buildType=build_type, builderId=builder_id,
        digest=_hash_json(predicate),
    )
    logger.info(
        "SLSA provenance verified",
        extra={"event": "slsa-attestation-verified", "zta_name": app_name,
               "zta_namespace": namespace, "duration_ms": duration_ms,
               "builder_id": builder_id, "build_type": build_type},
    )
    _emit_event(api_client, namespace, app_name,
                reason="SlsaAttestationVerified",
                message=f"builder={builder_id} buildType={build_type} ({duration_ms} ms)")
    return []


async def _verify_openvex_attestation(
    *,
    custom: "client.CustomObjectsApi",
    api_client: client.ApiClient,
    namespace: str,
    app_name: str,
    image: str,
    trusted_issuers: list[str],
    policy: dict[str, Any],
) -> list[str]:
    """Verify OpenVEX v0.2.0 attestation as a signed first-class artifact.

    Independent of the trivy-exemption code path in vex.py; this check
    only validates that a signed OpenVEX attestation exists and matches
    schema basics. Writes status.verifications.openvex and emits a K8s
    event for the EventsTimelinePanel.
    """
    import time
    t0 = time.monotonic()
    logger.info(
        "OpenVEX attestation verification started",
        extra={"event": "openvex-attestation-start", "zta_name": app_name,
               "zta_namespace": namespace, "image": image},
    )
    try:
        attestation = await _verify_attestation_by_type(
            image=image,
            attestation_type="https://openvex.dev/ns/v0.2.0",
            trusted_issuers=trusted_issuers,
        )
    except Exception as exc:
        duration_ms = int((time.monotonic() - t0) * 1000)
        reason = f"openvex-attestation-missing: {exc}"
        _record_verification(
            custom, namespace, app_name, "openvex",
            passed=False, reason=reason, durationMs=duration_ms,
        )
        logger.warning(
            "OpenVEX attestation missing or invalid",
            extra={"event": "openvex-attestation-missing", "zta_name": app_name,
                   "zta_namespace": namespace, "duration_ms": duration_ms, "error": str(exc)},
        )
        _emit_event(api_client, namespace, app_name,
                    reason="OpenVexAttestationMissing", message=reason, event_type="Warning")
        return [reason]

    predicate = attestation.get("predicate", {}) or {}
    statements = predicate.get("statements", []) or []
    failures: list[str] = []
    if not isinstance(statements, list):
        failures.append("openvex-statements-not-a-list")
    if bool(policy.get("requireStatements", False)) and not statements:
        failures.append("openvex-no-statements")

    duration_ms = int((time.monotonic() - t0) * 1000)
    if failures:
        reason = "; ".join(failures)
        _record_verification(
            custom, namespace, app_name, "openvex",
            passed=False, reason=reason, durationMs=duration_ms,
            statementCount=len(statements) if isinstance(statements, list) else 0,
        )
        logger.warning(
            "OpenVEX attestation rejected",
            extra={"event": "openvex-attestation-rejected", "zta_name": app_name,
                   "zta_namespace": namespace, "duration_ms": duration_ms, "failures": failures},
        )
        _emit_event(api_client, namespace, app_name,
                    reason="OpenVexAttestationRejected", message=reason, event_type="Warning")
        return failures

    _record_verification(
        custom, namespace, app_name, "openvex",
        passed=True, reason="ok", durationMs=duration_ms,
        statementCount=len(statements),
        digest=_hash_json(predicate),
    )
    logger.info(
        "OpenVEX attestation verified",
        extra={"event": "openvex-attestation-verified", "zta_name": app_name,
               "zta_namespace": namespace, "duration_ms": duration_ms,
               "statement_count": len(statements)},
    )
    _emit_event(api_client, namespace, app_name,
                reason="OpenVexAttestationVerified",
                message=f"{len(statements)} statements ({duration_ms} ms)")
    return []


async def _resolve_digest(image: str) -> str:
    if "@sha256:" in image:
        return image

    cmd = [COSIGN_BIN, "triangulate", image]
    returncode, stdout, stderr = await _run_cosign(cmd, timeout=VERIFY_TIMEOUT_SECONDS)
    if returncode != 0:
        raise SupplyChainPolicyError(f"Failed to resolve digest for image {image}: {stderr or stdout}")

    digest_ref = stdout.strip()
    if not digest_ref:
        raise SupplyChainPolicyError(f"Empty digest resolution for image {image}")

    return digest_ref


def _extract_sbom_packages(sbom_predicate: dict[str, Any]) -> list[dict[str, str]]:
    packages = []
    for package in sbom_predicate.get("packages", []) or []:
        name = str(package.get("name", "")).strip()
        version = str(package.get("versionInfo", "")).strip()
        if name:
            packages.append({"name": name, "version": version})
    return packages


def _validate_sbom_against_policy(packages: list[dict[str, str]], sbom_policy: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    if not bool(sbom_policy.get("enforceSBOM", False)):
        return violations

    forbidden = sbom_policy.get("forbiddenPackages", []) or []
    for rule in forbidden:
        blocked_name = str(rule.get("name", "")).strip().lower()
        max_version = str(rule.get("maxVersion", "")).strip()
        if not blocked_name:
            continue
        for package in packages:
            name = package.get("name", "").lower()
            version = package.get("version", "")
            if name != blocked_name:
                continue
            if not max_version:
                violations.append(f"forbidden package present: {name}")
                continue
            if _version_leq(version, max_version):
                violations.append(f"forbidden package/version: {name} {version} <= {max_version}")
    return violations


def _validate_spec_against_policy(spec: dict[str, Any], policy_predicate: dict[str, Any]) -> list[str]:
    violations: list[str] = []

    boundaries = (policy_predicate.get("securityBoundaries", {}) or {})
    network = (boundaries.get("network", {}) or {})

    allow_global = bool(network.get("allowGlobalInternet", False))
    allowed_egress_namespaces = {str(x).strip() for x in (network.get("allowedEgressNamespaces", []) or []) if str(x).strip()}
    restricted_ports = {int(x) for x in (network.get("restrictedPorts", []) or []) if str(x).strip()}

    requested_egress = ((spec.get("networkZeroTrust", {}) or {}).get("egressAllowedTo", []) or [])
    for item in requested_egress:
        ns = str(item.get("namespace", "")).strip()
        ports = [int(p) for p in (item.get("ports", []) or [])]

        if not allow_global and ns and (not allowed_egress_namespaces or ns not in allowed_egress_namespaces):
            violations.append(f"egress namespace '{ns}' is not allowed by attested policy")

        for port in ports:
            if port in restricted_ports:
                violations.append(f"egress port '{port}' is restricted by attested policy")

    return violations


def _validate_manifest_hash(
    spec: dict[str, Any],
    strict_manifest_hash: dict[str, Any],
    expected_hash: str,
) -> tuple[list[str], list[str], str]:
    """Returns (deny_violations, alert_violations, computed_hash).

    When strictManifestHash.enforcementAction == "Alert", manifest hash
    mismatches surface as alert_violations (audit mode) instead of
    deny_violations (blocking). Default enforcement remains "Deny".
    """
    deny: list[str] = []
    alert: list[str] = []
    if not bool(strict_manifest_hash.get("enabled", False)):
        return deny, alert, ""

    enforcement = str(strict_manifest_hash.get("enforcementAction", "Deny") or "Deny").strip()

    if not expected_hash:
        msg = "strictManifestHash enabled but attested expected_infra_hash is missing"
        if enforcement.lower() == "alert":
            alert.append(msg)
        else:
            deny.append(msg)
        return deny, alert, ""

    computed_hash = _hash_spec_payload(spec)
    if _normalize_sha256(computed_hash) != _normalize_sha256(expected_hash):
        msg = "manifest spec hash mismatch against expected_infra_hash"
        if enforcement.lower() == "alert":
            alert.append(msg)
        else:
            deny.append(msg)

    return deny, alert, computed_hash


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


def _emit_warning_event(
    api_client: client.ApiClient,
    namespace: str,
    app_name: str,
    reason: str,
    message: str,
) -> None:
    """Backwards-compat wrapper around _emit_event for existing call sites."""
    try:
        _emit_event(api_client, namespace, app_name, reason, message,
                    event_type="Warning", action="Audit")
    except Exception as exc:  # belt-and-braces
        logger.warning(
            "Failed to emit K8s warning event",
            extra={"event": "audit-event-emit-failed", "reason": reason, "error": str(exc)},
        )


def _security_policy_ref_name(spec: dict[str, Any] | None) -> str:
    if not spec:
        return ""
    policy_ref = (spec.get("securityPolicyRef", {}) or {})
    return str(policy_ref.get("name", "")).strip()


def _get_policy_by_reference(
    custom: client.CustomObjectsApi,
    spec: dict[str, Any] | None,
) -> dict[str, Any] | None:
    policy_name = _security_policy_ref_name(spec)
    if not policy_name:
        return None
    try:
        return custom.get_cluster_custom_object(
            group=GROUP,
            version=VERSION,
            plural=SCA_PLURAL,
            name=policy_name,
        )
    except ApiException as exc:
        if exc.status == 404:
            raise SupplyChainPolicyMissingError(f"Referenced SupplyChainAttestation not found: {policy_name}") from exc
        raise


def _policy_targets_zta(
    policy: dict[str, Any],
    namespace: str,
    app_name: str,
    labels: dict[str, str],
    app_spec: dict[str, Any] | None = None,
) -> bool:
    referenced_name = _security_policy_ref_name(app_spec)
    if not referenced_name:
        return False
    policy_name = str((policy.get("metadata", {}) or {}).get("name", "")).strip()
    return policy_name == referenced_name


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


def _explain_policy_target_match(
    policy: dict[str, Any],
    namespace: str,
    app_name: str,
    labels: dict[str, str],
    app_spec: dict[str, Any] | None = None,
) -> dict[str, Any]:
    meta = policy.get("metadata", {}) or {}
    policy_name = str(meta.get("name", "")).strip()
    referenced_name = _security_policy_ref_name(app_spec)

    if not referenced_name:
        return {
            "policyName": policy_name,
            "matchMode": "securityPolicyRef",
            "matched": False,
            "reasons": ["securityPolicyRef is missing on ZeroTrustApplication"],
        }

    matched = policy_name == referenced_name
    reasons = [] if matched else [f"securityPolicyRef mismatch: expected '{referenced_name}', got '{policy_name}'"]
    return {
        "policyName": policy_name,
        "matchMode": "securityPolicyRef",
        "matched": matched,
        "reasons": reasons,
    }


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


def get_matching_policy_for_application(
    api_client: client.ApiClient,
    namespace: str,
    app_name: str,
    labels: dict[str, str],
    app_spec: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    custom = client.CustomObjectsApi(api_client)
    return _get_matching_policy(custom, namespace=namespace, app_name=app_name, labels=labels, app_spec=app_spec)


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


def requires_provenance_verification(policy: dict[str, Any] | None) -> bool:
    if not policy:
        return False
    provenance = ((policy.get("spec", {}) or {}).get("provenance", {}) or {})
    return bool(provenance.get("requireVoucher", False))


def _status_patch(custom: client.CustomObjectsApi, namespace: str, name: str, patch: dict[str, Any]) -> None:
    custom.patch_namespaced_custom_object_status(
        group=GROUP,
        version=VERSION,
        namespace=namespace,
        plural=PLURAL,
        name=name,
        body={"status": patch},
    )


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
        logger.debug("status.verifications.%s patch failed (older CRD?)", key)


def apply_sanction(api_client: client.ApiClient, namespace: str, app_name: str, sanction: str) -> str:
    sanction = sanction.strip()
    apps = client.AppsV1Api(api_client)
    networking = client.NetworkingV1Api(api_client)

    if sanction == "Kill":
        try:
            apps.delete_namespaced_deployment(name=app_name, namespace=namespace)
        except ApiException as exc:
            if exc.status != 404:
                raise
        return "Killed"

    policy_name = f"{app_name}-drift-isolation"
    deny_all = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": policy_name, "namespace": namespace},
        "spec": {
            "podSelector": {"matchLabels": {"app": app_name}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        },
    }
    try:
        networking.read_namespaced_network_policy(name=policy_name, namespace=namespace)
        networking.patch_namespaced_network_policy(name=policy_name, namespace=namespace, body=deny_all)
    except ApiException as exc:
        if exc.status != 404:
            raise
        networking.create_namespaced_network_policy(namespace=namespace, body=deny_all)
    return "Isolated"


async def validate_admission_with_attestations(
    api_client: client.ApiClient,
    namespace: str,
    app_name: str,
    image: str,
    spec: dict[str, Any],
    labels: dict[str, str],
) -> dict[str, Any]:
    custom = client.CustomObjectsApi(api_client)

    matched_policy = _get_matching_policy(custom, namespace=namespace, app_name=app_name, labels=labels, app_spec=spec)
    if not matched_policy:
        diagnostics = _collect_policy_match_diagnostics(
            custom,
            namespace=namespace,
            app_name=app_name,
            labels=labels,
            app_spec=spec,
        )
        logger.info(
            "No matching SupplyChainAttestation found for application",
            extra={
                "event": "attestation-policy-missing",
                "zta_name": app_name,
                "zta_namespace": namespace,
                "candidate_count": diagnostics.get("candidateCount", 0),
            },
        )
        return {
            "securityState": "Compliant",
            "attestations": {},
            "activeViolations": [],
            "lastVerified": datetime.now(timezone.utc).isoformat(),
            "policyMatchDebug": diagnostics,
        }

    global_spec = matched_policy.get("spec", {}) or {}
    logger.info(
        "Matched SupplyChainAttestation for application",
        extra={
            "event": "attestation-policy-matched",
            "zta_name": app_name,
            "zta_namespace": namespace,
            "policy_name": str((matched_policy.get("metadata", {}) or {}).get("name", "")),
        },
    )
    trusted_issuers = [str(x).strip() for x in (global_spec.get("sourceValidation", {}) or {}).get("trustedIssuers", []) or [] if str(x).strip()]
    if not trusted_issuers:
        raise SupplyChainPolicyError("SupplyChainAttestation sourceValidation.trustedIssuers is empty")

    resolved_image = await _resolve_digest(image)

    sbom_policy = global_spec.get("sbomPolicy", {}) or {}
    policy_binding = global_spec.get("policyBinding", {}) or {}
    strict_manifest_hash = global_spec.get("strictManifestHash", {}) or {}
    slsa_policy = global_spec.get("slsaProvenancePolicy", {}) or {}
    openvex_policy = global_spec.get("openVexPolicy", {}) or {}

    sbom_packages: list[dict[str, str]] = []
    sbom_digest = ""
    sbom_predicate: dict[str, Any] = {}
    policy_predicate: dict[str, Any] = {}
    policy_digest = ""
    expected_infra_hash = ""
    computed_infra_hash = ""

    if bool(sbom_policy.get("enforceSBOM", False)):
        import time as _time_sbom
        _t0_sbom = _time_sbom.monotonic()
        logger.info(
            "SBOM attestation verification started",
            extra={"event": "attestation-sbom-start", "zta_name": app_name,
                   "zta_namespace": namespace, "image": resolved_image},
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
            _record_verification(
                custom, namespace, app_name, "sbom",
                passed=False, reason=_reason, durationMs=_duration_ms,
            )
            logger.warning(
                "SBOM attestation missing or invalid",
                extra={"event": "attestation-sbom-missing", "zta_name": app_name,
                       "zta_namespace": namespace, "duration_ms": _duration_ms, "error": str(exc)},
            )
            _emit_event(api_client, namespace, app_name,
                        reason="SbomAttestationMissing", message=_reason, event_type="Warning")
            raise
        sbom_predicate = sbom_attestation.get("predicate", {}) or {}
        sbom_packages = _extract_sbom_packages(sbom_predicate)
        sbom_digest = _hash_json(sbom_predicate)
        _duration_ms = int((_time_sbom.monotonic() - _t0_sbom) * 1000)
        _record_verification(
            custom, namespace, app_name, "sbom",
            passed=True, reason="ok", durationMs=_duration_ms,
            digest=sbom_digest,
            packageCount=len(sbom_packages),
        )
        logger.info(
            "SBOM attestation extracted",
            extra={
                "event": "attestation-sbom-extracted",
                "zta_name": app_name,
                "zta_namespace": namespace,
                "duration_ms": _duration_ms,
                "sbom_packages_count": len(sbom_packages),
                "sbom_digest": sbom_digest,
            },
        )
        _emit_event(api_client, namespace, app_name,
                    reason="SbomAttestationVerified",
                    message=f"{len(sbom_packages)} packages, digest={sbom_digest[:24]}... ({_duration_ms} ms)")

    if bool(policy_binding.get("enabled", False)):
        attestation_type = (
            str(
                policy_binding.get(
                    "requireAttestationType",
                    "https://devsecops.licenta.ro/attestations/custom-zta-policy/v1",
                )
            ).strip()
            or "https://devsecops.licenta.ro/attestations/custom-zta-policy/v1"
        )
        import time as _time_pol
        _t0_pol = _time_pol.monotonic()
        logger.info(
            "Policy attestation verification started",
            extra={"event": "attestation-policy-start", "zta_name": app_name,
                   "zta_namespace": namespace, "image": resolved_image,
                   "attestation_type": attestation_type},
        )
        try:
            policy_attestation = await _verify_attestation_by_type(
                image=resolved_image,
                attestation_type=attestation_type,
                trusted_issuers=trusted_issuers,
            )
        except Exception as exc:
            _duration_ms = int((_time_pol.monotonic() - _t0_pol) * 1000)
            _reason = f"policy-attestation-missing: {exc}"
            _record_verification(
                custom, namespace, app_name, "policyAttestation",
                passed=False, reason=_reason, durationMs=_duration_ms,
                attestationType=attestation_type,
            )
            logger.warning(
                "Policy attestation missing or invalid",
                extra={"event": "attestation-policy-missing-failed",
                       "zta_name": app_name, "zta_namespace": namespace,
                       "duration_ms": _duration_ms, "error": str(exc)},
            )
            _emit_event(api_client, namespace, app_name,
                        reason="PolicyAttestationMissing", message=_reason, event_type="Warning")
            raise
        policy_predicate = policy_attestation.get("predicate", {}) or {}
        policy_digest = _hash_json(policy_predicate)
        expected_infra_hash = str(policy_predicate.get("expected_infra_hash", "")).strip()
        _duration_ms = int((_time_pol.monotonic() - _t0_pol) * 1000)
        _record_verification(
            custom, namespace, app_name, "policyAttestation",
            passed=True, reason="ok", durationMs=_duration_ms,
            attestationType=attestation_type,
            digest=policy_digest,
            expectedInfraHash=expected_infra_hash,
        )
        _emit_event(api_client, namespace, app_name,
                    reason="PolicyAttestationVerified",
                    message=f"type={attestation_type} digest={policy_digest[:24]}... ({_duration_ms} ms)")
        logger.info(
            "Policy attestation extracted",
            extra={
                "event": "attestation-policy-extracted",
                "zta_name": app_name,
                "zta_namespace": namespace,
                "policy_digest": policy_digest,
                "expected_infra_hash": expected_infra_hash,
            },
        )

    slsa_violations: list[str] = []
    if bool(slsa_policy.get("enforceSlsa", False)):
        slsa_violations = await _verify_slsa_provenance(
            custom=custom,
            api_client=api_client,
            namespace=namespace,
            app_name=app_name,
            image=resolved_image,
            trusted_issuers=trusted_issuers,
            policy=slsa_policy,
        )

    openvex_violations: list[str] = []
    if bool(openvex_policy.get("enforceOpenVex", False)):
        openvex_violations = await _verify_openvex_attestation(
            custom=custom,
            api_client=api_client,
            namespace=namespace,
            app_name=app_name,
            image=resolved_image,
            trusted_issuers=trusted_issuers,
            policy=openvex_policy,
        )

    violations: list[str] = []
    violations.extend(slsa_violations)
    violations.extend(openvex_violations)
    alerts: list[str] = []
    violations.extend(_validate_sbom_against_policy(sbom_packages, sbom_policy))
    if policy_predicate:
        violations.extend(_validate_spec_against_policy(spec, policy_predicate))
    deny_hash, alert_hash, computed_infra_hash = _validate_manifest_hash(
        spec=spec,
        strict_manifest_hash=strict_manifest_hash,
        expected_hash=expected_infra_hash,
    )
    logger.info(
        "Manifest hash validation completed",
        extra={
            "event": "attestation-hash-validated",
            "zta_name": app_name,
            "zta_namespace": namespace,
            "strict_manifest_hash_enabled": bool(strict_manifest_hash.get("enabled", False)),
            "expected_infra_hash": expected_infra_hash,
            "computed_infra_hash": computed_infra_hash,
            "hash_violations_count": len(deny_hash),
            "hash_alerts_count": len(alert_hash),
        },
    )
    violations.extend(deny_hash)
    alerts.extend(alert_hash)

    cel_evaluations: list[dict[str, Any]] = []
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
            # downstream raise. Otherwise a denying rule would short-circuit
            # the function with `raise SupplyChainPolicyError(...)` and the
            # CelEvaluationsTable on the UI would never see why the app was
            # rejected — exactly when the user needs that diagnostic most.
            # Uses merge-patch so other attestation fields are preserved.
            try:
                _status_patch(
                    custom, namespace, app_name,
                    {"attestations": {"celEvaluations": cel_evaluations}},
                )
            except ApiException:
                logger.debug("status.attestations.celEvaluations early-patch failed")
            if cel_result.errors:
                logger.warning(
                    "CEL evaluation produced errors",
                    extra={"event": "cel-eval-errors", "errors": cel_result.errors},
                )
            violations.extend(cel_result.deny)
            for alert_msg in cel_result.alert:
                alerts.append(alert_msg)
                _emit_warning_event(
                    api_client=api_client,
                    namespace=namespace,
                    app_name=app_name,
                    reason="CelRuleAlert",
                    message=alert_msg,
                )
        except Exception as exc:
            logger.warning(
                "CEL evaluation skipped due to unexpected error",
                extra={"event": "cel-eval-skipped", "error": str(exc)},
            )

    if violations:
        raise SupplyChainPolicyError("; ".join(violations))

    security_state = "Compliant"
    if alerts:
        security_state = "Alert"
        for msg in alerts:
            _emit_warning_event(
                api_client=api_client,
                namespace=namespace,
                app_name=app_name,
                reason="ManifestHashDrift",
                message=msg,
            )
            logger.warning(
                "Audit-mode policy violation",
                extra={
                    "event": "attestation-audit-mode",
                    "zta_name": app_name,
                    "zta_namespace": namespace,
                    "violation": msg,
                },
            )

    return {
        "securityState": security_state,
        "attestations": {
            "policyName": str((matched_policy.get("metadata", {}) or {}).get("name", "")),
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


def check_runtime_drift(
    api_client: client.ApiClient,
    namespace: str,
    app_name: str,
    current_spec: dict[str, Any],
    current_status: dict[str, Any],
    labels: dict[str, str],
) -> tuple[bool, list[str], str]:
    custom = client.CustomObjectsApi(api_client)
    policy = _get_matching_policy(
        custom,
        namespace=namespace,
        app_name=app_name,
        labels=labels,
        app_spec=current_spec,
    )
    if not policy:
        return True, [], "Alert"

    runtime = (policy.get("spec", {}) or {}).get("runtimeEnforcement", {}) or {}
    strict_manifest_hash = (policy.get("spec", {}) or {}).get("strictManifestHash", {}) or {}
    if not bool(runtime.get("enabled", False)):
        return True, [], str(runtime.get("onPolicyDrift", "Alert"))

    sanction = str(runtime.get("onPolicyDrift", "Isolate"))
    saved_policy = ((current_status.get("attestations", {}) or {}).get("policyPredicate", {}) or {})
    expected_infra_hash = str(((current_status.get("attestations", {}) or {}).get("expectedInfraHash", ""))).strip()
    if not saved_policy:
        return True, [], sanction

    violations = _validate_spec_against_policy(current_spec, saved_policy)
    deny_hash, alert_hash, _ = _validate_manifest_hash(
        spec=current_spec,
        strict_manifest_hash=strict_manifest_hash,
        expected_hash=expected_infra_hash,
    )
    violations.extend(deny_hash)
    # alert_hash is non-blocking by design: at runtime, an Alert-mode hash
    # mismatch must not trigger Isolate/Kill sanctions. It is surfaced via
    # the periodic reconcile event emission upstream.
    return (len(violations) == 0), violations, sanction


def reevaluate_policy_targets(api_client: client.ApiClient, policy: dict[str, Any]) -> list[dict[str, Any]]:
    custom = client.CustomObjectsApi(api_client)

    spec = policy.get("spec", {}) or {}
    sbom_policy = spec.get("sbomPolicy", {}) or {}
    strict_manifest_hash = spec.get("strictManifestHash", {}) or {}
    runtime = spec.get("runtimeEnforcement", {}) or {}
    sanction = str(runtime.get("onPolicyDrift", "Isolate"))

    ztas = custom.list_cluster_custom_object(group=GROUP, version=VERSION, plural=PLURAL)
    items = ztas.get("items", []) or []

    results = []
    for item in items:
        meta = item.get("metadata", {}) or {}
        app_name = str(meta.get("name", ""))
        app_ns = str(meta.get("namespace", ""))
        app_labels = (meta.get("labels", {}) or {})
        status = item.get("status", {}) or {}
        spec_app = item.get("spec", {}) or {}
        attestations = status.get("attestations", {}) or {}

        if not _policy_targets_zta(policy, namespace=app_ns, app_name=app_name, labels=app_labels, app_spec=spec_app):
            continue

        violations: list[str] = []

        saved_packages = attestations.get("sbomPackages", []) or []
        violations.extend(_validate_sbom_against_policy(saved_packages, sbom_policy))

        saved_policy = attestations.get("policyPredicate", {}) or {}
        if saved_policy:
            violations.extend(_validate_spec_against_policy(spec_app, saved_policy))

        saved_expected_hash = str(attestations.get("expectedInfraHash", "")).strip()
        deny_hash, _alert_hash, _ = _validate_manifest_hash(
            spec=spec_app,
            strict_manifest_hash=strict_manifest_hash,
            expected_hash=saved_expected_hash,
        )
        violations.extend(deny_hash)

        results.append(
            {
                "name": app_name,
                "namespace": app_ns,
                "violations": violations,
                "sanction": sanction,
            }
        )

    return results


@kopf.on.update(GROUP, VERSION, SCA_PLURAL)
def on_supply_chain_policy_update(body: dict, **_: Any) -> None:
    reconcile_id = new_reconcile_id()
    uid = (body.get("metadata", {}) or {}).get("uid", "unknown")
    sca_name = str((body.get("metadata", {}) or {}).get("name", "unknown"))
    adapter = logging.LoggerAdapter(
        logger,
        ctx(name=sca_name, namespace="cluster", uid=uid, reconcile_id=reconcile_id, phase="ContinuousCompliance"),
    )

    api_client = client.ApiClient()
    custom = client.CustomObjectsApi(api_client)

    try:
        adapter.info("SupplyChainAttestation reconciliation triggered", extra={"event": "sca-reconcile-start"})
        evaluations = reevaluate_policy_targets(api_client=api_client, policy=body)
        adapter.info(
            "SupplyChainAttestation target evaluation completed",
            extra={"event": "sca-reconcile-evaluated", "targets_count": len(evaluations)},
        )
        for entry in evaluations:
            app_name = entry["name"]
            app_ns = entry["namespace"]
            violations = entry["violations"]
            sanction = entry["sanction"]

            if not app_name or not app_ns:
                continue

            if violations:
                state = apply_sanction(api_client=api_client, namespace=app_ns, app_name=app_name, sanction=sanction)
                _status_patch(
                    custom,
                    app_ns,
                    app_name,
                    {
                        "securityState": state,
                        "activeViolations": violations,
                        "lastVerified": datetime.now(timezone.utc).isoformat(),
                    },
                )
                adapter.warning(
                    "Application became non-compliant after policy update",
                    extra={"event": "sca-drift-enforcement", "resource_kind": "ZeroTrustApplication", "resource_name": app_name},
                )
            else:
                _status_patch(
                    custom,
                    app_ns,
                    app_name,
                    {
                        "securityState": "Compliant",
                        "activeViolations": [],
                        "lastVerified": datetime.now(timezone.utc).isoformat(),
                    },
                )
    except ApiException as exc:
        adapter.exception("Continuous compliance update failed", extra={"event": "sca-update-error"})
        raise kopf.TemporaryError(str(exc), delay=30) from exc


@kopf.on.create(GROUP, VERSION, SCA_PLURAL)
def on_supply_chain_policy_create(body: dict, **kwargs: Any) -> None:
    on_supply_chain_policy_update(body=body, **kwargs)
