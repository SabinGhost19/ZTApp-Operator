import asyncio
import hashlib
import json
import logging
from typing import Any

import kopf
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from .config import (
    GROUP,
    KIND,
    PLURAL,
    VERSION,
    INGRESS_CLASS_NAME,
    INGRESS_PATH,
    INGRESS_PATH_TYPE,
    OAUTH2_AUTH_URL,
    OAUTH2_AUTH_SIGNIN,
    OAUTH2_AUTH_RESPONSE_HEADERS,
    OAUTH2_GROUPS_HEADER,
    OAUTH2_GROUPS_HEADER_FALLBACK,
    OAUTH2_PROXY_SERVICE_NAME,
    OAUTH2_PROXY_NAMESPACE,
    OAUTH2_PROXY_PORT,
    OAUTH2_INGRESS_PATH,
)
from .logging_utils import configure_logging, ctx, new_reconcile_id
from .resources import (
    apply_object,
    build_authorization_policy,
    build_deployment,
    build_falco_rule_configmap,
    build_external_name_service,
    build_ingress,
    build_network_policy,
    build_oauth2_ingress,
    build_service,
    build_wasm_plugin,
)
from .supply_chain_attestation import (
    SupplyChainPolicyError,
    SupplyChainPolicyMissingError,
    apply_sanction,
    check_runtime_drift,
    get_matching_policy_for_application,
    requires_provenance_verification,
    resolve_effective_supply_chain_policy,
    validate_admission_with_attestations,
    _emit_event as _emit_zta_event,
)
from .supply_chain import SupplyChainError, verify_supply_chain
from .talon import TalonConfigError, TalonInfrastructureMissingError, delete_talon_rule, upsert_talon_rule
from . import zerotrust_secret  # noqa: F401
from . import supply_chain_attestation  # noqa: F401

logger = configure_logging()


VULNERABILITY_FAILURE_REASONS = {
    "trivy-threshold-exceeded",
    "trivy-fixable-vulnerability-found",
}


def _unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique.append(normalized)
    return unique


def _status_patch(custom: client.CustomObjectsApi, namespace: str, name: str, patch: dict[str, Any]) -> None:
    custom.patch_namespaced_custom_object_status(
        group=GROUP,
        version=VERSION,
        namespace=namespace,
        plural=PLURAL,
        name=name,
        body={"status": patch},
    )


_ERROR_RING_BUFFER_MAX = 20


def _classify_api_exception(exc: ApiException) -> tuple[str, bool]:
    """Map a Kubernetes ApiException to (code, retryable).

    Codes are stable strings consumed by the UI; retryable signals
    whether the controller should keep retrying or escalate to
    PermanentError.
    """
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
        # Race conditions on this field are acceptable because the
        # operator is the only writer.
        obj = custom.get_namespaced_custom_object(
            group=GROUP, version=VERSION, namespace=namespace,
            plural=PLURAL, name=name,
        )
        existing = list(((obj or {}).get("status", {}) or {}).get("errors", []) or [])
        existing.append(entry)
        if len(existing) > _ERROR_RING_BUFFER_MAX:
            existing = existing[-_ERROR_RING_BUFFER_MAX:]
        _status_patch(custom, namespace, name, {"errors": existing})
    except ApiException as patch_exc:
        logger.warning(
            "status.errors patch failed",
            extra={"event": "record-error-failed",
                   "patch_status": getattr(patch_exc, "status", 0),
                   "original_code": code, "original_message": message[:256]},
        )
    except Exception as patch_exc:  # noqa: BLE001 — last resort
        logger.warning(
            "status.errors patch failed (non-API)",
            extra={"event": "record-error-failed",
                   "error": str(patch_exc),
                   "original_code": code, "original_message": message[:256]},
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


def _owner_reference(body: dict[str, Any]) -> dict:
    metadata = body.get("metadata", {})
    return {
        "apiVersion": f"{GROUP}/{VERSION}",
        "kind": KIND,
        "name": metadata["name"],
        "uid": metadata["uid"],
        "controller": True,
        "blockOwnerDeletion": True,
    }


def _falco_rule_name(namespace: str, name: str) -> str:
    return f"Unauthorized_Write_{namespace}_{name}".replace("-", "_")


SPEC_HASH_ANNOTATION = "zta.devsecops/spec-reconcile-hash"


def _write_spec_hash_annotation(
    custom: client.CustomObjectsApi,
    namespace: str,
    name: str,
    spec_hash: str,
) -> None:
    """Persist the spec hash as a metadata annotation.

    Belt-and-braces with the schema-aware status.specReconcileHash field:
    annotations are always accepted by the API server even if the CRD
    schema wasn't upgraded to include the new status field. The metadata
    PATCH is on the main resource (not the status subresource).
    """
    try:
        custom.patch_namespaced_custom_object(
            group=GROUP,
            version=VERSION,
            namespace=namespace,
            plural=PLURAL,
            name=name,
            body={"metadata": {"annotations": {SPEC_HASH_ANNOTATION: spec_hash}}},
        )
    except ApiException:
        # Non-fatal — the status field is the primary watermark.
        pass


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
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()


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


async def _reconcile_impl(spec: dict, name: str, namespace: str, body: dict, patch: dict, **_: Any) -> None:
    reconcile_id = new_reconcile_id()
    uid = body.get("metadata", {}).get("uid", "unknown")

    adapter = logging.LoggerAdapter(logger, ctx(name=name, namespace=namespace, uid=uid, reconcile_id=reconcile_id, phase="Validating"))

    api_client = client.ApiClient()
    custom = client.CustomObjectsApi(api_client)
    core = client.CoreV1Api(api_client)
    current_status = body.get("status", {}) or {}

    desired_spec = body.get("spec", {}) or dict(spec)

    # ----------------------------------------------------------------------
    # Idempotency short-circuit
    # ----------------------------------------------------------------------
    # If the spec hash matches what we converged on last time, and the ZTA
    # is in a healthy terminal state, skip the entire pipeline. This breaks
    # the spurious reconcile loops we see when kopf field watchers fire on
    # no-op status patches from provenance-enforcer.
    #
    # Two storage locations are checked, in order:
    #   1. status.specReconcileHash (requires CRD schema field; primary)
    #   2. metadata.annotations["zta.devsecops/spec-reconcile-hash"]
    #      (fallback when CRD schema hasn't been upgraded yet — annotations
    #      are always accepted by the API server)
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

    image = str(desired_spec.get("image", "")).strip()
    replicas = int(desired_spec.get("replicas", 1))

    network = desired_spec.get("networkZeroTrust", {})
    ingress_allowed_from = network.get("ingressAllowedFrom", []) or []
    egress_allowed_to = network.get("egressAllowedTo", []) or []

    waf = desired_spec.get("wafConfig", {})
    waf_mode = str(waf.get("mode", "Block")).strip()
    app_profile = str(waf.get("appProfile", "REST-API")).strip()

    ingress_spec = desired_spec.get("ingress", {}) or {}
    ingress_enabled = bool(ingress_spec.get("enabled", False))
    ingress_host = str(ingress_spec.get("host", "")).strip()
    ingress_class = str(ingress_spec.get("className", "") or INGRESS_CLASS_NAME).strip()
    ingress_path = str(ingress_spec.get("path", "") or INGRESS_PATH).strip()
    ingress_path_type = str(ingress_spec.get("pathType", "") or INGRESS_PATH_TYPE).strip()
    service_port = int(ingress_spec.get("servicePort", 80))
    oauth2_enabled = bool(ingress_spec.get("oauth2Enabled", True))
    oauth2_service_name = str(ingress_spec.get("oauth2ServiceName", "") or OAUTH2_PROXY_SERVICE_NAME).strip()
    oauth2_service_namespace = str(ingress_spec.get("oauth2ServiceNamespace", "") or OAUTH2_PROXY_NAMESPACE).strip()
    oauth2_service_port = int(ingress_spec.get("oauth2ServicePort", OAUTH2_PROXY_PORT))
    oauth2_ingress_path = str(ingress_spec.get("oauth2IngressPath", "") or OAUTH2_INGRESS_PATH).strip()
    groups_header = str(ingress_spec.get("groupsHeader", "") or OAUTH2_GROUPS_HEADER).strip()
    groups_header_fallback = str(ingress_spec.get("groupsHeaderFallback", "") or OAUTH2_GROUPS_HEADER_FALLBACK).strip()

    runtime = desired_spec.get("runtimeSecurity", {})
    allowed_paths = runtime.get("allowedPaths", []) or []
    labels = ((body.get("metadata", {}) or {}).get("labels", {}) or {})
    trust_level = str(current_status.get("trustLevel", "Untrusted") or "Untrusted")
    vulnerability_violations: list[str] = []
    vulnerability_details: dict[str, Any] = {}

    try:
        _status_patch(custom, namespace, name, {"phase": "Validating", "lastError": ""})

        matched_policy = get_matching_policy_for_application(
            api_client=api_client,
            namespace=namespace,
            app_name=name,
            labels=labels,
            app_spec=desired_spec,
        )
        effective_policy = resolve_effective_supply_chain_policy(matched_policy, desired_spec)
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

        compliant, violations, sanction = check_runtime_drift(
            api_client=api_client,
            namespace=namespace,
            app_name=name,
            current_spec=desired_spec,
            current_status=current_status,
            labels=labels,
        )
        if not compliant:
            state = apply_sanction(api_client=api_client, namespace=namespace, app_name=name, sanction=sanction)
            _status_patch(
                custom,
                namespace,
                name,
                {
                    "phase": "Degraded",
                    "securityState": state,
                    "activeViolations": _unique_strings(violations),
                    "lastError": "; ".join(_unique_strings(violations)),
                },
            )
            adapter.warning("Runtime policy drift detected and sanctioned", extra={"event": "runtime-drift-enforced"})
            raise kopf.PermanentError("Runtime policy drift detected")

        import time as _time_sc
        _t0_sc = _time_sc.monotonic()
        adapter.info("Starting supply-chain verification", extra={"event": "supply-chain-start", "image": image})
        result = await verify_supply_chain(
            image=image,
            require_signature=bool(effective_policy.get("requireSignature", True)),
            trusted_identities=list(effective_policy.get("trustedIdentities", [])),
            max_vulnerabilities=str(effective_policy.get("maxAllowedSeverity", "Medium")),
            fail_on_fixable=bool(effective_policy.get("failOnFixable", False)),
        )
        _sc_duration_ms = int((_time_sc.monotonic() - _t0_sc) * 1000)
        # Disambiguate which check failed: verify_supply_chain runs cosign
        # first, then trivy. A cosign-* reason means trivy never ran.
        _cosign_required = bool(effective_policy.get("requireSignature", True))
        _is_cosign_failure = result.reason.startswith("cosign-")
        if _cosign_required:
            _cosign_passed = not _is_cosign_failure
            _record_verification(
                custom, namespace, name, "cosign",
                passed=_cosign_passed,
                reason=result.reason if _is_cosign_failure else "ok",
                # Total supply-chain duration is the best proxy we have
                # without splitting cosign/trivy timings inside the helper.
                durationMs=_sc_duration_ms,
            )
            if _cosign_passed:
                adapter.info(
                    "Cosign keyless signature verified",
                    extra={"event": "cosign-verification-passed", "duration_ms": _sc_duration_ms},
                )
                _emit_zta_event(api_client, namespace, name,
                                reason="CosignVerified",
                                message=f"keyless signature ok ({_sc_duration_ms} ms)")
            else:
                adapter.warning(
                    "Cosign signature verification failed",
                    extra={"event": "cosign-verification-failed", "reason": result.reason,
                           "duration_ms": _sc_duration_ms},
                )
                _emit_zta_event(api_client, namespace, name,
                                reason="CosignVerificationFailed",
                                message=f"{result.reason} ({_sc_duration_ms} ms)",
                                event_type="Warning")
        if not _is_cosign_failure:
            _record_verification(
                custom, namespace, name, "trivy",
                passed=result.success,
                reason=result.reason,
                durationMs=_sc_duration_ms,
                highest=(result.details or {}).get("highest"),
                threshold=(result.details or {}).get("threshold"),
                vexExempted=(result.details or {}).get("vexExempted"),
                # CVE-level detail so the UI can show exactly what failed and why.
                counts=(result.details or {}).get("counts"),
                findings=(result.details or {}).get("findings"),
            )
            if result.success:
                adapter.info(
                    "Trivy vulnerability scan completed within policy threshold",
                    extra={"event": "trivy-scan-passed",
                           "duration_ms": _sc_duration_ms,
                           "highest": (result.details or {}).get("highest"),
                           "threshold": (result.details or {}).get("threshold")},
                )
                _emit_zta_event(api_client, namespace, name,
                                reason="TrivyScanPassed",
                                message=f"highest={(result.details or {}).get('highest','NONE')} threshold={(result.details or {}).get('threshold','')} ({_sc_duration_ms} ms)")
            else:
                _emit_zta_event(api_client, namespace, name,
                                reason="TrivyScanRejected",
                                message=f"{result.reason} ({_sc_duration_ms} ms)",
                                event_type="Warning")
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
                _status_patch(
                    custom,
                    namespace,
                    name,
                    {
                        "phase": "Failed_SupplyChain",
                        "securityState": state,
                        "activeViolations": _unique_strings(active_violations),
                        "lastError": result.reason,
                        "details": result.details,
                    },
                )
                adapter.error(
                    "Supply-chain verification failed",
                    extra={"event": "supply-chain-failed"},
                )
                raise kopf.PermanentError(f"Supply chain verification failed: {result.reason}")

        attestation_status = current_status if current_status.get("attestations") else await validate_admission_with_attestations(
            api_client=api_client,
            namespace=namespace,
            app_name=name,
            image=image,
            spec=desired_spec,
            labels=labels,
        )

        attestations = attestation_status.get("attestations", {}) or {}
        policy_match_debug = attestation_status.get("policyMatchDebug", {}) or {}
        if attestations:
            adapter.info(
                "Supply-chain attestation validation completed",
                extra={
                    "event": "attestation-validated",
                    "policy_name": attestations.get("policyName", ""),
                    "resolved_image": attestations.get("resolvedImage", ""),
                    "expected_infra_hash": attestations.get("expectedInfraHash", ""),
                    "computed_infra_hash": attestations.get("computedInfraHash", ""),
                },
            )
        else:
            adapter.info(
                "No matching SupplyChainAttestation found for application",
                extra={
                    "event": "attestation-policy-missing",
                    "candidate_count": policy_match_debug.get("candidateCount", 0),
                    "candidates": policy_match_debug.get("candidates", []),
                },
            )

        effective_security_state = attestation_status.get("securityState", "Compliant")
        effective_violations = _unique_strings(list(attestation_status.get("activeViolations", [])))
        if vulnerability_violations:
            effective_security_state = "Alert"
            effective_violations = _unique_strings(effective_violations + vulnerability_violations)

        _status_patch(
            custom,
            namespace,
            name,
            {
                "phase": "Provisioning",
                "lastError": "",
                "securityState": effective_security_state,
                "attestations": attestations,
                "policyMatchDebug": policy_match_debug,
                "activeViolations": effective_violations,
                "lastVerified": attestation_status.get("lastVerified"),
                "provenance": current_status.get("provenance", {}),
                "details": vulnerability_details,
            },
        )

        owner = _owner_reference(body)
        objects = [
            build_deployment(
                name=name,
                namespace=namespace,
                image=image,
                replicas=replicas,
                allowed_paths=allowed_paths,
                owner=owner,
                runtime_security_enabled=bool(runtime),
            ),
            build_service(name=name, namespace=namespace, owner=owner, port=service_port),
        ]

        if ingress_enabled:
            if not ingress_host:
                raise ValueError("spec.ingress.host is required when ingress.enabled is true")

            auth_signin = str(ingress_spec.get("authSignin", "") or OAUTH2_AUTH_SIGNIN).strip()
            if "{host}" in auth_signin:
                auth_signin = auth_signin.format(host=ingress_host)

            auth_url = str(ingress_spec.get("authUrl", "") or OAUTH2_AUTH_URL).strip()
            auth_headers = str(ingress_spec.get("authResponseHeaders", "") or OAUTH2_AUTH_RESPONSE_HEADERS).strip()

            if oauth2_enabled:
                if not oauth2_service_namespace:
                    raise ValueError("spec.ingress.oauth2ServiceNamespace is required when oauth2Enabled is true")

                oauth2_external_name = f"{oauth2_service_name}.{oauth2_service_namespace}.svc.cluster.local"
                objects.append(
                    build_external_name_service(
                        name=oauth2_service_name,
                        namespace=namespace,
                        owner=owner,
                        external_name=oauth2_external_name,
                        port=oauth2_service_port,
                    )
                )
                objects.append(
                    build_oauth2_ingress(
                        name=f"{name}-oauth2",
                        namespace=namespace,
                        owner=owner,
                        host=ingress_host,
                        class_name=ingress_class,
                        path=oauth2_ingress_path,
                        service_name=oauth2_service_name,
                        service_port=oauth2_service_port,
                    )
                )

            objects.append(
                build_ingress(
                    name=f"{name}-ingress",
                    namespace=namespace,
                    owner=owner,
                    host=ingress_host,
                    service_name=name,
                    service_port=service_port,
                    class_name=ingress_class,
                    path=ingress_path,
                    path_type=ingress_path_type,
                    auth_url=auth_url,
                    auth_signin=auth_signin,
                    auth_response_headers=auth_headers,
                    jit_group=f"jit-access-{name}",
                    groups_header=groups_header,
                    groups_header_fallback=groups_header_fallback,
                )
            )

        if ingress_allowed_from or egress_allowed_to:
            objects.append(
                build_network_policy(
                    name=name,
                    namespace=namespace,
                    ingress_allowed_from=ingress_allowed_from,
                    egress_allowed_to=egress_allowed_to,
                    owner=owner,
                )
            )

        # Istio resources are opt-in: when wafConfig is absent, skip service-mesh provisioning.
        if waf:
            objects.append(
                build_authorization_policy(
                    name=name,
                    namespace=namespace,
                    ingress_allowed_from=ingress_allowed_from,
                    owner=owner,
                )
            )
            objects.append(
                build_wasm_plugin(name=name, namespace=namespace, mode=waf_mode, app_profile=app_profile, owner=owner)
            )

        # Falco/Talon resources are opt-in: when runtimeSecurity is absent, skip runtime enforcement provisioning.
        if runtime:
            objects.append(
                build_falco_rule_configmap(name=name, namespace=namespace, image=image, allowed_paths=allowed_paths, owner=owner)
            )

        for obj in objects:
            apply_object(api_client=api_client, obj=obj)
            adapter.info(
                "Applied resource",
                extra={
                    "event": "resource-applied",
                    "resource_kind": obj["kind"],
                    "resource_name": obj["metadata"]["name"],
                },
            )

        # Default runtime enforcement state: not declared by the spec.
        runtime_enforcement_status: dict[str, Any] = {
            "requested": bool(runtime),
            "installed": None,                 # tri-state: None=unknown, True/False=concrete
            "talonRulePatched": False,
            "missing": [],
            "reason": "",
        }
        if runtime:
            falco_rule_name = _falco_rule_name(namespace=namespace, name=name)
            try:
                upsert_talon_rule(core=core, app_namespace=namespace, app_name=name, falco_rule_name=falco_rule_name)
                adapter.info("Patched Talon rules ConfigMap", extra={"event": "talon-configmap-upsert"})
                runtime_enforcement_status.update({
                    "installed": True,
                    "talonRulePatched": True,
                })
            except TalonInfrastructureMissingError as exc:
                # Falco/Talon stack is not installed. The Pod is already
                # running by this point — degrade to a clearly-labeled
                # warning instead of aborting the reconcile. UI surfaces
                # this state via status.runtimeEnforcement.installed=false.
                adapter.warning(
                    "Runtime enforcement infrastructure is not installed in this cluster",
                    extra={
                        "event": "runtime-enforcement-infrastructure-missing",
                        "missing": list(exc.missing),
                    },
                )
                _record_error(
                    custom, namespace, name,
                    code="runtime-infrastructure-missing",
                    message=str(exc),
                    phase="RuntimeEnforcement",
                    retryable=False,
                    details={"missing": list(exc.missing),
                             "hint": "Install Falco + falco-talon Helm charts to enable Talon-based runtime enforcement."},
                )
                runtime_enforcement_status.update({
                    "installed": False,
                    "missing": list(exc.missing),
                    "reason": str(exc),
                })
            except TalonConfigError as exc:
                # Detection rule (the Falco ConfigMap) is already applied; the
                # Talon response rule failed transiently (5xx / RBAC /
                # conflict-retries-exhausted). Surface a partial state
                # ("detection active, response pending retry") before the outer
                # handler marks Degraded and kopf retries the whole reconcile.
                runtime_enforcement_status.update({
                    "installed": None,
                    "talonRulePatched": False,
                    "reason": f"{exc}; detection rule active, response pending retry",
                })
                _status_patch(custom, namespace, name, {"runtimeEnforcement": runtime_enforcement_status})
                raise


        _status_patch(
            custom,
            namespace,
            name,
            {
                "phase": "Running",
                "lastError": "",
                "securityState": effective_security_state,
                "attestations": attestations,
                "policyMatchDebug": policy_match_debug,
                "activeViolations": effective_violations,
                "lastVerified": attestation_status.get("lastVerified"),
                "provenance": current_status.get("provenance", {}),
                "details": vulnerability_details,
                # Runtime enforcement state (Falco+Talon). When the stack
                # is not installed, installed=false + missing=[...] tells
                # the UI to render an informational banner rather than a
                # red error chip.
                "runtimeEnforcement": runtime_enforcement_status,
                # Spec hash watermark — next reconcile with the same spec
                # will short-circuit at the top of _reconcile_impl.
                "specReconcileHash": spec_hash,
            },
        )
        # Mirror the hash to a metadata annotation so the watermark survives
        # even if the CRD schema hasn't been upgraded to declare the new
        # status field (in that case the API server would silently drop
        # status.specReconcileHash and the loop would never break).
        _write_spec_hash_annotation(custom, namespace, name, spec_hash)
        adapter.info("Reconciliation completed", extra={"event": "reconcile-success", "phase": "Running", "spec_hash": spec_hash[:16]})

        # Asynchronous GUAC ingestion — decoupled from the reconcile loop
        # so a slow OCI pull / GUAC collector roundtrip never delays Pod
        # creation. The worker thread PATCHes status.guacIngestionStatus
        # to Completed/Failed when finished; the UI surfaces this as a
        # spinner that resolves to a checkmark.
        try:
            from .guac_client import trigger_guac_ingestion

            started = trigger_guac_ingestion(image=image, namespace=namespace, app_name=name)
            if started:
                _status_patch(
                    custom,
                    namespace,
                    name,
                    {
                        "guacIngestionStatus": "InProgress",
                        "guacIngestionMessage": "Pulling SBOM/VEX from OCI and ingesting into GUAC knowledge graph...",
                    },
                )
                adapter.info(
                    "GUAC ingestion worker started (async)",
                    extra={"event": "guac-worker-started", "image": image},
                )
            else:
                _status_patch(
                    custom,
                    namespace,
                    name,
                    {
                        "guacIngestionStatus": "Disabled",
                        "guacIngestionMessage": "GUAC_GRAPHQL_URL is not configured for this operator.",
                    },
                )
        except Exception as exc:
            adapter.info(
                "GUAC ingest skipped",
                extra={"event": "guac-ingest-skipped", "error": str(exc)},
            )

    except SupplyChainPolicyMissingError as exc:
        # Declarative recovery: SCA may be applied after ZTA (Helm/ArgoCD
        # don't guarantee order). Surface a Pending state and retry every
        # 15s so the system self-heals when the SCA appears.
        _status_patch(
            custom,
            namespace,
            name,
            {
                "phase": "Pending",
                "securityState": "WaitingForPolicy",
                "activeViolations": [],
                "lastError": str(exc),
            },
        )
        _record_error(custom, namespace, name,
                      code="sca-policy-missing", message=str(exc),
                      phase="Validating", retryable=True)
        adapter.info("Referenced SCA not yet present; retrying", extra={"event": "sca-policy-missing"})
        raise kopf.TemporaryError(str(exc), delay=15) from exc

    except SupplyChainPolicyError as exc:
        _status_patch(
            custom,
            namespace,
            name,
            {
                "phase": "Failed_SupplyChain",
                "securityState": "NonCompliant",
                "activeViolations": _unique_strings([str(exc)]),
                "lastError": str(exc),
            },
        )
        _record_error(custom, namespace, name,
                      code="attestation-policy-violation", message=str(exc),
                      phase="Attestation", retryable=False)
        adapter.exception("Policy attestation validation failed", extra={"event": "attestation-policy-failed"})
        raise kopf.PermanentError(str(exc)) from exc

    except ApiException as exc:
        code, retryable = _classify_api_exception(exc)
        body_text = str(getattr(exc, "body", "") or "")[:512]
        _status_patch(custom, namespace, name,
                      {"phase": "Degraded", "lastError": f"{code}: {exc.reason}"})
        _record_error(custom, namespace, name,
                      code=code, message=str(exc.reason or "Kubernetes API error"),
                      phase="K8sApi", retryable=retryable,
                      details={"status": int(getattr(exc, "status", 0) or 0),
                               "body": body_text})
        adapter.exception("Kubernetes API call failed during reconcile",
                          extra={"event": "k8s-api-error", "code": code,
                                 "status": int(getattr(exc, "status", 0) or 0)})
        if not retryable:
            raise kopf.PermanentError(f"{code}: {exc.reason}") from exc
        raise kopf.TemporaryError(f"{code}: {exc.reason}", delay=30) from exc

    except SupplyChainError as exc:
        _status_patch(custom, namespace, name,
                      {"phase": "Degraded", "lastError": str(exc)})
        _record_error(custom, namespace, name,
                      code="supply-chain-error", message=str(exc),
                      phase="SupplyChain", retryable=True)
        adapter.exception("Supply-chain check error",
                          extra={"event": "supply-chain-error"})
        raise kopf.TemporaryError(str(exc), delay=30) from exc

    except TalonConfigError as exc:
        _status_patch(custom, namespace, name,
                      {"phase": "Degraded", "lastError": str(exc)})
        _record_error(custom, namespace, name,
                      code="talon-config-error", message=str(exc),
                      phase="RuntimeEnforcement", retryable=True)
        adapter.exception("Talon configuration error",
                          extra={"event": "talon-config-error"})
        raise kopf.TemporaryError(str(exc), delay=30) from exc

    except ValueError as exc:
        # Spec validation failures (missing required fields, bad types).
        # Permanent — re-running with the same spec will fail again.
        _status_patch(custom, namespace, name,
                      {"phase": "Failed_SupplyChain", "lastError": str(exc)})
        _record_error(custom, namespace, name,
                      code="spec-validation-error", message=str(exc),
                      phase="Validating", retryable=False)
        adapter.exception("Spec validation error", extra={"event": "spec-validation-error"})
        raise kopf.PermanentError(str(exc)) from exc

    except asyncio.TimeoutError as exc:
        msg = f"reconcile timed out: {exc}"
        _status_patch(custom, namespace, name,
                      {"phase": "Degraded", "lastError": msg})
        _record_error(custom, namespace, name,
                      code="reconcile-timeout", message=msg,
                      phase="Unknown", retryable=True)
        adapter.exception("Reconcile timed out", extra={"event": "reconcile-timeout"})
        raise kopf.TemporaryError(msg, delay=30) from exc

    except kopf.TemporaryError:
        raise
    except kopf.PermanentError:
        raise
    except Exception as exc:  # noqa: BLE001 — defensive catch-all
        # Unanticipated path: log full traceback, snapshot a short detail
        # for the UI, retry with backoff. This is the safety net for
        # "impossible" errors — programming bugs, sudden library changes,
        # transient OS issues — so the operator never crashes silently.
        import traceback as _tb
        tb_excerpt = _tb.format_exc(limit=6)
        msg = f"unexpected error: {type(exc).__name__}: {exc}"
        try:
            _status_patch(custom, namespace, name,
                          {"phase": "Degraded", "lastError": msg[:512]})
        except Exception:
            pass
        _record_error(custom, namespace, name,
                      code="reconcile-unexpected",
                      message=str(exc) or type(exc).__name__,
                      phase="Unknown", retryable=True,
                      details={"exceptionType": type(exc).__name__,
                               "traceback": tb_excerpt[-1500:]})
        adapter.exception("Unexpected error during reconcile",
                          extra={"event": "reconcile-unexpected",
                                 "exception_type": type(exc).__name__})
        raise kopf.TemporaryError(msg, delay=60) from exc


@kopf.on.create(GROUP, VERSION, PLURAL)
async def reconcile_on_create(spec: dict, name: str, namespace: str, body: dict, patch: dict, **kwargs: Any) -> None:
    await _reconcile_impl(spec=spec, name=name, namespace=namespace, body=body, patch=patch, **kwargs)


@kopf.on.field(GROUP, VERSION, PLURAL, field="spec")
async def reconcile_on_spec(spec: dict, name: str, namespace: str, body: dict, patch: dict, **kwargs: Any) -> None:
    await _reconcile_impl(spec=spec, name=name, namespace=namespace, body=body, patch=patch, **kwargs)


@kopf.on.field(GROUP, VERSION, PLURAL, field="status.trustLevel")
async def reconcile_on_trust_level(
    spec: dict,
    name: str,
    namespace: str,
    body: dict,
    patch: dict,
    old: Any,
    new: Any,
    **kwargs: Any,
) -> None:
    old_value = str(old or "").strip().lower()
    new_value = str(new or "").strip().lower()

    # Only run once when provenance-enforcer moves trustLevel to Verified.
    if new_value != "verified" or old_value == new_value:
        return

    await _reconcile_impl(spec=spec, name=name, namespace=namespace, body=body, patch=patch, **kwargs)


@kopf.on.delete(GROUP, VERSION, PLURAL)
def cleanup(spec: dict, name: str, namespace: str, body: dict, **_: Any) -> None:
    reconcile_id = new_reconcile_id()
    uid = body.get("metadata", {}).get("uid", "unknown")
    adapter = logging.LoggerAdapter(logger, ctx(name=name, namespace=namespace, uid=uid, reconcile_id=reconcile_id, phase="Deleting"))

    api_client = client.ApiClient()
    core = client.CoreV1Api(api_client)

    try:
        delete_talon_rule(core=core, app_namespace=namespace, app_name=name)
        adapter.info("Removed Talon rule from ConfigMap", extra={"event": "talon-configmap-delete"})
    except TalonConfigError:
        adapter.exception("Failed to cleanup Talon rule", extra={"event": "cleanup-error"})
        raise
