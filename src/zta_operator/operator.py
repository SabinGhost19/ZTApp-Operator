import logging
from typing import Any

import kopf
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from .config import GROUP, KIND, PLURAL, VERSION
from .logging_utils import configure_logging, ctx, new_reconcile_id
from .resources import (
    apply_object,
    build_authorization_policy,
    build_deployment,
    build_falco_rule_configmap,
    build_network_policy,
    build_service,
    build_wasm_plugin,
)
from .supply_chain_attestation import (
    SupplyChainPolicyError,
    apply_sanction,
    check_runtime_drift,
    get_matching_policy_for_application,
    requires_provenance_verification,
    resolve_effective_supply_chain_policy,
    validate_admission_with_attestations,
)
from .supply_chain import SupplyChainError, verify_supply_chain
from .talon import TalonConfigError, delete_talon_rule, upsert_talon_rule
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


@kopf.on.startup()
def startup_fn(**_: Any) -> None:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()


@kopf.on.create(GROUP, VERSION, PLURAL)
@kopf.on.field(GROUP, VERSION, PLURAL, field="spec")
@kopf.on.field(GROUP, VERSION, PLURAL, field="status.trustLevel")
def reconcile(spec: dict, name: str, namespace: str, body: dict, patch: dict, **_: Any) -> None:
    reconcile_id = new_reconcile_id()
    uid = body.get("metadata", {}).get("uid", "unknown")

    adapter = logging.LoggerAdapter(logger, ctx(name=name, namespace=namespace, uid=uid, reconcile_id=reconcile_id, phase="Validating"))

    api_client = client.ApiClient()
    custom = client.CustomObjectsApi(api_client)
    core = client.CoreV1Api(api_client)
    current_status = body.get("status", {}) or {}

    desired_spec = body.get("spec", {}) or dict(spec)

    image = str(desired_spec.get("image", "")).strip()
    replicas = int(desired_spec.get("replicas", 1))

    network = desired_spec.get("networkZeroTrust", {})
    ingress_allowed_from = network.get("ingressAllowedFrom", []) or []
    egress_allowed_to = network.get("egressAllowedTo", []) or []

    waf = desired_spec.get("wafConfig", {})
    waf_mode = str(waf.get("mode", "Block")).strip()
    app_profile = str(waf.get("appProfile", "REST-API")).strip()

    runtime = desired_spec.get("runtimeSecurity", {})
    allowed_paths = runtime.get("allowedPaths", []) or []
    labels = ((body.get("metadata", {}) or {}).get("labels", {}) or {})
    trust_level = str(current_status.get("trustLevel", "Untrusted") or "Untrusted")
    vulnerability_violations: list[str] = []
    vulnerability_details: dict[str, Any] = {}

    try:
        _status_patch(custom, namespace, name, {"phase": "Validating", "lastError": "", "trustLevel": trust_level})

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
                    "trustLevel": trust_level,
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
                    "trustLevel": trust_level,
                    "securityState": state,
                    "activeViolations": _unique_strings(violations),
                    "lastError": "; ".join(_unique_strings(violations)),
                },
            )
            adapter.warning("Runtime policy drift detected and sanctioned", extra={"event": "runtime-drift-enforced"})
            raise kopf.PermanentError("Runtime policy drift detected")

        adapter.info("Starting supply-chain verification", extra={"event": "supply-chain-start"})
        result = verify_supply_chain(
            image=image,
            require_signature=bool(effective_policy.get("requireSignature", True)),
            trusted_identities=list(effective_policy.get("trustedIdentities", [])),
            max_vulnerabilities=str(effective_policy.get("maxAllowedSeverity", "Medium")),
            fail_on_fixable=bool(effective_policy.get("failOnFixable", False)),
        )
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
                        "trustLevel": trust_level,
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

        attestation_status = current_status if current_status.get("attestations") else validate_admission_with_attestations(
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
                "trustLevel": trust_level,
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
            build_service(name=name, namespace=namespace, owner=owner),
        ]

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

        if runtime:
            falco_rule_name = _falco_rule_name(namespace=namespace, name=name)
            upsert_talon_rule(core=core, app_namespace=namespace, app_name=name, falco_rule_name=falco_rule_name)
            adapter.info("Patched Talon rules ConfigMap", extra={"event": "talon-configmap-upsert"})

        _status_patch(
            custom,
            namespace,
            name,
            {
                "phase": "Running",
                "lastError": "",
                "trustLevel": trust_level,
                "securityState": effective_security_state,
                "attestations": attestations,
                "policyMatchDebug": policy_match_debug,
                "activeViolations": effective_violations,
                "lastVerified": attestation_status.get("lastVerified"),
                "provenance": current_status.get("provenance", {}),
                "details": vulnerability_details,
            },
        )
        adapter.info("Reconciliation completed", extra={"event": "reconcile-success", "phase": "Running"})

    except SupplyChainPolicyError as exc:
        _status_patch(
            custom,
            namespace,
            name,
            {
                "phase": "Failed_SupplyChain",
                "trustLevel": trust_level,
                "securityState": "NonCompliant",
                "activeViolations": _unique_strings([str(exc)]),
                "lastError": str(exc),
            },
        )
        adapter.exception("Policy attestation validation failed", extra={"event": "attestation-policy-failed"})
        raise kopf.PermanentError(str(exc)) from exc

    except (SupplyChainError, TalonConfigError, ApiException, ValueError) as exc:
        _status_patch(custom, namespace, name, {"phase": "Degraded", "lastError": str(exc), "trustLevel": trust_level})
        adapter.exception("Reconciliation failed", extra={"event": "reconcile-error"})
        raise kopf.TemporaryError(str(exc), delay=30) from exc


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
