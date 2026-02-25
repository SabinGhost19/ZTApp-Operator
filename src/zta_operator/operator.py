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
    validate_admission_with_attestations,
)
from .supply_chain import SupplyChainError, verify_supply_chain
from .talon import TalonConfigError, delete_talon_rule, upsert_talon_rule
from . import zerotrust_secret  # noqa: F401
from . import supply_chain_attestation  # noqa: F401

logger = configure_logging()


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
@kopf.on.update(GROUP, VERSION, PLURAL)
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

    supply = desired_spec.get("supplyChain", {})
    require_signature = bool(supply.get("requireSignature", True))
    allowed_signer = str(supply.get("allowedSigner", "")).strip()
    max_vuln = str(supply.get("maxVulnerabilities", "Medium")).strip()

    network = desired_spec.get("networkZeroTrust", {})
    ingress_allowed_from = network.get("ingressAllowedFrom", []) or []
    egress_allowed_to = network.get("egressAllowedTo", []) or []

    waf = desired_spec.get("wafConfig", {})
    waf_mode = str(waf.get("mode", "Block")).strip()
    app_profile = str(waf.get("appProfile", "REST-API")).strip()

    runtime = desired_spec.get("runtimeSecurity", {})
    allowed_paths = runtime.get("allowedPaths", []) or []
    labels = ((body.get("metadata", {}) or {}).get("labels", {}) or {})

    try:
        _status_patch(custom, namespace, name, {"phase": "Validating", "lastError": ""})

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
                    "activeViolations": violations,
                    "lastError": "; ".join(violations),
                },
            )
            adapter.warning("Runtime policy drift detected and sanctioned", extra={"event": "runtime-drift-enforced"})
            raise kopf.PermanentError("Runtime policy drift detected")

        adapter.info("Starting supply-chain verification", extra={"event": "supply-chain-start"})
        result = verify_supply_chain(
            image=image,
            require_signature=require_signature,
            allowed_signer=allowed_signer,
            max_vulnerabilities=max_vuln,
        )
        if not result.success:
            _status_patch(
                custom,
                namespace,
                name,
                {
                    "phase": "Failed_SupplyChain",
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

        _status_patch(
            custom,
            namespace,
            name,
            {
                "phase": "Provisioning",
                "lastError": "",
                "securityState": attestation_status.get("securityState", "Compliant"),
                "attestations": attestation_status.get("attestations", {}),
                "activeViolations": attestation_status.get("activeViolations", []),
                "lastVerified": attestation_status.get("lastVerified"),
            },
        )

        owner = _owner_reference(body)
        objects = [
            build_deployment(name=name, namespace=namespace, image=image, replicas=replicas, allowed_paths=allowed_paths, owner=owner),
            build_service(name=name, namespace=namespace, owner=owner),
            build_authorization_policy(name=name, namespace=namespace, ingress_allowed_from=ingress_allowed_from, owner=owner),
            build_network_policy(
                name=name,
                namespace=namespace,
                ingress_allowed_from=ingress_allowed_from,
                egress_allowed_to=egress_allowed_to,
                owner=owner,
            ),
            build_wasm_plugin(name=name, namespace=namespace, mode=waf_mode, app_profile=app_profile, owner=owner),
            build_falco_rule_configmap(name=name, namespace=namespace, image=image, allowed_paths=allowed_paths, owner=owner),
        ]

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
                "securityState": attestation_status.get("securityState", "Compliant"),
                "attestations": attestation_status.get("attestations", {}),
                "activeViolations": attestation_status.get("activeViolations", []),
                "lastVerified": attestation_status.get("lastVerified"),
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
                "securityState": "NonCompliant",
                "activeViolations": [str(exc)],
                "lastError": str(exc),
            },
        )
        adapter.exception("Policy attestation validation failed", extra={"event": "attestation-policy-failed"})
        raise kopf.PermanentError(str(exc)) from exc

    except (SupplyChainError, TalonConfigError, ApiException, ValueError) as exc:
        _status_patch(custom, namespace, name, {"phase": "Degraded", "lastError": str(exc)})
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
