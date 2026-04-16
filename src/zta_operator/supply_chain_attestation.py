import hashlib
import json
import logging
import re
import subprocess
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

logger = configure_logging()


class SupplyChainPolicyError(Exception):
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


def _verify_attestation_by_type(image: str, attestation_type: str, trusted_issuers: list[str]) -> dict[str, Any]:
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
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=VERIFY_TIMEOUT_SECONDS)
        if result.returncode != 0:
            last_error = result.stderr or result.stdout
            continue

        for obj in _extract_json_objects(result.stdout):
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


def _resolve_digest(image: str) -> str:
    if "@sha256:" in image:
        return image

    cmd = [COSIGN_BIN, "triangulate", image]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=VERIFY_TIMEOUT_SECONDS)
    if result.returncode != 0:
        raise SupplyChainPolicyError(f"Failed to resolve digest for image {image}: {result.stderr or result.stdout}")

    digest_ref = result.stdout.strip()
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
) -> tuple[list[str], str]:
    violations: list[str] = []
    if not bool(strict_manifest_hash.get("enabled", False)):
        return violations, ""

    if not expected_hash:
        return ["strictManifestHash enabled but attested expected_infra_hash is missing"], ""

    computed_hash = _hash_spec_payload(spec)
    if _normalize_sha256(computed_hash) != _normalize_sha256(expected_hash):
        violations.append("manifest spec hash mismatch against expected_infra_hash")

    return violations, computed_hash


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
            raise SupplyChainPolicyError(f"Referenced SupplyChainAttestation not found: {policy_name}") from exc
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


def validate_admission_with_attestations(
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

    resolved_image = _resolve_digest(image)

    sbom_policy = global_spec.get("sbomPolicy", {}) or {}
    policy_binding = global_spec.get("policyBinding", {}) or {}
    strict_manifest_hash = global_spec.get("strictManifestHash", {}) or {}

    sbom_packages: list[dict[str, str]] = []
    sbom_digest = ""
    policy_predicate: dict[str, Any] = {}
    policy_digest = ""
    expected_infra_hash = ""
    computed_infra_hash = ""

    if bool(sbom_policy.get("enforceSBOM", False)):
        sbom_attestation = _verify_attestation_by_type(
            image=resolved_image,
            attestation_type="spdxjson",
            trusted_issuers=trusted_issuers,
        )
        sbom_predicate = sbom_attestation.get("predicate", {}) or {}
        sbom_packages = _extract_sbom_packages(sbom_predicate)
        sbom_digest = _hash_json(sbom_predicate)
        logger.info(
            "SBOM attestation extracted",
            extra={
                "event": "attestation-sbom-extracted",
                "zta_name": app_name,
                "zta_namespace": namespace,
                "sbom_packages_count": len(sbom_packages),
                "sbom_digest": sbom_digest,
            },
        )

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
        policy_attestation = _verify_attestation_by_type(
            image=resolved_image,
            attestation_type=attestation_type,
            trusted_issuers=trusted_issuers,
        )
        policy_predicate = policy_attestation.get("predicate", {}) or {}
        policy_digest = _hash_json(policy_predicate)
        expected_infra_hash = str(policy_predicate.get("expected_infra_hash", "")).strip()
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

    violations: list[str] = []
    violations.extend(_validate_sbom_against_policy(sbom_packages, sbom_policy))
    if policy_predicate:
        violations.extend(_validate_spec_against_policy(spec, policy_predicate))
    hash_violations, computed_infra_hash = _validate_manifest_hash(
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
            "hash_violations_count": len(hash_violations),
        },
    )
    violations.extend(hash_violations)

    if violations:
        raise SupplyChainPolicyError("; ".join(violations))

    return {
        "securityState": "Compliant",
        "attestations": {
            "policyName": str((matched_policy.get("metadata", {}) or {}).get("name", "")),
            "resolvedImage": resolved_image,
            "sbomDigest": sbom_digest,
            "policyDigest": policy_digest,
            "sbomPackages": sbom_packages,
            "policyPredicate": policy_predicate,
            "expectedInfraHash": expected_infra_hash,
            "computedInfraHash": computed_infra_hash,
        },
        "activeViolations": [],
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
    hash_violations, _ = _validate_manifest_hash(
        spec=current_spec,
        strict_manifest_hash=strict_manifest_hash,
        expected_hash=expected_infra_hash,
    )
    violations.extend(hash_violations)
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
        hash_violations, _ = _validate_manifest_hash(
            spec=spec_app,
            strict_manifest_hash=strict_manifest_hash,
            expected_hash=saved_expected_hash,
        )
        violations.extend(hash_violations)

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
