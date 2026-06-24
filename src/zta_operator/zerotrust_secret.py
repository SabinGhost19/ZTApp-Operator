import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

import kopf
from kubernetes import client
from kubernetes.client.exceptions import ApiException

from .config import (
    EXTERNAL_SECRETS_GROUP,
    EXTERNAL_SECRETS_PLURAL,
    EXTERNAL_SECRETS_VERSION,
    GROUP,
    VERSION,
    ZTS_HEALTH_INTERVAL,
    ZTS_KIND,
    ZTS_LABEL_NAME,
    ZTS_LABEL_NAMESPACE,
    ZTS_MANAGED_LABEL_KEY,
    ZTS_MANAGED_LABEL_VALUE,
    ZTS_PLURAL,
)
from .logging_utils import configure_logging, ctx, new_reconcile_id

logger = configure_logging()


class ZeroTrustSecretError(Exception):
    pass


# (connect, read) timeouts on every synchronous K8s call so a stalled API server
# can't block a reconcile/timer thread forever (kopf's async timeout does not
# cover the blocking kubernetes-client I/O).
_K8S_TIMEOUT = (3.05, 10)

# Status phases written to .status.phase.
_PHASE_VALIDATING = "Validating"
_PHASE_PROVISIONING = "Provisioning"
_PHASE_RUNNING = "Running"
_PHASE_DEGRADED = "Degraded"
_PHASE_BLOCKED = "BlockedBySecurity"

# Condition types surfaced on .status.conditions[] (K8s-style conditions).
_COND_TRUSTED = "Trusted"  # target ZeroTrustApplication still satisfies the trust gate
_COND_SYNCED = "Synced"    # backing ExternalSecret reports a successful Vault sync
_COND_READY = "Ready"      # ZTS fully provisioned AND the target K8s Secret exists


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_error(exc: Exception) -> str:
    """Human-readable error for status.lastError. For a Kubernetes ApiException
    this extracts the API `status.message` (e.g. 'deployments.apps "x" not found')
    instead of dumping the full HTTP response (headers + body) into the field."""
    if isinstance(exc, ApiException):
        message = ""
        try:
            body = json.loads(exc.body) if exc.body else {}
            message = str(body.get("message", "")).strip()
        except (ValueError, TypeError):
            message = ""
        message = message or (exc.reason or "Kubernetes API error")
        status = getattr(exc, "status", "") or ""
        return f"{status} {message}".strip()
    return str(exc)


def _condition(cond_type: str, ok: bool, reason: str, message: str, existing: list[dict] | None) -> dict:
    """Build one status condition, preserving lastTransitionTime when the
    boolean state is unchanged (so transition timestamps stay meaningful)."""
    status = "True" if ok else "False"
    prev = next((c for c in (existing or []) if c.get("type") == cond_type), None)
    if prev and prev.get("status") == status and prev.get("lastTransitionTime"):
        last_transition = prev["lastTransitionTime"]
    else:
        last_transition = _now_iso()
    return {
        "type": cond_type,
        "status": status,
        "reason": reason or "",
        "message": (message or "")[:512],
        "lastTransitionTime": last_transition,
    }


def _zts_status_patch(custom: client.CustomObjectsApi, namespace: str, name: str, patch: dict[str, Any]) -> None:
    custom.patch_namespaced_custom_object_status(
        group=GROUP,
        version=VERSION,
        namespace=namespace,
        plural=ZTS_PLURAL,
        name=name,
        body={"status": patch},
        _request_timeout=_K8S_TIMEOUT,
    )


def _owner_reference(body: dict[str, Any]) -> dict:
    metadata = body.get("metadata", {})
    return {
        "apiVersion": f"{GROUP}/{VERSION}",
        "kind": ZTS_KIND,
        "name": metadata["name"],
        "uid": metadata["uid"],
        "controller": True,
        "blockOwnerDeletion": True,
    }


def _normalize_vault_path(remote_path: str) -> str:
    value = remote_path.strip().strip("/")
    for prefix in ("secret/data/", "secret/"):
        if value.startswith(prefix):
            return value[len(prefix) :]
    return value


def _sanitize_name(name: str) -> str:
    normalized = re.sub(r"[^a-z0-9-]", "-", name.lower())
    normalized = re.sub(r"-+", "-", normalized).strip("-")
    return normalized[:63] if normalized else "zts"


def _volume_name(zts_name: str, local_key: str, index: int) -> str:
    base = _sanitize_name(f"zts-{zts_name}-{local_key}-{index}")
    return base[:63]


def _target_secret_name(zts_name: str, spec: dict) -> str:
    return str(spec.get("targetSecretName", zts_name)).strip() or zts_name


def _build_external_secret(
    zts_name: str,
    namespace: str,
    body: dict,
    spec: dict,
    owner: dict,
) -> tuple[dict, str]:
    lifecycle = spec.get("lifecycle", {}) or {}
    secret_data = spec.get("secretData", {}) or {}

    refresh_interval = str(lifecycle.get("refreshInterval", "10m")).strip()
    remote_path = _normalize_vault_path(str(secret_data.get("remotePath", "")).strip())
    if not remote_path:
        raise ZeroTrustSecretError("spec.secretData.remotePath is required")

    mapping = secret_data.get("mapping", []) or []
    if not mapping:
        raise ZeroTrustSecretError("spec.secretData.mapping must contain at least one item")

    target_secret_name = _target_secret_name(zts_name, spec)

    data_entries = []
    for item in mapping:
        remote_key = str(item.get("remoteKey", "")).strip()
        local_key = str(item.get("localKey", "")).strip()
        if not remote_key or not local_key:
            raise ZeroTrustSecretError("Each mapping item must include remoteKey and localKey")

        data_entries.append(
            {
                "secretKey": local_key,
                "remoteRef": {
                    "key": remote_path,
                    "property": remote_key,
                },
            }
        )

    store_ref = spec.get("secretStoreRef", {}) or {}
    store_name = str(store_ref.get("name", "vault-backend")).strip() or "vault-backend"
    store_kind = str(store_ref.get("kind", "ClusterSecretStore")).strip() or "ClusterSecretStore"

    external_secret = {
        "apiVersion": f"{EXTERNAL_SECRETS_GROUP}/{EXTERNAL_SECRETS_VERSION}",
        "kind": "ExternalSecret",
        "metadata": {
            "name": zts_name,
            "namespace": namespace,
            "labels": {
                ZTS_MANAGED_LABEL_KEY: ZTS_MANAGED_LABEL_VALUE,
                ZTS_LABEL_NAME: zts_name,
                ZTS_LABEL_NAMESPACE: namespace,
            },
            "ownerReferences": [owner],
        },
        "spec": {
            "refreshInterval": refresh_interval,
            "secretStoreRef": {
                "kind": store_kind,
                "name": store_name,
            },
            "target": {
                "name": target_secret_name,
                "creationPolicy": "Owner",
                "template": {
                    "metadata": {
                        "labels": {
                            ZTS_MANAGED_LABEL_KEY: ZTS_MANAGED_LABEL_VALUE,
                            ZTS_LABEL_NAME: zts_name,
                            ZTS_LABEL_NAMESPACE: namespace,
                        }
                    }
                },
            },
            "data": data_entries,
        },
    }

    return external_secret, target_secret_name


def _read_workload(
    kind: str,
    namespace: str,
    name: str,
    apps: client.AppsV1Api,
    api_client: client.ApiClient,
) -> dict:
    if kind == "Deployment":
        obj = apps.read_namespaced_deployment(name=name, namespace=namespace, _request_timeout=_K8S_TIMEOUT)
    elif kind == "StatefulSet":
        obj = apps.read_namespaced_stateful_set(name=name, namespace=namespace, _request_timeout=_K8S_TIMEOUT)
    else:
        obj = apps.read_namespaced_daemon_set(name=name, namespace=namespace, _request_timeout=_K8S_TIMEOUT)
    return api_client.sanitize_for_serialization(obj)


def _get_target(
    namespace: str,
    target_workload: dict,
    apps: client.AppsV1Api,
    api_client: client.ApiClient,
) -> tuple[str, str, dict]:
    kind = str(target_workload.get("kind", "")).strip()
    name = str(target_workload.get("name", "")).strip()
    workload_ns = str(target_workload.get("namespace", namespace)).strip() or namespace

    if kind not in {"Deployment", "StatefulSet", "DaemonSet"}:
        raise ZeroTrustSecretError("targetWorkload.kind must be one of Deployment, StatefulSet, DaemonSet")
    if not name:
        raise ZeroTrustSecretError("targetWorkload.name is required")

    return kind, workload_ns, _read_workload(kind, workload_ns, name, apps, api_client)


def _patch_target(kind: str, namespace: str, name: str, patch_body: dict, apps: client.AppsV1Api) -> None:
    if kind == "Deployment":
        apps.patch_namespaced_deployment(name=name, namespace=namespace, body=patch_body, _request_timeout=_K8S_TIMEOUT)
    elif kind == "StatefulSet":
        apps.patch_namespaced_stateful_set(name=name, namespace=namespace, body=patch_body, _request_timeout=_K8S_TIMEOUT)
    else:
        apps.patch_namespaced_daemon_set(name=name, namespace=namespace, body=patch_body, _request_timeout=_K8S_TIMEOUT)


def _inject_mapping_to_workload(
    zts_name: str,
    target_secret_name: str,
    mapping: list[dict],
    target_kind: str,
    target_namespace: str,
    target_name: str,
    apps: client.AppsV1Api,
    api_client: client.ApiClient,
) -> None:
    # Re-read the workload immediately before patching to shrink the
    # read-modify-write window (validation + ExternalSecret upsert happen between
    # the reconcile's first read and this point). A concurrent writer's additions
    # survive: the strategic-merge patch below merges containers/env by name and
    # only touches the containers we inject into.
    target_obj = _read_workload(target_kind, target_namespace, target_name, apps, api_client)
    pod_spec = target_obj["spec"]["template"].get("spec", {})
    containers = pod_spec.get("containers", [])
    if not containers:
        raise ZeroTrustSecretError("Target workload has no containers")

    default_container = containers[0].get("name")
    if not default_container:
        raise ZeroTrustSecretError("Target workload first container has no name")

    by_name = {c.get("name"): c for c in containers if c.get("name")}
    volumes = pod_spec.get("volumes", []) or []
    touched: set[str] = set()

    for index, item in enumerate(mapping):
        local_key = str(item.get("localKey", "")).strip()
        value_type = str(item.get("type", "")).strip()
        container_name = str(item.get("containerName", "")).strip() or default_container

        container = by_name.get(container_name)
        if container is None:
            raise ZeroTrustSecretError(
                f"Target container {container_name!r} not found in workload {target_name}"
            )
        touched.add(container_name)

        if container.get("env") is None:
            container["env"] = []
        env = container["env"]
        if container.get("volumeMounts") is None:
            container["volumeMounts"] = []
        volume_mounts = container["volumeMounts"]

        if value_type == "EnvVar":
            desired_env = {
                "name": local_key,
                "valueFrom": {
                    "secretKeyRef": {
                        "name": target_secret_name,
                        "key": local_key,
                    }
                },
            }
            existing_index = next((i for i, e in enumerate(env) if e.get("name") == local_key), None)
            if existing_index is None:
                env.append(desired_env)
            else:
                env[existing_index] = desired_env

        elif value_type == "VolumeMount":
            mount_path = str(item.get("mountPath", "")).strip()
            if not mount_path:
                raise ZeroTrustSecretError("mountPath is required when mapping.type is VolumeMount")

            volume_name = _volume_name(zts_name=zts_name, local_key=local_key, index=index)
            desired_volume = {
                "name": volume_name,
                "secret": {
                    "secretName": target_secret_name,
                    "items": [{"key": local_key, "path": local_key}],
                },
            }
            desired_mount = {
                "name": volume_name,
                "mountPath": mount_path,
                "readOnly": True,
            }

            existing_vol_index = next((i for i, v in enumerate(volumes) if v.get("name") == volume_name), None)
            if existing_vol_index is None:
                volumes.append(desired_volume)
            else:
                volumes[existing_vol_index] = desired_volume

            existing_mount_index = next((i for i, m in enumerate(volume_mounts) if m.get("name") == volume_name), None)
            if existing_mount_index is None:
                volume_mounts.append(desired_mount)
            else:
                volume_mounts[existing_mount_index] = desired_mount
        else:
            raise ZeroTrustSecretError("mapping.type must be EnvVar or VolumeMount")

    injected_marker_key = f"zta.devsecops/injected-{_sanitize_name(zts_name)}"

    patch_containers = [
        {
            "name": cn,
            "env": by_name[cn].get("env", []),
            "volumeMounts": by_name[cn].get("volumeMounts", []),
        }
        for cn in sorted(touched)
    ]

    # Patch ONLY our marker key (not the full re-read annotations map). Strategic
    # merge merges annotation maps key-by-key, so concurrent annotation writes
    # from other controllers are preserved instead of being clobbered by a
    # read-modify-write of the whole map.
    patch_body = {
        "spec": {
            "template": {
                "metadata": {"annotations": {injected_marker_key: "true"}},
                "spec": {
                    "volumes": volumes,
                    "containers": patch_containers,
                },
            }
        }
    }

    _patch_target(kind=target_kind, namespace=target_namespace, name=target_name, patch_body=patch_body, apps=apps)


def _resolve_application_reference(namespace: str, spec: dict) -> tuple[str, str]:
    application_ref = spec.get("applicationRef", {}) or {}
    app_name = str(application_ref.get("name", "")).strip()
    app_namespace = str(application_ref.get("namespace", namespace)).strip() or namespace
    if app_name:
        return app_name, app_namespace

    target_workload = spec.get("targetWorkload", {}) or {}
    fallback_name = str(target_workload.get("name", "")).strip()
    fallback_namespace = str(target_workload.get("namespace", namespace)).strip() or namespace
    if fallback_name:
        return fallback_name, fallback_namespace

    raise ZeroTrustSecretError("applicationRef.name or targetWorkload.name is required")


def _check_trust(custom: client.CustomObjectsApi, namespace: str, spec: dict) -> tuple[bool, bool, str]:
    """Non-raising trust evaluation shared by the admission-time validator and
    the periodic re-evaluator.

    Returns (require_verified, trusted, detail). Raises only on a non-404 K8s API
    error reading the ZeroTrustApplication.
    """
    ztc = spec.get("zeroTrustConditions", {}) or {}
    require_verified = bool(ztc.get("requireVerifiedStatus", False))
    if not require_verified:
        return False, True, "trust gating disabled"

    target_name, target_namespace = _resolve_application_reference(namespace=namespace, spec=spec)
    try:
        zta = custom.get_namespaced_custom_object(
            group=GROUP,
            version=VERSION,
            namespace=target_namespace,
            plural="zerotrustapplications",
            name=target_name,
            _request_timeout=_K8S_TIMEOUT,
        )
    except ApiException as exc:
        if exc.status == 404:
            return True, False, f"No ZeroTrustApplication found for target workload {target_namespace}/{target_name}"
        raise

    trust_level = str((zta.get("status", {}) or {}).get("trustLevel", "Untrusted") or "Untrusted")
    if trust_level != "Verified":
        return True, False, f"target ZeroTrustApplication trustLevel is {trust_level}"
    return True, True, "Verified"


def _validate_zero_trust_conditions(namespace: str, spec: dict, ztc: dict, custom: client.CustomObjectsApi) -> None:
    if not ztc:
        return

    if ztc.get("timeBasedAccess", {}).get("enabled", False):
        raise ZeroTrustSecretError("timeBasedAccess.enabled=true is not implemented in this version")

    require_verified, trusted, detail = _check_trust(custom, namespace, spec)
    if require_verified and not trusted:
        # A missing ZTA is a configuration error (Degraded); a present-but-untrusted
        # ZTA is an explicit security block (BlockedBySecurity).
        if detail.startswith("No ZeroTrustApplication"):
            raise ZeroTrustSecretError(detail)
        raise ZeroTrustSecretError(
            f"BlockedBySecurity: requireVerifiedStatus=true but {detail}"
        )


def _upsert_external_secret(custom: client.CustomObjectsApi, namespace: str, external_secret: dict) -> None:
    name = external_secret["metadata"]["name"]
    try:
        custom.get_namespaced_custom_object(
            group=EXTERNAL_SECRETS_GROUP,
            version=EXTERNAL_SECRETS_VERSION,
            namespace=namespace,
            plural=EXTERNAL_SECRETS_PLURAL,
            name=name,
            _request_timeout=_K8S_TIMEOUT,
        )
        custom.patch_namespaced_custom_object(
            group=EXTERNAL_SECRETS_GROUP,
            version=EXTERNAL_SECRETS_VERSION,
            namespace=namespace,
            plural=EXTERNAL_SECRETS_PLURAL,
            name=name,
            body=external_secret,
            _request_timeout=_K8S_TIMEOUT,
        )
    except ApiException as exc:
        if exc.status != 404:
            raise
        custom.create_namespaced_custom_object(
            group=EXTERNAL_SECRETS_GROUP,
            version=EXTERNAL_SECRETS_VERSION,
            namespace=namespace,
            plural=EXTERNAL_SECRETS_PLURAL,
            body=external_secret,
            _request_timeout=_K8S_TIMEOUT,
        )


def _delete_external_secret(custom: client.CustomObjectsApi, namespace: str, name: str) -> bool:
    """Delete the backing ExternalSecret (hard revoke). ESO cascade-deletes the
    K8s Secret it owns (target.creationPolicy=Owner). Idempotent: a missing ES is
    treated as already-revoked."""
    try:
        custom.delete_namespaced_custom_object(
            group=EXTERNAL_SECRETS_GROUP,
            version=EXTERNAL_SECRETS_VERSION,
            namespace=namespace,
            plural=EXTERNAL_SECRETS_PLURAL,
            name=name,
            _request_timeout=_K8S_TIMEOUT,
        )
        return True
    except ApiException as exc:
        if exc.status == 404:
            return False
        raise


def _external_secret_ready(custom: client.CustomObjectsApi, namespace: str, name: str) -> tuple[bool | None, str, str]:
    """Read the backing ExternalSecret's Ready condition.

    Returns (ready, reason, message): ready is True/False, or None when the ES is
    missing or has not published a Ready condition yet (still settling)."""
    try:
        es = custom.get_namespaced_custom_object(
            group=EXTERNAL_SECRETS_GROUP,
            version=EXTERNAL_SECRETS_VERSION,
            namespace=namespace,
            plural=EXTERNAL_SECRETS_PLURAL,
            name=name,
            _request_timeout=_K8S_TIMEOUT,
        )
    except ApiException as exc:
        if exc.status == 404:
            return None, "Missing", "Backing ExternalSecret not found"
        raise

    conditions = (es.get("status", {}) or {}).get("conditions", []) or []
    ready = next((c for c in conditions if c.get("type") == "Ready"), None)
    if not ready:
        return None, "Pending", "ExternalSecret has no Ready condition yet"
    is_ready = str(ready.get("status", "")).strip() == "True"
    return is_ready, str(ready.get("reason", "") or ""), str(ready.get("message", "") or "")


def _secret_exists(core: client.CoreV1Api, namespace: str, name: str) -> bool:
    try:
        core.read_namespaced_secret(name=name, namespace=namespace, _request_timeout=_K8S_TIMEOUT)
        return True
    except ApiException as exc:
        if exc.status == 404:
            return False
        raise


def _evaluate_status(
    custom: client.CustomObjectsApi,
    core: client.CoreV1Api,
    namespace: str,
    name: str,
    spec: dict,
    existing_conditions: list[dict] | None,
) -> dict:
    """Compute the real ZTS status from live cluster state — never a blind 'Running'.

    Order matters (zero-trust): trust is evaluated first. On trust loss while
    requireVerifiedStatus is set, the backing ExternalSecret is deleted (hard
    revoke → ESO cascade-deletes the K8s Secret) and the phase becomes
    BlockedBySecurity. Otherwise the phase reflects whether ESO actually synced
    the value from Vault (ExternalSecret Ready condition) AND whether the target
    K8s Secret exists. A ZTS pointing at a non-existent Vault path therefore
    surfaces as Degraded with an actionable lastError instead of false-healthy.

    Returns a status patch dict; may delete the ExternalSecret as a side effect.
    """
    target_secret = _target_secret_name(name, spec)
    require_verified, trusted, trust_detail = _check_trust(custom, namespace, spec)

    if require_verified and not trusted:
        _delete_external_secret(custom, namespace, name)
        return {
            "phase": _PHASE_BLOCKED,
            "lastError": f"BlockedBySecurity: {trust_detail}",
            "targetSecretName": target_secret,
            "conditions": [
                _condition(_COND_TRUSTED, False, "TrustLost", trust_detail, existing_conditions),
                _condition(_COND_SYNCED, False, "Revoked", "ExternalSecret deleted due to trust loss", existing_conditions),
                _condition(_COND_READY, False, "Revoked", "Secret access revoked", existing_conditions),
            ],
        }

    ready, reason, message = _external_secret_ready(custom, namespace, name)
    secret_present = _secret_exists(core, namespace, target_secret)

    trusted_cond = _condition(
        _COND_TRUSTED, True, "Verified" if require_verified else "NotRequired", trust_detail, existing_conditions
    )

    if ready is True and secret_present:
        phase, last_error = _PHASE_RUNNING, ""
        synced_cond = _condition(_COND_SYNCED, True, reason or "SecretSynced", message or "Synced from Vault", existing_conditions)
        ready_cond = _condition(_COND_READY, True, "SecretAvailable", f"Secret {target_secret} present and synced", existing_conditions)
    elif ready is True and not secret_present:
        phase, last_error = _PHASE_PROVISIONING, ""
        synced_cond = _condition(_COND_SYNCED, True, reason or "SecretSynced", message, existing_conditions)
        ready_cond = _condition(_COND_READY, False, "SecretPending", f"ExternalSecret ready but Secret {target_secret} not present yet", existing_conditions)
    elif ready is False:
        phase = _PHASE_DEGRADED
        last_error = f"ExternalSecret sync failing ({reason}): {message}".strip()
        synced_cond = _condition(_COND_SYNCED, False, reason or "SecretSyncError", message, existing_conditions)
        ready_cond = _condition(_COND_READY, False, "SyncError", last_error, existing_conditions)
    elif reason == "Missing":
        phase = _PHASE_DEGRADED
        last_error = "Backing ExternalSecret is missing — re-apply the ZeroTrustSecret to re-provision"
        synced_cond = _condition(_COND_SYNCED, False, "Missing", last_error, existing_conditions)
        ready_cond = _condition(_COND_READY, False, "Missing", last_error, existing_conditions)
    else:  # ready is None, still settling (no Ready condition published yet)
        phase, last_error = _PHASE_PROVISIONING, ""
        synced_cond = _condition(_COND_SYNCED, False, "Pending", message or "Awaiting first ESO sync", existing_conditions)
        ready_cond = _condition(_COND_READY, False, "Provisioning", "Awaiting ExternalSecret sync from Vault", existing_conditions)

    return {
        "phase": phase,
        "lastError": last_error,
        "targetSecretName": target_secret,
        "conditions": [trusted_cond, synced_cond, ready_cond],
    }


def _checksum_secret_data(secret_obj: dict) -> str:
    data = secret_obj.get("data", {}) or {}
    packed = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(packed.encode("utf-8")).hexdigest()


def _apply_rolling_restart_annotation(
    api_client: client.ApiClient,
    apps: client.AppsV1Api,
    target_kind: str,
    target_namespace: str,
    target_name: str,
    zts_name: str,
    checksum: str,
) -> None:
    # Validate the workload still exists before patching (raises if not); the
    # only-key merge patch below does not need the full object.
    _read_workload(target_kind, target_namespace, target_name, apps, api_client)

    checksum_key = f"vault-secret-checksum/{_sanitize_name(zts_name)}"
    # Merge only our checksum annotation (preserves concurrent annotation writes
    # from other controllers; strategic merge merges annotation maps key-by-key).
    patch_body = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {checksum_key: checksum},
                }
            }
        }
    }
    _patch_target(kind=target_kind, namespace=target_namespace, name=target_name, patch_body=patch_body, apps=apps)


@kopf.on.create(GROUP, VERSION, ZTS_PLURAL)
@kopf.on.update(GROUP, VERSION, ZTS_PLURAL)
def reconcile_zerotrust_secret(spec: dict, name: str, namespace: str, body: dict, status: dict | None = None, **_: Any) -> None:
    reconcile_id = new_reconcile_id()
    uid = body.get("metadata", {}).get("uid", "unknown")
    adapter = logging.LoggerAdapter(
        logger,
        ctx(name=name, namespace=namespace, uid=uid, reconcile_id=reconcile_id, phase="Validating"),
    )

    existing_conditions = (status or {}).get("conditions", [])

    api_client = client.ApiClient()
    custom = client.CustomObjectsApi(api_client)
    apps = client.AppsV1Api(api_client)
    core = client.CoreV1Api(api_client)

    try:
        _zts_status_patch(custom, namespace, name, {"phase": _PHASE_VALIDATING, "lastError": ""})

        target_workload = spec.get("targetWorkload", {}) or {}
        target_kind, target_namespace, _target_obj = _get_target(
            namespace=namespace,
            target_workload=target_workload,
            apps=apps,
            api_client=api_client,
        )

        ztc = spec.get("zeroTrustConditions", {}) or {}
        _validate_zero_trust_conditions(namespace=namespace, spec=spec, ztc=ztc, custom=custom)

        owner = _owner_reference(body)
        external_secret, target_secret_name = _build_external_secret(
            zts_name=name,
            namespace=namespace,
            body=body,
            spec=spec,
            owner=owner,
        )

        _zts_status_patch(custom, namespace, name, {"phase": _PHASE_PROVISIONING, "lastError": ""})
        _upsert_external_secret(custom=custom, namespace=namespace, external_secret=external_secret)
        adapter.info(
            "Applied ExternalSecret",
            extra={"event": "external-secret-upsert", "resource_kind": "ExternalSecret", "resource_name": name},
        )

        secret_data = spec.get("secretData", {}) or {}
        mapping = secret_data.get("mapping", []) or []
        target_name = str(target_workload.get("name", "")).strip()

        _inject_mapping_to_workload(
            zts_name=name,
            target_secret_name=target_secret_name,
            mapping=mapping,
            target_kind=target_kind,
            target_namespace=target_namespace,
            target_name=target_name,
            apps=apps,
            api_client=api_client,
        )
        adapter.info(
            "Injected secret mapping into workload",
            extra={"event": "workload-injection", "resource_kind": target_kind, "resource_name": target_name},
        )

        # Real health: ExternalSecret is freshly upserted and ESO syncs
        # asynchronously, so this is typically Provisioning until the first sync.
        # The @kopf.timer below promotes it to Running once the Secret exists —
        # we never write a blind 'Running' here.
        status_patch = _evaluate_status(
            custom=custom,
            core=core,
            namespace=namespace,
            name=name,
            spec=spec,
            existing_conditions=existing_conditions,
        )
        generation = body.get("metadata", {}).get("generation")
        if generation is not None:
            status_patch["observedGeneration"] = generation
        _zts_status_patch(custom, namespace, name, status_patch)
        adapter.info(
            "ZeroTrustSecret reconciliation completed",
            extra={"event": "zts-reconcile-success", "phase": status_patch.get("phase")},
        )

    except (ZeroTrustSecretError, ApiException, ValueError) as exc:
        message = _format_error(exc)
        status_phase = _PHASE_BLOCKED if "BlockedBySecurity" in message else _PHASE_DEGRADED
        _zts_status_patch(
            custom,
            namespace,
            name,
            {
                "phase": status_phase,
                "lastError": message,
                "conditions": [_condition(_COND_READY, False, status_phase, message, existing_conditions)],
            },
        )
        adapter.exception("ZeroTrustSecret reconciliation failed", extra={"event": "zts-reconcile-error"})
        raise kopf.TemporaryError(str(exc), delay=30) from exc


@kopf.timer(GROUP, VERSION, ZTS_PLURAL, interval=ZTS_HEALTH_INTERVAL)
def reevaluate_zerotrust_secret(spec: dict, name: str, namespace: str, status: dict | None = None, **_: Any) -> None:
    """Periodic re-evaluation: continuous zero-trust + real sync verification.

    - Promotes Provisioning → Running once ESO has actually synced the Secret.
    - Demotes to Degraded if the ExternalSecret stops syncing or the Secret
      disappears (e.g. Vault down / path removed).
    - Revokes (hard) if the target ZeroTrustApplication drops below Verified.

    Skips objects the create/update handler has not finished provisioning yet so
    a freshly-created ZTS is not flapped to Degraded before its ExternalSecret
    exists.
    """
    phase = (status or {}).get("phase")
    if not phase or phase == _PHASE_VALIDATING:
        return

    api_client = client.ApiClient()
    custom = client.CustomObjectsApi(api_client)
    core = client.CoreV1Api(api_client)
    adapter = logging.LoggerAdapter(
        logger,
        ctx(name=name, namespace=namespace, uid="-", reconcile_id=new_reconcile_id(), phase="Health"),
    )

    try:
        status_patch = _evaluate_status(
            custom=custom,
            core=core,
            namespace=namespace,
            name=name,
            spec=spec,
            existing_conditions=(status or {}).get("conditions", []),
        )
        new_phase = status_patch.get("phase")
        if new_phase != phase:
            adapter.info(
                "ZTS health transition",
                extra={"event": "zts-health-transition", "previous": phase, "phase": new_phase},
            )
        _zts_status_patch(custom, namespace, name, status_patch)
    except ApiException as exc:
        if exc.status == 404:
            return  # ZTS deleted mid-flight
        adapter.warning(
            f"ZTS health re-evaluation transient error: {exc.reason}",
            extra={"event": "zts-health-error", "status": getattr(exc, "status", None)},
        )


@kopf.on.delete(GROUP, VERSION, ZTS_PLURAL)
def cleanup_zerotrust_secret(spec: dict, name: str, namespace: str, body: dict, **_: Any) -> None:
    reconcile_id = new_reconcile_id()
    uid = body.get("metadata", {}).get("uid", "unknown")
    adapter = logging.LoggerAdapter(
        logger,
        ctx(name=name, namespace=namespace, uid=uid, reconcile_id=reconcile_id, phase="Deleting"),
    )

    api_client = client.ApiClient()
    apps = client.AppsV1Api(api_client)

    try:
        target_workload = spec.get("targetWorkload", {}) or {}
        target_kind, target_namespace, target_obj = _get_target(
            namespace=namespace,
            target_workload=target_workload,
            apps=apps,
            api_client=api_client,
        )
        target_name = str(target_workload.get("name", "")).strip()

        secret_data = spec.get("secretData", {}) or {}
        mapping = secret_data.get("mapping", []) or []
        pod_spec = target_obj["spec"]["template"].get("spec", {})
        containers = pod_spec.get("containers", [])
        if not containers:
            return

        default_container = containers[0].get("name")
        by_name = {c.get("name"): c for c in containers if c.get("name")}
        volumes = pod_spec.get("volumes", []) or []

        # Group removals per target container (mirrors the multi-container injection).
        env_to_remove: dict[str, set[str]] = {}
        volume_names_to_remove: set[str] = set()
        for index, item in enumerate(mapping):
            value_type = str(item.get("type", "")).strip()
            local_key = str(item.get("localKey", "")).strip()
            container_name = str(item.get("containerName", "")).strip() or default_container
            if value_type == "EnvVar":
                env_to_remove.setdefault(container_name, set()).add(local_key)
            elif value_type == "VolumeMount":
                volume_names_to_remove.add(_volume_name(zts_name=name, local_key=local_key, index=index))

        # Recompute only the containers we actually touched (env/mount removed).
        patch_containers = []
        for container_name, container in by_name.items():
            drop_env = env_to_remove.get(container_name, set())
            orig_env = container.get("env", []) or []
            orig_mounts = container.get("volumeMounts", []) or []
            new_env = [e for e in orig_env if e.get("name") not in drop_env]
            new_mounts = [m for m in orig_mounts if m.get("name") not in volume_names_to_remove]
            if new_env != orig_env or new_mounts != orig_mounts:
                patch_containers.append({
                    "name": container_name,
                    "env": new_env,
                    "volumeMounts": new_mounts,
                })

        volumes = [v for v in volumes if v.get("name") not in volume_names_to_remove]

        # Delete ONLY our two annotations via null-merge. Omitting a key from a
        # merge patch does NOT remove it (so the old read-pop-resend never
        # actually deleted them); setting the value to null does. This also
        # avoids clobbering concurrent annotation writes from other controllers.
        removed_annotations = {
            f"zta.devsecops/injected-{_sanitize_name(name)}": None,
            f"vault-secret-checksum/{_sanitize_name(name)}": None,
        }

        spec_patch: dict[str, Any] = {"volumes": volumes}
        if patch_containers:
            spec_patch["containers"] = patch_containers
        patch_body = {
            "spec": {
                "template": {
                    "metadata": {"annotations": removed_annotations},
                    "spec": spec_patch,
                }
            }
        }
        _patch_target(kind=target_kind, namespace=target_namespace, name=target_name, patch_body=patch_body, apps=apps)
        adapter.info("Cleaned workload secret injection on delete", extra={"event": "zts-cleanup-success"})

    except ApiException as exc:
        if exc.status == 404:
            return  # workload already gone — nothing to clean
        adapter.exception("Failed cleanup for ZeroTrustSecret (K8s API error)", extra={"event": "zts-cleanup-error"})
        raise  # transient API error → let kopf retry briefly (finalizer holds, then releases)
    except (ZeroTrustSecretError, KeyError, ValueError) as exc:
        # The target workload is malformed/unreadable (no pod template, invalid kind,
        # already-mutated shape). Injection is moot — log and let the delete proceed
        # so the finalizer never wedges the ZTS in Terminating.
        adapter.warning(
            f"Skipping workload cleanup ({type(exc).__name__}: {exc}); allowing ZTS deletion",
            extra={"event": "zts-cleanup-skip"},
        )
        return


@kopf.on.update("", "v1", "secrets", labels={ZTS_MANAGED_LABEL_KEY: ZTS_MANAGED_LABEL_VALUE})
def on_managed_secret_update(body: dict, namespace: str, name: str, **_: Any) -> None:
    reconcile_id = new_reconcile_id()
    uid = body.get("metadata", {}).get("uid", "unknown")

    labels = (body.get("metadata", {}) or {}).get("labels", {}) or {}
    zts_name = str(labels.get(ZTS_LABEL_NAME, "")).strip()
    zts_namespace = str(labels.get(ZTS_LABEL_NAMESPACE, namespace)).strip() or namespace

    if not zts_name:
        return

    adapter = logging.LoggerAdapter(
        logger,
        ctx(name=zts_name, namespace=zts_namespace, uid=uid, reconcile_id=reconcile_id, phase="Rotate"),
    )

    api_client = client.ApiClient()
    custom = client.CustomObjectsApi(api_client)
    apps = client.AppsV1Api(api_client)

    try:
        zts = custom.get_namespaced_custom_object(
            group=GROUP,
            version=VERSION,
            namespace=zts_namespace,
            plural=ZTS_PLURAL,
            name=zts_name,
            _request_timeout=_K8S_TIMEOUT,
        )

        lifecycle = zts.get("spec", {}).get("lifecycle", {}) or {}
        on_update_action = str(lifecycle.get("onUpdateAction", "RollingRestart")).strip()
        if on_update_action != "RollingRestart":
            return

        target_workload = zts.get("spec", {}).get("targetWorkload", {}) or {}
        target_kind = str(target_workload.get("kind", "")).strip()
        target_name = str(target_workload.get("name", "")).strip()
        target_ns = str(target_workload.get("namespace", zts_namespace)).strip() or zts_namespace

        checksum = _checksum_secret_data(body)
        _apply_rolling_restart_annotation(
            api_client=api_client,
            apps=apps,
            target_kind=target_kind,
            target_namespace=target_ns,
            target_name=target_name,
            zts_name=zts_name,
            checksum=checksum,
        )

        _zts_status_patch(
            custom,
            zts_namespace,
            zts_name,
            {
                "phase": _PHASE_RUNNING,
                "lastError": "",
                "lastRotationChecksum": checksum,
            },
        )
        adapter.info(
            "Applied rolling restart checksum after secret rotation",
            extra={"event": "zts-rolling-restart", "resource_kind": target_kind, "resource_name": target_name},
        )

    except ApiException as exc:
        if exc.status == 404:
            return
        adapter.exception("Secret rotation handling failed", extra={"event": "zts-rotation-error"})
        raise
