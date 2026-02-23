import hashlib
import json
import logging
import re
from typing import Any

import kopf
from kubernetes import client
from kubernetes.client.exceptions import ApiException

from .config import (
    EXTERNAL_SECRETS_GROUP,
    EXTERNAL_SECRETS_PLURAL,
    EXTERNAL_SECRETS_VERSION,
    GROUP,
    SEVERITY_ORDER,
    VERSION,
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


def _zts_status_patch(custom: client.CustomObjectsApi, namespace: str, name: str, patch: dict[str, Any]) -> None:
    custom.patch_namespaced_custom_object_status(
        group=GROUP,
        version=VERSION,
        namespace=namespace,
        plural=ZTS_PLURAL,
        name=name,
        body={"status": patch},
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

    target_secret_name = str(spec.get("targetSecretName", zts_name)).strip() or zts_name

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

    if kind == "Deployment":
        obj = apps.read_namespaced_deployment(name=name, namespace=workload_ns)
    elif kind == "StatefulSet":
        obj = apps.read_namespaced_stateful_set(name=name, namespace=workload_ns)
    else:
        obj = apps.read_namespaced_daemon_set(name=name, namespace=workload_ns)

    return kind, workload_ns, api_client.sanitize_for_serialization(obj)


def _patch_target(kind: str, namespace: str, name: str, patch_body: dict, apps: client.AppsV1Api) -> None:
    if kind == "Deployment":
        apps.patch_namespaced_deployment(name=name, namespace=namespace, body=patch_body)
    elif kind == "StatefulSet":
        apps.patch_namespaced_stateful_set(name=name, namespace=namespace, body=patch_body)
    else:
        apps.patch_namespaced_daemon_set(name=name, namespace=namespace, body=patch_body)


def _inject_mapping_to_workload(
    zts_name: str,
    target_secret_name: str,
    mapping: list[dict],
    target_kind: str,
    target_namespace: str,
    target_name: str,
    target_obj: dict,
    apps: client.AppsV1Api,
) -> None:
    pod_spec = target_obj["spec"]["template"].get("spec", {})
    containers = pod_spec.get("containers", [])
    if not containers:
        raise ZeroTrustSecretError("Target workload has no containers")

    first_container = containers[0]
    container_name = first_container.get("name")
    if not container_name:
        raise ZeroTrustSecretError("Target workload first container has no name")

    env = first_container.get("env", []) or []
    volume_mounts = first_container.get("volumeMounts", []) or []
    volumes = pod_spec.get("volumes", []) or []

    for index, item in enumerate(mapping):
        local_key = str(item.get("localKey", "")).strip()
        value_type = str(item.get("type", "")).strip()

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

    annotations = target_obj["spec"]["template"].get("metadata", {}).get("annotations", {}) or {}
    injected_marker_key = f"zta.devsecops/injected-{_sanitize_name(zts_name)}"
    annotations[injected_marker_key] = "true"

    patch_body = {
        "spec": {
            "template": {
                "metadata": {"annotations": annotations},
                "spec": {
                    "volumes": volumes,
                    "containers": [
                        {
                            "name": container_name,
                            "env": env,
                            "volumeMounts": volume_mounts,
                        }
                    ],
                },
            }
        }
    }

    _patch_target(kind=target_kind, namespace=target_namespace, name=target_name, patch_body=patch_body, apps=apps)


def _validate_zero_trust_conditions(namespace: str, target_workload: dict, ztc: dict, custom: client.CustomObjectsApi) -> None:
    if not ztc:
        return

    target_name = str(target_workload.get("name", "")).strip()
    target_namespace = str(target_workload.get("namespace", namespace)).strip() or namespace

    if ztc.get("timeBasedAccess", {}).get("enabled", False):
        raise ZeroTrustSecretError("timeBasedAccess.enabled=true is not implemented in this version")

    require_clean = bool(ztc.get("requireCleanSupplyChain", False))
    max_allowed = str(ztc.get("maxAllowedVulnerability", "")).strip().upper()
    require_network_iso = bool(ztc.get("requireNetworkIsolation", False))

    if not (require_clean or max_allowed or require_network_iso):
        return

    try:
        zta = custom.get_namespaced_custom_object(
            group=GROUP,
            version=VERSION,
            namespace=target_namespace,
            plural="zerotrustapplications",
            name=target_name,
        )
    except ApiException as exc:
        if exc.status == 404:
            raise ZeroTrustSecretError(
                f"No ZeroTrustApplication found for target workload {target_namespace}/{target_name}"
            ) from exc
        raise

    zta_status = zta.get("status", {}) or {}
    zta_spec = zta.get("spec", {}) or {}

    if require_clean:
        phase = str(zta_status.get("phase", ""))
        if phase != "Running":
            raise ZeroTrustSecretError(
                f"BlockedBySecurity: requireCleanSupplyChain=true but target ZeroTrustApplication phase is {phase or 'unknown'}"
            )

    if max_allowed:
        if max_allowed not in SEVERITY_ORDER:
            raise ZeroTrustSecretError(f"Invalid zeroTrustConditions.maxAllowedVulnerability: {max_allowed}")
        app_max = str((zta_spec.get("supplyChain", {}) or {}).get("maxVulnerabilities", "")).upper()
        if app_max not in SEVERITY_ORDER:
            raise ZeroTrustSecretError("Target ZeroTrustApplication has invalid supplyChain.maxVulnerabilities")
        if SEVERITY_ORDER[app_max] > SEVERITY_ORDER[max_allowed]:
            raise ZeroTrustSecretError(
                f"BlockedBySecurity: target app vulnerability threshold {app_max} is weaker than required {max_allowed}"
            )

    if require_network_iso:
        network_spec = zta_spec.get("networkZeroTrust", {}) or {}
        egress = network_spec.get("egressAllowedTo", []) or []
        if not egress:
            raise ZeroTrustSecretError("BlockedBySecurity: requireNetworkIsolation=true but app egress policy is not defined")


def _upsert_external_secret(custom: client.CustomObjectsApi, namespace: str, external_secret: dict) -> None:
    name = external_secret["metadata"]["name"]
    try:
        custom.get_namespaced_custom_object(
            group=EXTERNAL_SECRETS_GROUP,
            version=EXTERNAL_SECRETS_VERSION,
            namespace=namespace,
            plural=EXTERNAL_SECRETS_PLURAL,
            name=name,
        )
        custom.patch_namespaced_custom_object(
            group=EXTERNAL_SECRETS_GROUP,
            version=EXTERNAL_SECRETS_VERSION,
            namespace=namespace,
            plural=EXTERNAL_SECRETS_PLURAL,
            name=name,
            body=external_secret,
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
        )


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
    if target_kind == "Deployment":
        target_obj = api_client.sanitize_for_serialization(
            apps.read_namespaced_deployment(name=target_name, namespace=target_namespace)
        )
    elif target_kind == "StatefulSet":
        target_obj = api_client.sanitize_for_serialization(
            apps.read_namespaced_stateful_set(name=target_name, namespace=target_namespace)
        )
    else:
        target_obj = api_client.sanitize_for_serialization(
            apps.read_namespaced_daemon_set(name=target_name, namespace=target_namespace)
        )

    annotations = target_obj["spec"]["template"].get("metadata", {}).get("annotations", {}) or {}
    annotations[f"vault-secret-checksum/{_sanitize_name(zts_name)}"] = checksum

    patch_body = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": annotations,
                }
            }
        }
    }
    _patch_target(kind=target_kind, namespace=target_namespace, name=target_name, patch_body=patch_body, apps=apps)


@kopf.on.create(GROUP, VERSION, ZTS_PLURAL)
@kopf.on.update(GROUP, VERSION, ZTS_PLURAL)
def reconcile_zerotrust_secret(spec: dict, name: str, namespace: str, body: dict, **_: Any) -> None:
    reconcile_id = new_reconcile_id()
    uid = body.get("metadata", {}).get("uid", "unknown")
    adapter = logging.LoggerAdapter(
        logger,
        ctx(name=name, namespace=namespace, uid=uid, reconcile_id=reconcile_id, phase="Validating"),
    )

    api_client = client.ApiClient()
    custom = client.CustomObjectsApi(api_client)
    apps = client.AppsV1Api(api_client)

    try:
        _zts_status_patch(custom, namespace, name, {"phase": "Validating", "lastError": ""})

        target_workload = spec.get("targetWorkload", {}) or {}
        target_kind, target_namespace, target_obj = _get_target(
            namespace=namespace,
            target_workload=target_workload,
            apps=apps,
            api_client=api_client,
        )

        ztc = spec.get("zeroTrustConditions", {}) or {}
        _validate_zero_trust_conditions(namespace=namespace, target_workload=target_workload, ztc=ztc, custom=custom)

        owner = _owner_reference(body)
        external_secret, target_secret_name = _build_external_secret(
            zts_name=name,
            namespace=namespace,
            body=body,
            spec=spec,
            owner=owner,
        )

        _zts_status_patch(custom, namespace, name, {"phase": "Provisioning", "lastError": ""})
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
            target_obj=target_obj,
            apps=apps,
        )
        adapter.info(
            "Injected secret mapping into workload",
            extra={"event": "workload-injection", "resource_kind": target_kind, "resource_name": target_name},
        )

        _zts_status_patch(
            custom,
            namespace,
            name,
            {
                "phase": "Running",
                "lastError": "",
                "targetSecretName": target_secret_name,
            },
        )
        adapter.info("ZeroTrustSecret reconciliation completed", extra={"event": "zts-reconcile-success"})

    except (ZeroTrustSecretError, ApiException, ValueError) as exc:
        status_phase = "BlockedBySecurity" if "BlockedBySecurity" in str(exc) else "Degraded"
        _zts_status_patch(custom, namespace, name, {"phase": status_phase, "lastError": str(exc)})
        adapter.exception("ZeroTrustSecret reconciliation failed", extra={"event": "zts-reconcile-error"})
        raise kopf.TemporaryError(str(exc), delay=30) from exc


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

        first_container = containers[0]
        container_name = first_container.get("name")
        env = first_container.get("env", []) or []
        volume_mounts = first_container.get("volumeMounts", []) or []
        volumes = pod_spec.get("volumes", []) or []

        env_to_remove = set()
        volume_names_to_remove = set()
        for index, item in enumerate(mapping):
            value_type = str(item.get("type", "")).strip()
            local_key = str(item.get("localKey", "")).strip()
            if value_type == "EnvVar":
                env_to_remove.add(local_key)
            elif value_type == "VolumeMount":
                volume_names_to_remove.add(_volume_name(zts_name=name, local_key=local_key, index=index))

        env = [e for e in env if e.get("name") not in env_to_remove]
        volume_mounts = [m for m in volume_mounts if m.get("name") not in volume_names_to_remove]
        volumes = [v for v in volumes if v.get("name") not in volume_names_to_remove]

        annotations = target_obj["spec"]["template"].get("metadata", {}).get("annotations", {}) or {}
        annotations.pop(f"zta.devsecops/injected-{_sanitize_name(name)}", None)
        annotations.pop(f"vault-secret-checksum/{_sanitize_name(name)}", None)

        patch_body = {
            "spec": {
                "template": {
                    "metadata": {"annotations": annotations},
                    "spec": {
                        "volumes": volumes,
                        "containers": [
                            {
                                "name": container_name,
                                "env": env,
                                "volumeMounts": volume_mounts,
                            }
                        ],
                    },
                }
            }
        }
        _patch_target(kind=target_kind, namespace=target_namespace, name=target_name, patch_body=patch_body, apps=apps)
        adapter.info("Cleaned workload secret injection on delete", extra={"event": "zts-cleanup-success"})

    except ApiException as exc:
        if exc.status == 404:
            return
        adapter.exception("Failed cleanup for ZeroTrustSecret", extra={"event": "zts-cleanup-error"})
        raise


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
                "phase": "Running",
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
