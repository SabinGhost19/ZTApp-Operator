"""Unit tests for the ZeroTrustSecret reconcile/health logic (zerotrust_secret.py).

Covers the new real-sync health evaluator (no more blind "Running"), the hard
trust-loss revocation, multi-container injection, the condition builder, and the
pure spec→ExternalSecret translation. Uses in-memory fakes for the K8s clients,
mirroring the FakeCore pattern in test_talon.py — no cluster required.
"""

import pytest
from kubernetes.client.exceptions import ApiException

from zta_operator.zerotrust_secret import (
    ZeroTrustSecretError,
    _build_external_secret,
    _check_trust,
    _condition,
    _evaluate_status,
    _external_secret_ready,
    _get_target,
    _inject_mapping_to_workload,
    _normalize_vault_path,
    _sanitize_name,
    _secret_exists,
    _target_secret_name,
)

EXTERNALSECRETS = "externalsecrets"
ZTA_PLURAL = "zerotrustapplications"


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class FakeCustom:
    """In-memory CustomObjectsApi. Objects keyed by (plural, namespace, name)."""

    def __init__(self, objects=None):
        self.objects = dict(objects or {})
        self.deleted = []
        self.status_patches = []

    def get_namespaced_custom_object(self, group, version, namespace, plural, name, _request_timeout=None):
        key = (plural, namespace, name)
        if key not in self.objects:
            raise ApiException(status=404, reason="Not Found")
        return self.objects[key]

    def delete_namespaced_custom_object(self, group, version, namespace, plural, name, _request_timeout=None):
        key = (plural, namespace, name)
        self.deleted.append(key)
        if key not in self.objects:
            raise ApiException(status=404, reason="Not Found")
        del self.objects[key]

    def patch_namespaced_custom_object_status(self, group, version, namespace, plural, name, body, _request_timeout=None):
        self.status_patches.append(body)


class FakeCore:
    def __init__(self, secrets=None):
        self.secrets = set(secrets or [])

    def read_namespaced_secret(self, name, namespace, _request_timeout=None):
        if (namespace, name) in self.secrets:
            return object()
        raise ApiException(status=404, reason="Not Found")


class FakeApiClient:
    def sanitize_for_serialization(self, obj):
        return obj


class FakeApps:
    def __init__(self, workload):
        self.workload = workload
        self.patched = None

    def read_namespaced_deployment(self, name, namespace, _request_timeout=None):
        return self.workload

    def patch_namespaced_deployment(self, name, namespace, body, _request_timeout=None):
        self.patched = body


def make_spec(require_verified=True, app_name="orders-api", target_secret="orders-db"):
    return {
        "applicationRef": {"name": app_name},
        "targetWorkload": {"kind": "Deployment", "name": "orders-api"},
        "targetSecretName": target_secret,
        "secretData": {
            "remotePath": "secret/data/orders/db",
            "mapping": [{"remoteKey": "password", "localKey": "DB_PASSWORD", "type": "EnvVar"}],
        },
        "zeroTrustConditions": {"requireVerifiedStatus": require_verified},
        "lifecycle": {"refreshInterval": "1m"},
    }


def make_workload(containers):
    return {"spec": {"template": {"metadata": {"annotations": {}}, "spec": {"containers": containers, "volumes": []}}}}


def es_obj(ready=None, reason="SecretSynced", message="ok"):
    conditions = []
    if ready is not None:
        conditions = [{"type": "Ready", "status": "True" if ready else "False", "reason": reason, "message": message}]
    return {"status": {"conditions": conditions}}


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #
def test_normalize_vault_path():
    assert _normalize_vault_path("secret/data/orders/db") == "orders/db"
    assert _normalize_vault_path("/secret/orders/db/") == "orders/db"
    assert _normalize_vault_path("orders/db") == "orders/db"


def test_sanitize_name():
    assert _sanitize_name("Orders_API.v1") == "orders-api-v1"


def test_target_secret_name_defaults_to_zts_name():
    assert _target_secret_name("zts-x", {}) == "zts-x"
    assert _target_secret_name("zts-x", {"targetSecretName": "custom"}) == "custom"


def test_build_external_secret_shape():
    spec = make_spec()
    owner = {"apiVersion": "devsecops.licenta.ro/v1", "kind": "ZeroTrustSecret", "name": "orders-zts", "uid": "u"}
    es, target = _build_external_secret("orders-zts", "default", {"metadata": {"name": "orders-zts", "uid": "u"}}, spec, owner)
    assert target == "orders-db"
    assert es["spec"]["target"]["name"] == "orders-db"
    assert es["spec"]["target"]["creationPolicy"] == "Owner"
    assert es["spec"]["secretStoreRef"]["name"] == "vault-backend"
    assert es["spec"]["data"][0]["secretKey"] == "DB_PASSWORD"
    assert es["spec"]["data"][0]["remoteRef"]["key"] == "orders/db"  # normalized
    assert es["metadata"]["ownerReferences"] == [owner]


# --------------------------------------------------------------------------- #
# Condition builder
# --------------------------------------------------------------------------- #
def test_condition_preserves_transition_time_when_unchanged():
    existing = [{"type": "Ready", "status": "True", "lastTransitionTime": "2020-01-01T00:00:00Z"}]
    c = _condition("Ready", True, "ok", "msg", existing)
    assert c["lastTransitionTime"] == "2020-01-01T00:00:00Z"
    assert c["status"] == "True"


def test_condition_resets_transition_time_on_flip():
    existing = [{"type": "Ready", "status": "True", "lastTransitionTime": "2020-01-01T00:00:00Z"}]
    c = _condition("Ready", False, "bad", "msg", existing)
    assert c["lastTransitionTime"] != "2020-01-01T00:00:00Z"
    assert c["status"] == "False"


# --------------------------------------------------------------------------- #
# Trust evaluation
# --------------------------------------------------------------------------- #
def test_check_trust_not_required():
    assert _check_trust(FakeCustom(), "default", make_spec(require_verified=False)) == (False, True, "trust gating disabled")


def test_check_trust_verified():
    custom = FakeCustom({(ZTA_PLURAL, "default", "orders-api"): {"status": {"trustLevel": "Verified"}}})
    assert _check_trust(custom, "default", make_spec()) == (True, True, "Verified")


def test_check_trust_untrusted():
    custom = FakeCustom({(ZTA_PLURAL, "default", "orders-api"): {"status": {"trustLevel": "Degraded"}}})
    require, trusted, detail = _check_trust(custom, "default", make_spec())
    assert require and not trusted and "Degraded" in detail


def test_check_trust_missing_zta():
    require, trusted, detail = _check_trust(FakeCustom(), "default", make_spec())
    assert require and not trusted and detail.startswith("No ZeroTrustApplication")


# --------------------------------------------------------------------------- #
# ExternalSecret readiness + Secret existence
# --------------------------------------------------------------------------- #
def test_external_secret_ready_true():
    custom = FakeCustom({(EXTERNALSECRETS, "default", "zts"): es_obj(ready=True)})
    ready, reason, _msg = _external_secret_ready(custom, "default", "zts")
    assert ready is True and reason == "SecretSynced"


def test_external_secret_ready_false():
    custom = FakeCustom({(EXTERNALSECRETS, "default", "zts"): es_obj(ready=False, reason="SecretSyncedError")})
    ready, reason, _msg = _external_secret_ready(custom, "default", "zts")
    assert ready is False and reason == "SecretSyncedError"


def test_external_secret_missing():
    ready, reason, _msg = _external_secret_ready(FakeCustom(), "default", "zts")
    assert ready is None and reason == "Missing"


def test_external_secret_no_condition_yet():
    custom = FakeCustom({(EXTERNALSECRETS, "default", "zts"): {"status": {"conditions": []}}})
    ready, reason, _msg = _external_secret_ready(custom, "default", "zts")
    assert ready is None and reason == "Pending"


def test_secret_exists():
    core = FakeCore(secrets={("default", "orders-db")})
    assert _secret_exists(core, "default", "orders-db") is True
    assert _secret_exists(core, "default", "missing") is False


# --------------------------------------------------------------------------- #
# Health evaluator
# --------------------------------------------------------------------------- #
def test_evaluate_running():
    ns, name = "default", "orders-zts"
    custom = FakeCustom({
        (ZTA_PLURAL, ns, "orders-api"): {"status": {"trustLevel": "Verified"}},
        (EXTERNALSECRETS, ns, name): es_obj(ready=True),
    })
    core = FakeCore(secrets={(ns, "orders-db")})
    patch = _evaluate_status(custom, core, ns, name, make_spec(), [])
    assert patch["phase"] == "Running"
    conds = {c["type"]: c["status"] for c in patch["conditions"]}
    assert conds == {"Trusted": "True", "Synced": "True", "Ready": "True"}
    assert patch["lastError"] == ""


def test_evaluate_provisioning_when_secret_not_yet_present():
    ns, name = "default", "orders-zts"
    custom = FakeCustom({
        (ZTA_PLURAL, ns, "orders-api"): {"status": {"trustLevel": "Verified"}},
        (EXTERNALSECRETS, ns, name): es_obj(ready=True),
    })
    core = FakeCore()  # secret not created yet
    patch = _evaluate_status(custom, core, ns, name, make_spec(), [])
    assert patch["phase"] == "Provisioning"


def test_evaluate_degraded_on_sync_error():
    ns, name = "default", "orders-zts"
    custom = FakeCustom({
        (ZTA_PLURAL, ns, "orders-api"): {"status": {"trustLevel": "Verified"}},
        (EXTERNALSECRETS, ns, name): es_obj(ready=False, reason="SecretSyncedError", message="path not found"),
    })
    patch = _evaluate_status(custom, FakeCore(), ns, name, make_spec(), [])
    assert patch["phase"] == "Degraded"
    assert "SecretSyncedError" in patch["lastError"]


def test_evaluate_degraded_when_external_secret_missing():
    ns, name = "default", "orders-zts"
    custom = FakeCustom({(ZTA_PLURAL, ns, "orders-api"): {"status": {"trustLevel": "Verified"}}})
    patch = _evaluate_status(custom, FakeCore(), ns, name, make_spec(), [])
    assert patch["phase"] == "Degraded"
    assert "missing" in patch["lastError"].lower()


def test_evaluate_provisioning_when_es_pending():
    ns, name = "default", "orders-zts"
    custom = FakeCustom({
        (ZTA_PLURAL, ns, "orders-api"): {"status": {"trustLevel": "Verified"}},
        (EXTERNALSECRETS, ns, name): {"status": {"conditions": []}},
    })
    patch = _evaluate_status(custom, FakeCore(), ns, name, make_spec(), [])
    assert patch["phase"] == "Provisioning"


def test_evaluate_hard_revoke_on_trust_loss():
    ns, name = "default", "orders-zts"
    custom = FakeCustom({
        (ZTA_PLURAL, ns, "orders-api"): {"status": {"trustLevel": "Untrusted"}},
        (EXTERNALSECRETS, ns, name): es_obj(ready=True),
    })
    core = FakeCore(secrets={(ns, "orders-db")})
    patch = _evaluate_status(custom, core, ns, name, make_spec(require_verified=True), [])
    assert patch["phase"] == "BlockedBySecurity"
    # Hard revoke: the backing ExternalSecret is deleted (ESO cascade-deletes the Secret).
    assert (EXTERNALSECRETS, ns, name) in custom.deleted
    assert (EXTERNALSECRETS, ns, name) not in custom.objects
    conds = {c["type"]: c["status"] for c in patch["conditions"]}
    assert conds["Trusted"] == "False"


def test_evaluate_trust_not_required_runs_without_zta():
    ns, name = "default", "orders-zts"
    custom = FakeCustom({(EXTERNALSECRETS, ns, name): es_obj(ready=True)})  # no ZTA object at all
    core = FakeCore(secrets={(ns, "orders-db")})
    patch = _evaluate_status(custom, core, ns, name, make_spec(require_verified=False), [])
    assert patch["phase"] == "Running"
    trusted = next(c for c in patch["conditions"] if c["type"] == "Trusted")
    assert trusted["reason"] == "NotRequired"


# --------------------------------------------------------------------------- #
# Multi-container injection
# --------------------------------------------------------------------------- #
def test_inject_envvar_default_container():
    apps = FakeApps(make_workload([{"name": "app", "env": []}]))
    mapping = [{"localKey": "DB_PASSWORD", "type": "EnvVar"}]
    _inject_mapping_to_workload("zts", "orders-db", mapping, "Deployment", "default", "orders-api", apps, FakeApiClient())
    containers = apps.patched["spec"]["template"]["spec"]["containers"]
    assert [c["name"] for c in containers] == ["app"]
    env = containers[0]["env"]
    assert env[0]["name"] == "DB_PASSWORD"
    assert env[0]["valueFrom"]["secretKeyRef"]["name"] == "orders-db"


def test_inject_envvar_named_container_only_patches_that_container():
    apps = FakeApps(make_workload([{"name": "app", "env": []}, {"name": "sidecar", "env": []}]))
    mapping = [{"localKey": "DB_PASSWORD", "type": "EnvVar", "containerName": "sidecar"}]
    _inject_mapping_to_workload("zts", "orders-db", mapping, "Deployment", "default", "orders-api", apps, FakeApiClient())
    containers = apps.patched["spec"]["template"]["spec"]["containers"]
    assert [c["name"] for c in containers] == ["sidecar"]  # only the touched container is patched
    assert containers[0]["env"][0]["name"] == "DB_PASSWORD"


def test_inject_missing_container_raises():
    apps = FakeApps(make_workload([{"name": "app", "env": []}]))
    mapping = [{"localKey": "X", "type": "EnvVar", "containerName": "nope"}]
    with pytest.raises(ZeroTrustSecretError):
        _inject_mapping_to_workload("zts", "s", mapping, "Deployment", "default", "orders-api", apps, FakeApiClient())


def test_inject_volume_mount():
    apps = FakeApps(make_workload([{"name": "app"}]))
    mapping = [{"localKey": "tls.crt", "type": "VolumeMount", "mountPath": "/certs"}]
    _inject_mapping_to_workload("zts", "orders-tls", mapping, "Deployment", "default", "orders-api", apps, FakeApiClient())
    spec = apps.patched["spec"]["template"]["spec"]
    assert spec["volumes"][0]["secret"]["secretName"] == "orders-tls"
    assert spec["containers"][0]["volumeMounts"][0]["mountPath"] == "/certs"
    assert spec["containers"][0]["volumeMounts"][0]["readOnly"] is True


def test_inject_volume_mount_requires_mount_path():
    apps = FakeApps(make_workload([{"name": "app"}]))
    mapping = [{"localKey": "tls.crt", "type": "VolumeMount"}]
    with pytest.raises(ZeroTrustSecretError):
        _inject_mapping_to_workload("zts", "s", mapping, "Deployment", "default", "orders-api", apps, FakeApiClient())


def test_inject_no_containers_raises():
    apps = FakeApps(make_workload([]))
    with pytest.raises(ZeroTrustSecretError):
        _inject_mapping_to_workload("zts", "s", [{"localKey": "X", "type": "EnvVar"}], "Deployment", "default", "orders-api", apps, FakeApiClient())


# --------------------------------------------------------------------------- #
# _get_target validation (the ZeroTrustSecretError types cleanup now catches)
# --------------------------------------------------------------------------- #
def test_get_target_rejects_invalid_kind():
    with pytest.raises(ZeroTrustSecretError):
        _get_target("default", {"kind": "Pod", "name": "x"}, FakeApps(make_workload([])), FakeApiClient())


def test_get_target_requires_name():
    with pytest.raises(ZeroTrustSecretError):
        _get_target("default", {"kind": "Deployment", "name": ""}, FakeApps(make_workload([])), FakeApiClient())


# --------------------------------------------------------------------------- #
# lastError formatting (no raw HTTP dump from ApiException)
# --------------------------------------------------------------------------- #
def test_format_error_trims_apiexception():
    from zta_operator.zerotrust_secret import _format_error

    exc = ApiException(status=404, reason="Not Found")
    exc.body = '{"kind":"Status","message":"deployments.apps \\"orders-api\\" not found","reason":"NotFound","code":404}'
    out = _format_error(exc)
    assert out.startswith("404")
    assert "deployments.apps" in out
    assert "HTTPHeaderDict" not in out and "HTTP response" not in out


def test_format_error_passes_through_plain_exceptions():
    from zta_operator.zerotrust_secret import _format_error

    assert _format_error(ZeroTrustSecretError("plain message")) == "plain message"
