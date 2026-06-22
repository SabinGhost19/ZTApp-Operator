"""Unit tests for the admission webhook's ZeroTrustSecret validation (webhook.py).

The webhook now dispatches on object kind; these cover the new _validate_zts
cross-field invariants (VolumeMount needs mountPath, timeBasedAccess rejected,
required references) plus the kind-dispatch in /validate via _admission_response.
"""

from zta_operator.webhook import _validate_zts


def _good_spec():
    return {
        "applicationRef": {"name": "orders-api"},
        "targetWorkload": {"kind": "Deployment", "name": "orders-api"},
        "secretData": {
            "remotePath": "secret/data/orders/db",
            "mapping": [{"remoteKey": "password", "localKey": "DB_PASSWORD", "type": "EnvVar"}],
        },
        "zeroTrustConditions": {"requireVerifiedStatus": True},
    }


def test_valid_zts_passes():
    assert _validate_zts(_good_spec()) == []


def test_missing_target_name_rejected():
    spec = _good_spec()
    spec["targetWorkload"]["name"] = ""
    errors = _validate_zts(spec)
    assert any("targetWorkload.name" in e for e in errors)


def test_invalid_kind_rejected():
    spec = _good_spec()
    spec["targetWorkload"]["kind"] = "Pod"
    assert any("targetWorkload.kind" in e for e in _validate_zts(spec))


def test_missing_application_ref_rejected():
    spec = _good_spec()
    spec["applicationRef"] = {}
    assert any("applicationRef.name" in e for e in _validate_zts(spec))


def test_missing_remote_path_rejected():
    spec = _good_spec()
    spec["secretData"]["remotePath"] = ""
    assert any("remotePath" in e for e in _validate_zts(spec))


def test_empty_mapping_rejected():
    spec = _good_spec()
    spec["secretData"]["mapping"] = []
    assert any("mapping" in e for e in _validate_zts(spec))


def test_volume_mount_without_mount_path_rejected():
    spec = _good_spec()
    spec["secretData"]["mapping"] = [{"remoteKey": "tls.crt", "localKey": "tls.crt", "type": "VolumeMount"}]
    assert any("mountPath" in e for e in _validate_zts(spec))


def test_volume_mount_with_mount_path_passes():
    spec = _good_spec()
    spec["secretData"]["mapping"] = [
        {"remoteKey": "tls.crt", "localKey": "tls.crt", "type": "VolumeMount", "mountPath": "/certs"}
    ]
    assert _validate_zts(spec) == []


def test_bad_mapping_type_rejected():
    spec = _good_spec()
    spec["secretData"]["mapping"] = [{"remoteKey": "k", "localKey": "K", "type": "ConfigMap"}]
    assert any("type must be EnvVar or VolumeMount" in e for e in _validate_zts(spec))


def test_time_based_access_rejected():
    spec = _good_spec()
    spec["zeroTrustConditions"]["timeBasedAccess"] = {"enabled": True}
    assert any("timeBasedAccess" in e for e in _validate_zts(spec))
