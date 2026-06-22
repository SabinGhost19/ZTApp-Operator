"""Validating admission webhook (synchronous gate in front of Kopf).

Kopf is a controller-loop framework (eventual consistency): malformed ZTA
resources still reach etcd before being marked Failed, polluting the cluster
and consuming reconcile cycles. This sidecar provides a *synchronous* rejection
path so that resources missing a `securityPolicyRef`, using `:latest` tags, or
carrying malformed digests are refused at `kubectl apply` time with an
admission error visible directly to the user.

The webhook intentionally performs only fast, dependency-free checks. Heavy
cryptographic validation (Cosign, Rekor, VBBI Merkle replay) remains in the
Kopf-based reconcile loop.
"""

from __future__ import annotations

import base64
import json
import re
import sys
from typing import Any

from fastapi import FastAPI, Request

app = FastAPI(title="zta-admission", version="1.0")

# RFC 6920 / OCI digest grammar (sha256 only, hex lowercase, 64 chars).
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_IMAGE_RE = re.compile(r"^[a-z0-9.\-/_:]+@sha256:[a-f0-9]{64}$")
_HEX64_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def _admission_response(uid: str, allowed: bool, message: str = "") -> dict[str, Any]:
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": allowed,
            "status": {"message": message[:1024]} if message else {"message": "ok"},
        },
    }


def _validate_zta(spec: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    image = str(spec.get("image", "")).strip()
    if not image:
        errors.append("spec.image is required")
    elif image.endswith(":latest") or ":latest@" in image:
        errors.append("spec.image must not use :latest tag (immutable digest required)")
    elif "@sha256:" not in image:
        errors.append("spec.image must be pinned to an immutable @sha256: digest")
    elif not _IMAGE_RE.match(image):
        errors.append(f"spec.image format invalid: {image!r}")

    policy_ref = spec.get("securityPolicyRef") or {}
    policy_name = str(policy_ref.get("name", "")).strip()
    if not policy_name:
        errors.append("spec.securityPolicyRef.name is required")

    expected_hash = str(spec.get("expectedInfraHash", "")).strip()
    if expected_hash and not _HEX64_RE.match(expected_hash):
        errors.append(
            f"spec.expectedInfraHash must be 64-char lowercase hex SHA-256, got: {expected_hash!r}"
        )

    return errors


def _validate_zts(spec: dict[str, Any]) -> list[str]:
    """Fast, dependency-free semantic checks for ZeroTrustSecret.

    Mirrors the cross-field invariants the Kopf reconcile enforces (and the
    structural CRD schema cannot express): VolumeMount requires mountPath, and
    timeBasedAccess is not implemented. Also re-asserts required references so a
    malformed ZTS is refused at `kubectl apply` time instead of looping in
    reconcile as Degraded.
    """
    errors: list[str] = []

    target = spec.get("targetWorkload") or {}
    if str(target.get("kind", "")).strip() not in {"Deployment", "StatefulSet", "DaemonSet"}:
        errors.append("spec.targetWorkload.kind must be one of Deployment, StatefulSet, DaemonSet")
    if not str(target.get("name", "")).strip():
        errors.append("spec.targetWorkload.name is required")

    app_ref = spec.get("applicationRef") or {}
    if not str(app_ref.get("name", "")).strip():
        errors.append("spec.applicationRef.name is required")

    secret_data = spec.get("secretData") or {}
    if not str(secret_data.get("remotePath", "")).strip():
        errors.append("spec.secretData.remotePath is required")
    mapping = secret_data.get("mapping") or []
    if not mapping:
        errors.append("spec.secretData.mapping must contain at least one item")
    for i, item in enumerate(mapping):
        if not isinstance(item, dict):
            errors.append(f"spec.secretData.mapping[{i}] must be an object")
            continue
        if not str(item.get("remoteKey", "")).strip():
            errors.append(f"spec.secretData.mapping[{i}].remoteKey is required")
        if not str(item.get("localKey", "")).strip():
            errors.append(f"spec.secretData.mapping[{i}].localKey is required")
        m_type = str(item.get("type", "")).strip()
        if m_type not in {"EnvVar", "VolumeMount"}:
            errors.append(f"spec.secretData.mapping[{i}].type must be EnvVar or VolumeMount")
        if m_type == "VolumeMount" and not str(item.get("mountPath", "")).strip():
            errors.append(f"spec.secretData.mapping[{i}].mountPath is required when type is VolumeMount")

    ztc = spec.get("zeroTrustConditions") or {}
    if (ztc.get("timeBasedAccess") or {}).get("enabled", False):
        errors.append(
            "spec.zeroTrustConditions.timeBasedAccess.enabled=true is not implemented in this version"
        )

    return errors


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/validate")
async def validate(request: Request) -> dict[str, Any]:
    body = await request.json()
    review_request = body.get("request", {}) or {}
    uid = str(review_request.get("uid", ""))
    obj = review_request.get("object", {}) or {}
    kind = (obj.get("kind") or "").strip()
    spec = obj.get("spec", {}) or {}

    if kind == "ZeroTrustApplication":
        errors = _validate_zta(spec)
    elif kind == "ZeroTrustSecret":
        errors = _validate_zts(spec)
    else:
        # Defer to other webhooks for unhandled kinds — admit by default.
        return _admission_response(uid, True, f"webhook does not handle kind={kind}")

    if errors:
        return _admission_response(
            uid,
            False,
            f"{kind} rejected by admission webhook: " + "; ".join(errors),
        )
    return _admission_response(uid, True)


def main() -> None:
    import uvicorn

    cert = "/tls/tls.crt"
    key = "/tls/tls.key"
    uvicorn.run(
        "zta_operator.webhook:app",
        host="0.0.0.0",
        port=8443,
        ssl_certfile=cert,
        ssl_keyfile=key,
        log_level="info",
    )


if __name__ == "__main__":
    main()
