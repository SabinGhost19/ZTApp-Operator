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

    if kind != "ZeroTrustApplication":
        # Defer to other webhooks for non-ZTA kinds — admit by default.
        return _admission_response(uid, True, f"webhook does not handle kind={kind}")

    errors = _validate_zta(spec)
    if errors:
        return _admission_response(
            uid,
            False,
            "ZeroTrustApplication rejected by admission webhook: " + "; ".join(errors),
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
