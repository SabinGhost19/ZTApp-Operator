import json
import subprocess
from dataclasses import dataclass
from typing import Any

from .config import (
    COSIGN_BIN,
    DEFAULT_ISSUER,
    SEVERITY_ORDER,
    TRIVY_BIN,
    TRIVY_TIMEOUT_SECONDS,
    VERIFY_TIMEOUT_SECONDS,
)


class SupplyChainError(Exception):
    pass


@dataclass
class VerificationResult:
    success: bool
    reason: str
    details: dict[str, Any]


def validate_image_reference(image: str) -> None:
    if not image.startswith("ghcr.io/"):
        raise SupplyChainError("Image must use ghcr.io registry.")
    if "@sha256:" in image:
        return
    if ":" not in image.rsplit("/", 1)[-1]:
        raise SupplyChainError("Image tag is required and must be immutable (e.g. v1.0.0).")
    tag = image.rsplit(":", 1)[-1]
    if tag.lower() == "latest":
        raise SupplyChainError("Tag 'latest' is forbidden.")


def verify_cosign_keyless(image: str, allowed_signer: str) -> VerificationResult:
    cmd = [
        COSIGN_BIN,
        "verify",
        image,
        "--certificate-identity",
        allowed_signer,
        "--certificate-oidc-issuer",
        DEFAULT_ISSUER,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=VERIFY_TIMEOUT_SECONDS)
    if result.returncode != 0:
        return VerificationResult(
            success=False,
            reason="cosign-verification-failed",
            details={"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode},
        )
    return VerificationResult(success=True, reason="ok", details={"stdout": result.stdout})


def _max_found_severity(payload: dict[str, Any]) -> str | None:
    max_value = 0
    max_name: str | None = None
    for section in payload.get("Results", []):
        for vuln in section.get("Vulnerabilities", []) or []:
            sev = str(vuln.get("Severity", "")).upper()
            value = SEVERITY_ORDER.get(sev, 0)
            if value > max_value:
                max_value = value
                max_name = sev
    return max_name


def verify_trivy_threshold(image: str, max_vulnerabilities: str) -> VerificationResult:
    threshold = str(max_vulnerabilities).upper()
    if threshold not in SEVERITY_ORDER:
        raise SupplyChainError(f"Invalid maxVulnerabilities: {max_vulnerabilities}")

    cmd = [TRIVY_BIN, "image", "--format", "json", image]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=TRIVY_TIMEOUT_SECONDS)
    if result.returncode != 0:
        return VerificationResult(
            success=False,
            reason="trivy-scan-failed",
            details={"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode},
        )

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SupplyChainError("Trivy output is not valid JSON.") from exc

    highest = _max_found_severity(payload)
    if highest is None:
        return VerificationResult(success=True, reason="ok", details={"highest": "NONE", "threshold": threshold})

    if SEVERITY_ORDER[highest] > SEVERITY_ORDER[threshold]:
        return VerificationResult(
            success=False,
            reason="trivy-threshold-exceeded",
            details={"highest": highest, "threshold": threshold},
        )

    return VerificationResult(success=True, reason="ok", details={"highest": highest, "threshold": threshold})


def verify_supply_chain(image: str, require_signature: bool, allowed_signer: str, max_vulnerabilities: str) -> VerificationResult:
    validate_image_reference(image)

    if require_signature:
        if not allowed_signer:
            raise SupplyChainError("allowedSigner is required when requireSignature is true.")
        cosign_result = verify_cosign_keyless(image=image, allowed_signer=allowed_signer)
        if not cosign_result.success:
            return cosign_result

    return verify_trivy_threshold(image=image, max_vulnerabilities=max_vulnerabilities)
