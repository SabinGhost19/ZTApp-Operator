import asyncio
import json
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


async def _run_subprocess(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    """Run a subprocess without blocking the event loop.

    Returns (returncode, stdout_text, stderr_text). Raises TimeoutError on
    timeout (caller decides whether to wrap as SupplyChainError).
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise SupplyChainError(f"Command timed out after {timeout}s: {' '.join(cmd[:2])}")
    return proc.returncode or 0, stdout_bytes.decode("utf-8", errors="replace"), stderr_bytes.decode("utf-8", errors="replace")


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


async def verify_cosign_keyless(image: str, allowed_signer: str) -> VerificationResult:
    cmd = [
        COSIGN_BIN,
        "verify",
        image,
        "--certificate-identity",
        allowed_signer,
        "--certificate-oidc-issuer",
        DEFAULT_ISSUER,
    ]
    returncode, stdout, stderr = await _run_subprocess(cmd, timeout=VERIFY_TIMEOUT_SECONDS)
    if returncode != 0:
        return VerificationResult(
            success=False,
            reason="cosign-verification-failed",
            details={"stdout": stdout, "stderr": stderr, "returncode": returncode},
        )
    return VerificationResult(success=True, reason="ok", details={"stdout": stdout})


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


def _has_fixable_vulnerabilities(payload: dict[str, Any]) -> bool:
    for section in payload.get("Results", []):
        for vuln in section.get("Vulnerabilities", []) or []:
            fixed_version = str(vuln.get("FixedVersion", "")).strip()
            if fixed_version:
                return True
    return False


def _collect_findings(
    payload: dict[str, Any],
    *,
    fixable_only: bool = False,
    min_severity: str | None = None,
    limit: int = 300,
) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Extract a capped, UI-friendly list of vulnerabilities plus a per-severity
    count. `fixable_only` keeps only vulns with a FixedVersion; `min_severity`
    keeps only vulns at/above that severity (used for threshold breaches)."""
    floor = SEVERITY_ORDER.get(str(min_severity).upper(), 0) if min_severity else 0
    findings: list[dict[str, str]] = []
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for section in payload.get("Results", []) or []:
        target = str(section.get("Target", ""))
        for vuln in section.get("Vulnerabilities", []) or []:
            sev = str(vuln.get("Severity", "")).upper()
            if sev in counts:
                counts[sev] += 1
            fixed = str(vuln.get("FixedVersion", "")).strip()
            if fixable_only and not fixed:
                continue
            if floor and SEVERITY_ORDER.get(sev, 0) < floor:
                continue
            if len(findings) < limit:
                findings.append({
                    "id": str(vuln.get("VulnerabilityID", "")),
                    "pkg": str(vuln.get("PkgName", "")),
                    "severity": sev,
                    "installed": str(vuln.get("InstalledVersion", "")),
                    "fixedVersion": fixed,
                    "title": str(vuln.get("Title", "") or "")[:160],
                    "target": target,
                    # Canonical reference Trivy cites for this vuln (usually the
                    # NVD/GHSA/advisory page); the UI links to it.
                    "primaryUrl": str(vuln.get("PrimaryURL", "")),
                })
    return findings, counts


async def verify_trivy_threshold(
    image: str,
    max_vulnerabilities: str,
    fail_on_fixable: bool = False,
    vex_statements: list | None = None,
) -> VerificationResult:
    threshold = str(max_vulnerabilities).upper()
    if threshold not in SEVERITY_ORDER:
        raise SupplyChainError(f"Invalid maxVulnerabilities: {max_vulnerabilities}")

    cmd = [TRIVY_BIN, "image", "--format", "json", image]
    returncode, stdout, stderr = await _run_subprocess(cmd, timeout=TRIVY_TIMEOUT_SECONDS)
    if returncode != 0:
        return VerificationResult(
            success=False,
            reason="trivy-scan-failed",
            details={"stdout": stdout, "stderr": stderr, "returncode": returncode},
        )

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise SupplyChainError("Trivy output is not valid JSON.") from exc

    exempted_cves: list[str] = []
    if vex_statements:
        from .vex import filter_trivy_vulnerabilities

        payload, exempted_cves = filter_trivy_vulnerabilities(payload, vex_statements)

    highest = _max_found_severity(payload)
    if fail_on_fixable and _has_fixable_vulnerabilities(payload):
        # Record EVERY detected vuln (fixable ones are flagged via fixedVersion)
        # so the UI dropdown can list the full Trivy result, not just the trigger.
        findings, counts = _collect_findings(payload)
        return VerificationResult(
            success=False,
            reason="trivy-fixable-vulnerability-found",
            details={
                "threshold": threshold,
                "failOnFixable": True,
                "highest": highest or "NONE",
                "counts": counts,
                "findings": findings,
                "vexExempted": exempted_cves,
            },
        )

    if highest is None:
        return VerificationResult(
            success=True,
            reason="ok",
            details={"highest": "NONE", "threshold": threshold, "vexExempted": exempted_cves},
        )

    if SEVERITY_ORDER[highest] > SEVERITY_ORDER[threshold]:
        # Record ALL detected vulns (full Trivy result) for the UI dropdown.
        findings, counts = _collect_findings(payload)
        return VerificationResult(
            success=False,
            reason="trivy-threshold-exceeded",
            details={
                "highest": highest,
                "threshold": threshold,
                "counts": counts,
                "findings": findings,
                "vexExempted": exempted_cves,
            },
        )

    return VerificationResult(
        success=True,
        reason="ok",
        details={
            "highest": highest,
            "threshold": threshold,
            "failOnFixable": fail_on_fixable,
            "vexExempted": exempted_cves,
        },
    )


async def verify_supply_chain(
    image: str,
    require_signature: bool,
    trusted_identities: list[str],
    max_vulnerabilities: str,
    fail_on_fixable: bool = False,
    vex_statements: list | None = None,
) -> VerificationResult:
    validate_image_reference(image)

    if require_signature:
        identities = [identity for identity in trusted_identities if str(identity).strip()]
        if not identities:
            raise SupplyChainError("At least one trusted identity is required when requireSignature is true.")
        last_result: VerificationResult | None = None
        for identity in identities:
            cosign_result = await verify_cosign_keyless(image=image, allowed_signer=str(identity).strip())
            if cosign_result.success:
                last_result = cosign_result
                break
            last_result = cosign_result
        if not last_result or not last_result.success:
            return last_result or VerificationResult(success=False, reason="cosign-verification-failed", details={})

    if vex_statements is None:
        identities = [identity for identity in trusted_identities if str(identity).strip()]
        if identities:
            try:
                from .vex import fetch_vex_statements

                vex_statements = await fetch_vex_statements(image=image, trusted_issuers=identities)
            except Exception:
                vex_statements = []

    return await verify_trivy_threshold(
        image=image,
        max_vulnerabilities=max_vulnerabilities,
        fail_on_fixable=fail_on_fixable,
        vex_statements=vex_statements,
    )
