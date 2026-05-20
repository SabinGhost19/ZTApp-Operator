"""OpenVEX (Vulnerability Exploitability eXchange) integration.

VEX gives an auditor a signed mechanism to declare CVEs as `not_affected`,
`fixed`, or `under_investigation` for a specific product. We fetch the
OpenVEX predicate attested via `cosign attest --type vex` and use it to
suppress Trivy findings that have been formally justified — without
silently weakening the policy: every suppression emits a K8s Event so
the audit trail remains intact.

Spec reference: https://openvex.dev/spec/v0.2.0 / NIST SSDF PW.4.4.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from dataclasses import dataclass
from typing import Any

from .config import COSIGN_BIN, DEFAULT_ISSUER, VERIFY_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)

# Statuses that justify suppressing a Trivy finding. `affected` and
# `under_investigation` must NEVER suppress — they are not justifications.
_SUPPRESSING_STATUSES = {"not_affected", "fixed"}


@dataclass
class VexStatement:
    cve: str
    status: str
    justification: str
    impact_statement: str

    def suppresses(self) -> bool:
        return self.status.strip().lower() in _SUPPRESSING_STATUSES


async def fetch_vex_statements(
    image: str,
    trusted_issuers: list[str],
) -> list[VexStatement]:
    """Fetch and parse the OpenVEX attestation for an image.

    Returns an empty list if no VEX is attached (best-effort: VEX is opt-in).
    """
    last_error = ""
    for identity in trusted_issuers:
        cmd = [
            COSIGN_BIN,
            "verify-attestation",
            image,
            "--type",
            "vex",
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            DEFAULT_ISSUER,
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=VERIFY_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            continue
        if (proc.returncode or 0) != 0:
            last_error = stderr_bytes.decode("utf-8", errors="replace")
            continue

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                envelope = json.loads(line)
                payload_b64 = envelope.get("payload")
                if not payload_b64:
                    continue
                statement = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
                predicate = statement.get("predicate") or {}
                return _parse_openvex_predicate(predicate)
            except (json.JSONDecodeError, ValueError):
                continue

    if last_error:
        logger.info("No VEX attestation found (continuing)", extra={"event": "vex-absent", "error": last_error[:200]})
    return []


def _parse_openvex_predicate(predicate: dict[str, Any]) -> list[VexStatement]:
    statements: list[VexStatement] = []
    for raw in predicate.get("statements", []) or []:
        vuln = raw.get("vulnerability") or {}
        cve = str(vuln.get("name") or vuln.get("@id") or "").strip()
        status = str(raw.get("status") or "").strip()
        if not cve or not status:
            continue
        statements.append(
            VexStatement(
                cve=cve,
                status=status,
                justification=str(raw.get("justification") or "").strip(),
                impact_statement=str(raw.get("impact_statement") or "").strip(),
            )
        )
    return statements


def filter_trivy_vulnerabilities(
    trivy_payload: dict[str, Any],
    vex_statements: list[VexStatement],
) -> tuple[dict[str, Any], list[str]]:
    """Strip Trivy findings that have a suppressing VEX statement.

    Returns (filtered_payload, exempted_cve_ids). The caller is responsible
    for emitting K8s events for each exempted CVE.
    """
    if not vex_statements:
        return trivy_payload, []

    suppressing = {s.cve.upper() for s in vex_statements if s.suppresses()}
    if not suppressing:
        return trivy_payload, []

    exempted: list[str] = []
    new_results = []
    for section in trivy_payload.get("Results", []) or []:
        kept = []
        for vuln in section.get("Vulnerabilities", []) or []:
            cve_id = str(vuln.get("VulnerabilityID", "")).upper()
            if cve_id in suppressing:
                exempted.append(cve_id)
                continue
            kept.append(vuln)
        new_section = dict(section)
        new_section["Vulnerabilities"] = kept
        new_results.append(new_section)

    filtered = dict(trivy_payload)
    filtered["Results"] = new_results
    return filtered, exempted
