"""Pull-based GUAC ingestion from inside the cluster.

Rationale (vs the original CI/CD push model):

  *Network*       Zero-Trust environments keep the GUAC collector on a
                  private VPC. The CI/CD runner cannot reach it without
                  exposing an inbound endpoint to the public internet.
                  Operator-side pull respects the principle of "no
                  inbound traffic" — only outbound: registry + intra-cluster.

  *Garbage*       The CI/CD push model floods GUAC with SBOMs for every
                  branch, PR and tag, including code that never reaches
                  production. Pulling at admission time means GUAC only
                  knows about images that actually run in K8s.

  *Secrets*       No GUAC tokens in GitHub Actions; all auth stays in
                  K8s Secrets, never crossing the cluster boundary.

Concurrency: this is run from a background thread (started by the Kopf
reconciler). The thread fetches SBOM + VEX from OCI via `cosign download
attestation`, pushes them to the GUAC collector REST endpoint, then
PATCHes the ZTA status with the final state. The reconcile loop returns
immediately with `guacIngestionStatus: InProgress` — the UI surfaces this
as a spinner that resolves to a checkmark once the worker finishes.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
import threading
from datetime import datetime, timezone
from typing import Any

from .config import COSIGN_BIN, GROUP, PLURAL, VERSION

logger = logging.getLogger("zta_operator.guac_client")


def _endpoint() -> str:
    return str(os.environ.get("GUAC_GRAPHQL_URL", "")).strip()


def _collector_endpoint() -> str:
    """GUAC's REST-style ingest endpoint accepts raw SBOM / VEX documents.
    Convention: if GUAC_GRAPHQL_URL ends with `/query`, swap to `/v0/collect`;
    otherwise honour an explicit `GUAC_COLLECTOR_URL` env var.
    """
    explicit = str(os.environ.get("GUAC_COLLECTOR_URL", "")).strip()
    if explicit:
        return explicit
    graphql = _endpoint()
    if graphql.endswith("/query"):
        return graphql[: -len("/query")] + "/v0/collect"
    return graphql


def _cosign_download_attestation(image: str, predicate_type: str) -> dict | None:
    """Pull a single attestation from the OCI registry by predicate type.

    Returns the decoded predicate dict, or None on any failure. We use the
    `cosign download attestation` subcommand because the OCI artifact for
    attestations is multi-blob (DSSE-wrapped) and re-implementing the
    decode in Python would duplicate a non-trivial amount of Sigstore code.
    """
    try:
        result = subprocess.run(
            [
                COSIGN_BIN,
                "download",
                "attestation",
                image,
                "--predicate-type",
                predicate_type,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.info(
            "cosign attestation download skipped",
            extra={"event": "guac-cosign-download-skipped", "error": str(exc)},
        )
        return None

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            envelope = json.loads(line)
            payload_b64 = envelope.get("payload")
            if not payload_b64:
                continue
            statement = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
            predicate = statement.get("predicate")
            if isinstance(predicate, dict):
                return predicate
        except (json.JSONDecodeError, ValueError):
            continue
    return None


def _push_to_collector(payload: dict, document_format: str) -> bool:
    url = _collector_endpoint()
    if not url:
        return False
    try:
        import httpx
    except ImportError:
        logger.info(
            "httpx not installed; GUAC client disabled",
            extra={"event": "guac-skipped"},
        )
        return False

    try:
        with httpx.Client(timeout=15.0) as http:
            response = http.post(
                url,
                content=json.dumps({"format": document_format, "document": payload}),
                headers={"Content-Type": "application/json"},
            )
            return response.status_code < 300
    except Exception as exc:
        logger.info(
            "GUAC collector push failed",
            extra={"event": "guac-collector-failed", "error": str(exc)},
        )
        return False


def _patch_status_sync(namespace: str, app_name: str, ingestion_status: str, message: str) -> None:
    """Best-effort PATCH of the ZTA status. Uses the synchronous K8s client
    because we are inside a worker thread (no asyncio loop available).
    """
    try:
        from kubernetes import client, config as kconfig

        try:
            kconfig.load_incluster_config()
        except Exception:
            kconfig.load_kube_config()

        api = client.CustomObjectsApi()
        body = {
            "status": {
                "guacIngestionStatus": ingestion_status,
                "guacIngestionMessage": message[:512],
                "guacIngestionCompletedAt": datetime.now(timezone.utc).isoformat()
                if ingestion_status in ("Completed", "Failed")
                else "",
            }
        }
        api.patch_namespaced_custom_object_status(
            group=GROUP,
            version=VERSION,
            namespace=namespace,
            plural=PLURAL,
            name=app_name,
            body=body,
        )
    except Exception as exc:
        logger.warning(
            "Failed to PATCH guacIngestionStatus",
            extra={
                "event": "guac-status-patch-failed",
                "namespace": namespace,
                "name": app_name,
                "error": str(exc)[:200],
            },
        )


def _ingest_worker(image: str, namespace: str, app_name: str) -> None:
    """Background job: pull SBOM + VEX from OCI, push to GUAC collector,
    finalize ZTA status. Never raises — all errors surface as a
    `guacIngestionStatus: Failed` patch with a human-readable reason.
    """
    pulled_any = False
    pushed_any = False

    sbom = _cosign_download_attestation(image, "https://spdx.dev/Document")
    if sbom is None:
        sbom = _cosign_download_attestation(image, "spdxjson")
    if sbom is not None:
        pulled_any = True
        if _push_to_collector(sbom, "DOCUMENT_SPDX"):
            pushed_any = True

    vex = _cosign_download_attestation(image, "https://openvex.dev/ns/v0.2.0")
    if vex is None:
        vex = _cosign_download_attestation(image, "vex")
    if vex is not None:
        pulled_any = True
        if _push_to_collector(vex, "DOCUMENT_OPENVEX"):
            pushed_any = True

    # Always emit the deployment edge — it is the cheap mutation that
    # links the OCI image to the K8s deployment, independent of whether
    # the heavier SBOM/VEX payload was retrievable.
    deployment_edge_ok = _emit_deployment_edge(image, namespace, app_name)

    if pulled_any and pushed_any:
        _patch_status_sync(
            namespace, app_name, "Completed",
            f"GUAC graph updated (SBOM/VEX pulled from OCI, deployment edge: {'ok' if deployment_edge_ok else 'skipped'}).",
        )
    elif deployment_edge_ok and not pulled_any:
        _patch_status_sync(
            namespace, app_name, "Completed",
            "GUAC graph updated with deployment edge only — no SBOM/VEX attestation found on the image.",
        )
    else:
        _patch_status_sync(
            namespace, app_name, "Failed",
            "GUAC ingestion did not complete. Image may lack attestations, or GUAC collector is unreachable.",
        )


def _emit_deployment_edge(image: str, namespace: str, app_name: str) -> bool:
    """GraphQL mutation that links the OCI image to the K8s deployment.
    This is the cluster-side contribution to GUAC: GUAC alone never sees
    where an image actually runs.
    """
    url = _endpoint()
    if not url:
        return False
    try:
        import httpx
    except ImportError:
        return False

    mutation = """
    mutation IngestHasSourceAt($image: String!, $location: String!, $time: Time!) {
      ingestHasSourceAt(
        pkg: { type: "oci", name: $image, version: "" }
        source: { type: "k8s", namespace: "deployment", name: $location, tag: "" }
        hasSourceAt: { knownSince: $time, justification: "deployed by zta-operator", origin: "zta-operator", collector: "zta-operator" }
      ) { id }
    }
    """
    variables = {
        "image": image,
        "location": f"{namespace}/{app_name}",
        "time": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with httpx.Client(timeout=5.0) as http:
            response = http.post(
                url,
                content=json.dumps({"query": mutation, "variables": variables}),
                headers={"Content-Type": "application/json"},
            )
            return response.status_code < 300
    except Exception:
        return False


def trigger_guac_ingestion(image: str, namespace: str, app_name: str) -> bool:
    """Public entry point called from the Kopf reconcile loop.

    Decouples the slow OCI/GUAC I/O from the K8s reconciliation window:
    the reconciler returns immediately while a daemon thread does the
    actual work and PATCHes status when done.

    Returns True if a worker was started, False if GUAC is disabled
    (the env var is unset).
    """
    if not _endpoint():
        return False
    thread = threading.Thread(
        target=_ingest_worker,
        args=(image, namespace, app_name),
        name=f"guac-ingest-{namespace}-{app_name}",
        daemon=True,
    )
    thread.start()
    return True


# Backwards-compat shim — kept so existing call sites compile until
# they are migrated to the new entry point.
def ingest_deployment_link(
    image: str,
    namespace: str,
    app_name: str,
    cluster_name: str = "default",
) -> bool:
    return _emit_deployment_edge(image, namespace, app_name)
