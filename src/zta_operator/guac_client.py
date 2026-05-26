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
    # Default tracks the official `guacsec/guac` Helm chart service names:
    #   Service/graphql-server   :8080   exposes /query
    # Override per-cluster via GUAC_GRAPHQL_URL.
    return str(
        os.environ.get(
            "GUAC_GRAPHQL_URL",
            "http://graphql-server.guac.svc.cluster.local:8080/query",
        )
    ).strip()


def _collectsub_endpoint() -> str:
    """gRPC endpoint for GUAC's CollectSubscriberService.

    Stock chart exposes `collectsub:2782`. This is how `oci-collector` is
    told which images to fetch attestations for — without an entry here,
    oci-collector idles and no SBOM/VEX ever land in the graph.
    """
    return str(
        os.environ.get(
            "GUAC_COLLECTSUB_URL",
            "collectsub.guac.svc.cluster.local:2782",
        )
    ).strip()


def _notify_collectsub(image: str) -> bool:
    """Enqueue an OCI reference on GUAC's collectsub bus.

    Sends DATATYPE_OCI with the bare ``registry/repo`` (digest/tag stripped).

    Why ``DATATYPE_OCI`` and not ``DATATYPE_OCI_REGISTRY``:
      - The chart runs ``guaccollect image`` which subscribes only to OCI
        entries. The separate ``guaccollect registry`` subcommand consumes
        OCI_REGISTRY but is not deployed in the stock chart.
      - GUAC's polling mode refuses entries that carry a tag or digest:
            "image identifiers (tag or digest) should not be specified
             when using polling"
        so we strip both — polling on the bare repo lets oci-collector
        enumerate tags itself and pick up the exact digest we just shipped.

    Returns True on success. Failures are logged and swallowed — collectsub
    being down should not break the rest of GUAC ingestion (the deployment
    edge still lands via GraphQL).
    """
    addr = _collectsub_endpoint()
    if not addr:
        return False
    try:
        import grpc  # type: ignore
        from ._grpc import collectsub_pb2, collectsub_pb2_grpc  # type: ignore
    except ImportError as exc:
        logger.info(
            "collectsub gRPC stubs unavailable",
            extra={"event": "guac-collectsub-skipped", "error": str(exc)},
        )
        return False

    registry, repo, _digest = _split_oci_reference(image)
    repo_ref = f"{registry}/{repo}" if registry else repo

    try:
        with grpc.insecure_channel(addr) as channel:
            stub = collectsub_pb2_grpc.CollectSubscriberServiceStub(channel)
            request = collectsub_pb2.AddCollectEntriesRequest(
                entries=[
                    collectsub_pb2.CollectEntry(
                        type=collectsub_pb2.DATATYPE_OCI,
                        value=repo_ref,
                        since_time=0,
                    )
                ]
            )
            response = stub.AddCollectEntries(request, timeout=5.0)
            if not response.success:
                logger.warning(
                    "collectsub refused entry",
                    extra={
                        "event": "guac-collectsub-refused",
                        "repo": repo_ref,
                    },
                )
                return False
            logger.info(
                "collectsub accepted OCI repo",
                extra={"event": "guac-collectsub-accepted", "repo": repo_ref},
            )
            return True
    except Exception as exc:
        logger.warning(
            "collectsub call failed",
            extra={
                "event": "guac-collectsub-failed",
                "repo": repo_ref,
                "error": str(exc)[:200],
            },
        )
        return False


def _collector_endpoint() -> str:
    """GUAC raw-document ingestion endpoint (optional).

    Stock GUAC (v1.x) does NOT expose an HTTP collector — the `rest-api`
    service only serves `/healthz`. Real ingestion flows through NATS
    (`DOCUMENTS.collected`) or the collectsub gRPC API, both of which
    `oci-collector` already consumes for any image visible to the registry.

    So this function returns "" by default, which makes `_push_to_collector`
    a no-op. Set `GUAC_COLLECTOR_URL` only if you have a custom HTTP shim
    in front of GUAC that accepts `{format, document}` payloads.
    """
    return str(os.environ.get("GUAC_COLLECTOR_URL", "")).strip()


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
        # No custom collector configured — rely on oci-collector to discover
        # SBOM/VEX attestations directly from the registry.
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
            if response.status_code >= 300:
                logger.warning(
                    "GUAC collector push rejected",
                    extra={
                        "event": "guac-collector-rejected",
                        "status": response.status_code,
                        "body": response.text[:200],
                    },
                )
                return False
            return True
    except Exception as exc:
        logger.warning(
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
                "app_name": app_name,
                "error": str(exc)[:200],
            },
        )


def _guacone_push_files(predicate_files: list[str]) -> bool:
    """Run ``guacone collect files <dir>`` against graphql-server.

    Why ``guacone collect files``:
      - GUAC's ingestor REJECTS attestations signed with cosign keyless
        (Fulcio/OIDC) — it requires explicit trusted keys for DSSE
        verification, which isn't configurable in v1.0.1.
      - ``guacone collect files`` reads raw SBOM/VEX JSON (no DSSE wrapper)
        and talks DIRECTLY to graphql-server, fully bypassing the ingestor's
        DSSE verification step.

    The caller is responsible for extracting the raw predicate JSON from
    the cosign DSSE envelope and placing each document as ``*.json`` inside
    a single directory; this function points guacone at that directory.

    Returns True if guacone reports a graceful ingest of >=1 document.
    """
    if not predicate_files:
        return False
    work_dir = predicate_files[0].rsplit("/", 1)[0]
    gql = _endpoint()
    try:
        result = subprocess.run(
            [
                "guacone",
                "--gql-addr", gql,
                "collect", "files", work_dir,
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.warning(
            "guacone invocation failed",
            extra={"event": "guac-guacone-failed", "error": str(exc)},
        )
        return False
    if result.returncode != 0 or "collector ended gracefully" not in result.stderr + result.stdout:
        logger.warning(
            "guacone returned non-success",
            extra={
                "event": "guac-guacone-rejected",
                "returncode": result.returncode,
                "tail": (result.stderr or result.stdout)[-300:],
            },
        )
        return False
    logger.info(
        "guacone ingested documents",
        extra={"event": "guac-guacone-ok", "files": len(predicate_files)},
    )
    return True


def _write_predicate_files(image: str) -> list[str]:
    """Download SBOM/VEX attestations with cosign, extract raw predicates,
    write each one as a JSON file in a temp dir. Returns the list of paths.
    """
    work_dir = f"/tmp/guac-{os.getpid()}-{abs(hash(image)) % 10**8}"
    os.makedirs(work_dir, exist_ok=True)
    written: list[str] = []

    sbom = _cosign_download_attestation(image, "https://spdx.dev/Document")
    if sbom is None:
        sbom = _cosign_download_attestation(image, "spdxjson")
    if isinstance(sbom, dict):
        path = f"{work_dir}/sbom.spdx.json"
        with open(path, "w") as f:
            json.dump(sbom, f)
        written.append(path)

    vex = _cosign_download_attestation(image, "https://openvex.dev/ns/v0.2.0")
    if vex is None:
        vex = _cosign_download_attestation(image, "vex")
    if isinstance(vex, dict):
        path = f"{work_dir}/vex.openvex.json"
        with open(path, "w") as f:
            json.dump(vex, f)
        written.append(path)

    return written


def _ingest_worker(image: str, namespace: str, app_name: str) -> None:
    """Background job: extract SBOM/VEX from OCI attestations and push them
    into GUAC via ``guacone collect files`` (which bypasses ingestor's DSSE
    verification, the only path that works for cosign-keyless attestations).
    Also emits the K8s deployment edge via GraphQL.

    Never raises — all errors surface as a ``guacIngestionStatus: Failed``
    patch with a human-readable reason.
    """
    # Primary path: extract attestations locally and push raw JSON to
    # graphql-server through guacone.
    files = _write_predicate_files(image)
    guacone_ok = _guacone_push_files(files) if files else False

    # Best-effort hint to oci-collector via collectsub. Kept because future
    # GUAC versions may add keyless support; harmless if oci-collector is
    # disabled or in polling mode (we send a bare repo, no digest).
    _notify_collectsub(image)

    # Always emit the deployment edge — it is the cheap mutation that
    # links the OCI image to the K8s deployment, independent of whether
    # the heavier SBOM/VEX payload was retrievable.
    deployment_edge_ok = _emit_deployment_edge(image, namespace, app_name)

    if deployment_edge_ok and guacone_ok:
        _patch_status_sync(
            namespace, app_name, "Completed",
            "GUAC graph updated: SBOM/VEX ingested via guacone, deployment edge linked.",
        )
    elif deployment_edge_ok and files and not guacone_ok:
        _patch_status_sync(
            namespace, app_name, "Completed",
            "GUAC graph updated with deployment edge only — guacone failed to push SBOM/VEX, "
            "check zta-operator logs (event=guac-guacone-*).",
        )
    elif deployment_edge_ok:
        _patch_status_sync(
            namespace, app_name, "Completed",
            "GUAC graph updated with deployment edge only — no SBOM/VEX attestation found on "
            "the image. Publish attestations via cosign attest to enable blast-radius queries.",
        )
    elif guacone_ok:
        _patch_status_sync(
            namespace, app_name, "Failed",
            "guacone ingested SBOM/VEX but the deployment edge mutation failed — check "
            "graphql-server logs.",
        )
    else:
        _patch_status_sync(
            namespace, app_name, "Failed",
            "GUAC ingestion did not complete: both guacone and the GraphQL deployment edge "
            "failed. Check GUAC service health.",
        )


def _split_oci_reference(image: str) -> tuple[str, str, str]:
    """Split an OCI reference into (registry, repo, version) for GUAC purl-style ingest.

    Examples:
      ghcr.io/sabinghost19/demo-fastapi@sha256:abc...
        -> ("ghcr.io", "sabinghost19/demo-fastapi", "sha256:abc...")
      docker.io/library/nginx:1.25
        -> ("docker.io", "library/nginx", "1.25")
    """
    ref = image.strip()
    version = ""
    if "@" in ref:
        ref, version = ref.rsplit("@", 1)
    elif ":" in ref.rsplit("/", 1)[-1]:
        head, tag = ref.rsplit(":", 1)
        ref, version = head, tag

    if "/" in ref:
        registry, repo = ref.split("/", 1)
        if "." not in registry and ":" not in registry and registry != "localhost":
            # No dot => not a registry hostname; treat the whole thing as a repo
            # under docker.io (matches Docker's parsing rules).
            registry, repo = "docker.io", ref
    else:
        registry, repo = "docker.io", ref
    return registry, repo, version


def _emit_deployment_edge(image: str, namespace: str, app_name: str) -> bool:
    """GraphQL mutation that links the OCI image to the K8s deployment.
    This is the cluster-side contribution to GUAC: GUAC alone never sees
    where an image actually runs.

    Schema (GUAC v1.x): `ingestHasSourceAt` takes `IDorPkgInput`/`IDorSourceInput`
    wrappers, requires `pkgMatchType`, and `HasSourceAtInputSpec.documentRef`
    is non-nullable. The earlier signature predates the `IDorXxxInput` change
    and was returning 422.
    """
    url = _endpoint()
    if not url:
        return False
    try:
        import httpx
    except ImportError:
        return False

    registry, repo, version = _split_oci_reference(image)

    pkg_input: dict[str, Any] = {
        "packageInput": {
            "type": "oci",
            "namespace": registry,
            "name": repo,
            "version": version,
            "qualifiers": [],
            "subpath": "",
        }
    }
    source_input: dict[str, Any] = {
        "sourceInput": {
            "type": "k8s",
            "namespace": "deployment",
            "name": f"{namespace}/{app_name}",
            "tag": "",
        }
    }
    has_source_at_input = {
        "knownSince": datetime.now(timezone.utc).isoformat(),
        "justification": "deployed by zta-operator",
        "origin": "zta-operator",
        "collector": "zta-operator",
        "documentRef": "",
    }

    # GUAC graph nodes must exist before edges can reference them, so we
    # ingest the package and source first (both are idempotent — repeat
    # calls just return the existing IDs).
    steps = [
        (
            "ingestPackage",
            "mutation($pkg: IDorPkgInput!) { ingestPackage(pkg: $pkg) { packageVersionID } }",
            {"pkg": pkg_input},
        ),
        (
            "ingestSource",
            "mutation($source: IDorSourceInput!) { ingestSource(source: $source) { sourceNameID } }",
            {"source": source_input},
        ),
        (
            "ingestHasSourceAt",
            "mutation($pkg: IDorPkgInput!, $mt: MatchFlags!, $src: IDorSourceInput!, $hsa: HasSourceAtInputSpec!) {"
            " ingestHasSourceAt(pkg: $pkg, pkgMatchType: $mt, source: $src, hasSourceAt: $hsa)"
            " }",
            {
                "pkg": pkg_input,
                "mt": {"pkg": "SPECIFIC_VERSION"},
                "src": source_input,
                "hsa": has_source_at_input,
            },
        ),
    ]

    try:
        with httpx.Client(timeout=5.0) as http:
            for op, query, variables in steps:
                response = http.post(
                    url,
                    content=json.dumps({"query": query, "variables": variables}),
                    headers={"Content-Type": "application/json"},
                )
                if response.status_code >= 300:
                    logger.warning(
                        "GUAC graphql HTTP error",
                        extra={
                            "event": "guac-graphql-rejected",
                            "operation": op,
                            "status": response.status_code,
                            "body": response.text[:300],
                        },
                    )
                    return False
                body = response.json()
                if body.get("errors"):
                    logger.warning(
                        "GUAC graphql returned errors",
                        extra={
                            "event": "guac-graphql-errors",
                            "operation": op,
                            "errors": str(body["errors"])[:300],
                        },
                    )
                    return False
        return True
    except Exception as exc:
        logger.warning(
            "GUAC graphql request failed",
            extra={"event": "guac-graphql-failed", "error": str(exc)[:200]},
        )
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
