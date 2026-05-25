# 15 — Operator: ingestia asincronă în GUAC

## §15.1 Analogie: arhiva publică a notarului

Un notar nu doar verifică actele când le primește — le și **arhivează**
într-o bibliotecă publică, indexate cross-document, ca alți notari sau
auditori să poată face interogări de tip "ce alte acte au fost emise pentru
proprietarul X?" sau "câte contracte conțin clauza Y?". Arhivarea nu
trebuie să blocheze tranzacția curentă (e o operațiune *secundară*); dar
fără ea, nu există vedere globală.

GUAC (Graph for Understanding Artifact Composition) e arhiva. SBOM-urile,
VEX-urile, atestările tuturor aplicațiilor sunt ingerate într-un graf
unificat. Permite interogări *blast radius* (vezi UI-ul BlastRadius
Explorer): "ce alte deployment-uri din cluster sunt afectate de CVE-X?".

## §15.2 De ce asincron?

```python
# operator.py:731-735
# Asynchronous GUAC ingestion — decoupled from the reconcile loop
# so a slow OCI pull / GUAC collector roundtrip never delays Pod
# creation. The worker thread PATCHes status.guacIngestionStatus
# to Completed/Failed when finished; the UI surfaces this as a
# spinner that resolves to a checkmark.
```

Pull-ul SBOM/VEX din OCI + ingest-ul în GUAC pot dura zeci de secunde
(rețea, parsing, GraphQL mutation-uri serializate). Dacă acest pas ar bloca
reconcile-ul, Pod-ul nu ar fi creat până la finalizarea ingestiei — UX-ul
ar fi inacceptabil pentru un dev care doar vrea ca aplicația să pornească.

Soluția: thread separat declanșat după provisioning, care PATCH-uiește
status atunci când termină. UI-ul randează indicator de progres separat.

## §15.3 Trigger-ul

```python
# operator.py:736-768
try:
    from .guac_client import trigger_guac_ingestion

    started = trigger_guac_ingestion(image=image, namespace=namespace, app_name=name)
    if started:
        _status_patch(
            custom,
            namespace,
            name,
            {
                "guacIngestionStatus": "InProgress",
                "guacIngestionMessage": "Pulling SBOM/VEX from OCI and ingesting into GUAC knowledge graph...",
            },
        )
        adapter.info(
            "GUAC ingestion worker started (async)",
            extra={"event": "guac-worker-started", "image": image},
        )
    else:
        _status_patch(
            custom,
            namespace,
            name,
            {
                "guacIngestionStatus": "Disabled",
                "guacIngestionMessage": "GUAC_GRAPHQL_URL is not configured for this operator.",
            },
        )
except Exception as exc:
    adapter.info(
        "GUAC ingest skipped",
        extra={"event": "guac-ingest-skipped", "error": str(exc)},
    )
```

Trei stări inițiale posibile (înainte ca worker-ul să termine):

| Status | Sens |
|---|---|
| `InProgress` | Worker-ul a pornit cu succes |
| `Disabled` | `GUAC_GRAPHQL_URL` env nu e configurat (instalare fără GUAC) |
| Niciun status (excepție) | Importul `guac_client` a eșuat (logged warning) |

## §15.4 Worker thread

În `guac_client.py` (citate conceptuale, dat fiind lungimea fișierului):

```python
# guac_client.py:572-603 (selecție)
def trigger_guac_ingestion(image: str, namespace: str, app_name: str) -> bool:
    if not GUAC_GRAPHQL_URL:
        return False
    executor = _get_executor()
    executor.submit(_ingest_to_guac, image=image, namespace=namespace, app_name=app_name)
    return True


def _ingest_to_guac(image: str, namespace: str, app_name: str) -> None:
    try:
        # 1. cosign download attestation pentru SBOM și VEX
        # 2. guacone collect files <directory> --gql-addr=<GUAC_GRAPHQL_URL>
        # 3. Apel GraphQL mutație IngestArtifact + IngestPackage + IngestDependency
        # 4. Edge K8s deployment (subiect = imagine, target = pod)
        # 5. PATCH status: guacIngestionStatus = Completed
    except Exception as exc:
        # PATCH status: guacIngestionStatus = Failed, message = str(exc)
```

Detalii non-triviale:

1. **`cosign download attestation`** (nu `verify`) — descarcă atestarea
   fără a o re-verifica. Verificarea s-a făcut deja în `validate_admission_with_attestations`.
   Re-verificarea ar dubla costul rețea.
2. **`guacone collect files`** — CLI-ul oficial GUAC, ingerează fișiere
   locale într-o instanță GUAC remote (vs. setup-ul standard NATS-based).
   Reusabil cu air-gapped GUAC.
3. **GraphQL mutation pentru edge K8s** — link explicit între pachetul OCI
   și pod-ul deployed. Permite UI-ului să răspundă "care pod rulează această
   imagine?".
4. **PATCH status** — actualizează `guacIngestionStatus` la
   `Completed`/`Failed` + `guacIngestionCompletedAt`. UI-ul vede tranziția
   prin SSE stream.

## §15.5 Eșecuri în ingest

`Failed` nu invalidează ZTA-ul. Pod-ul rulează, aplicația e funcțională.
Doar partea de blast radius e indisponibilă temporar. Reasoning:

- GUAC e o componentă de **observabilitate**, nu de **enforcement**.
- O downtime în GUAC nu ar trebui să oprească deployment-urile.
- Failure-uri tranziente (GUAC restart, rețea) → următoarea reconciliere a
  ZTA-ului re-încearcă automat (specReconcileHash unchanged → reconcile
  triggered de update minor).

## §15.6 Pull vs push (decizie design)

Pipeline-ul CI/CD ar fi putut împinge SBOM/VEX direct în GUAC (variant
*push-based*). De ce *pull-based* (operatorul citește din OCI și împinge în
GUAC)?

```yaml
# Comentariu reluat din ci-cd.yaml:440-446
# NOTE: GUAC ingestion is intentionally NOT performed from CI/CD.
# The pipeline is the "producer of evidence" — it attests SBOM and VEX
# to the OCI registry via cosign. The cluster-side zta-operator is the
# "consumer and distributor of evidence" — at admission time it pulls
# those attestations from OCI and ingests them into GUAC asynchronously,
# so a private/air-gapped GUAC instance never has to be exposed to
# GitHub Actions. See docs §14.7 (Pull-based Threat Intel).
```

Patru avantaje:

1. **GUAC nu e expus la internet.** Cluster-ul intern citește GUAC; GitHub
   Actions niciodată nu trebuie să aibă credentiale GUAC.
2. **Idempotent retry.** Dacă GUAC e jos când rulează pipeline-ul, dar
   urcat când rulează operatorul, ingest-ul reușește. Push-ul ar fi
   pierdut.
3. **Versioning evidence.** OCI e single source of truth pentru atestări.
   GUAC e un cache derivativ. Dacă GUAC e șters (incident), operatorul îl
   poate re-popula doar prin re-reconcile.
4. **Air-gapped.** Cluster-uri închise pot ingera SBOM-uri (citite din
   OCI registry-uri private replicate intern) fără a oferi acces extern.

## §15.7 Ce vede UI-ul

Câmpurile status:

- `status.guacIngestionStatus` — `InProgress | Completed | Failed | Disabled`.
- `status.guacIngestionMessage` — text uman.
- `status.guacIngestionCompletedAt` — ISO timestamp.

Frontend (`Apps.vue`) randează:

```vue
<v-chip
  :color="guacStatusColor(integrityDetails.application.status.guacIngestionStatus)"
  size="small"
  variant="tonal"
>
  GUAC: {{ integrityDetails.application.status.guacIngestionStatus || 'pending' }}
</v-chip>
```

Plus separat — view BlastRadius care interoghează GUAC pentru CVE/package
relationships (vezi `userInterfaceDashboard/docs/blast-radius/`).

## §15.8 Ce urmează

Cu aceasta se încheie operatorul `zta-operator`. Următorul fișier
descrie operatorul *satelit* `provenance-enforcer` care lucrează în paralel
pentru verificarea VBBI: `16-provenance-enforcer.md`.
