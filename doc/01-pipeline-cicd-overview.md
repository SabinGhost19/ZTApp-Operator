# 01 — Pipeline CI/CD: privire de ansamblu

## §1.1 Analogie: lanțul producției unei sticle de vin

Înainte ca o sticlă să ajungă în supermarket, ea trece prin etape distincte:
fermentație (build), filtrare (test), îmbuteliere (push), etichetare cu data
și origine (atestări), sigiliul producătorului (cosign sign), verificare la
ieșirea din cramă (self-verify). Fiecare etapă produce un document oficial.
Fiecare document e contrasemnat de o autoritate diferită (laborator, vamă,
proprietar). La supermarket (cluster), niciun document nu este în plus —
toate sunt necesare pentru a fi pus pe raft.

În acest fișier ne uităm la **succesiunea job-urilor** din `ci-cd.yaml`.
Detaliile fiecărui artefact sunt în fișierele 02–07.

## §1.2 Configurarea globală

```yaml
# demo-app/.github/workflows/ci-cd.yaml:1-13
name: ci-cd-demo-app

on:
  push:
    branches: ["main"]
    tags:
      - "v*"
  workflow_dispatch:

permissions:
  contents: read
  packages: write
  id-token: write
```

Cele trei permisiuni sunt critice și ortogonale:

- `contents: read` — checkout-ul codului sursă.
- `packages: write` — push în GHCR (`ghcr.io/...`).
- `id-token: write` — emiterea unui OIDC JWT către **Sigstore Fulcio**, care
  semnează cu certificat de scurtă durată (15 minute) imaginea și atestările.
  Fără acest scope, întregul pipeline keyless nu poate funcționa.

## §1.3 Variabile de mediu

```yaml
# ci-cd.yaml:15-20
env:
  REGISTRY: ghcr.io
  MANIFESTS_REPO: SabinGhost19/vulfastapi-manifests-samples
  MANIFESTS_REF: main
  MANIFESTS_SUBPATH: demo-app
  MANIFESTS_CHECKOUT_PATH: manifests-source
```

Două repository-uri, intenționat separate:

- `demo-app/` — codul sursă + pipeline-ul.
- `vulfastapi-manifests-samples/` — manifestele Kubernetes (`ZeroTrustApplication`,
  `SupplyChainAttestation`, `ZeroTrustSecret`). Acest pattern (GitOps cu
  separare cod/config) permite ca:
  1. Hash-ul canonic al `spec`-ului ZTA să fie calculat la build time peste
     conținutul real al manifestului care va fi aplicat — incluzând digest-ul
     imaginii proaspăt construite (vezi `05-pipeline-zta-policy-attestor.md`).
  2. Job-ul `bump-manifests-repo` (final) împinge automat noul digest în
     repository-ul de manifeste, închizând bucla GitOps.

## §1.4 Graful job-urilor

```
build-metadata ─┐
                ├──▶ build-push ─┬──▶ scan-image ─┐
                                 │                 ├──▶ attestations ─┬──▶ sign-and-verify ─▶ bump-manifests-repo
                                 │                 │                  │
                                 │                 └──────────────────┘
                                 │
                                 └──▶ slsa-provenance (independent, called via reusable workflow)
```

Job-urile:

1. **`build-metadata`** — rulează lint surrogate + smoke test, salvează
   rezultate JSON ca artifact-uri (`vbbi-lint`, `vbbi-test`). Aceste JSON-uri
   vor fi consumate ulterior de VBBI voucher-ul ca *step receipts*.
2. **`build-push`** — `docker buildx` + push către GHCR. Output: `image_repo`
   și `image_digest` (sha256, imutabil).
3. **`scan-image`** — `trivy` pe digest. Salvează metadata (`vbbi-scan`)
   pentru voucher.
4. **`attestations`** — generează și atașează (`cosign attest`):
   - SBOM `spdxjson` (syft → cosign).
   - OpenVEX `v0.2.0` (dacă există `vex.json` în repo).
   - VBBI voucher (custom action).
   - ZTA policy attestation (custom action).
   - Verifică pe loc toate cele trei via `cosign verify-attestation` și
     compară hash-ul canonic al `spec`-ului ZTA cu `expected_infra_hash` din
     atestarea proaspăt creată (gate intern, vezi §07).
5. **`slsa-provenance`** — invocă reusable workflow oficial SLSA v1.0:
   `slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0`.
6. **`sign-and-verify`** — `cosign sign --yes` (semnătura propriu-zisă a
   imaginii, separată de atestări) + self-verify keyless.
7. **`bump-manifests-repo`** — împinge noul digest în repository-ul de
   manifeste (GitOps push-back). Skipped pentru tag-uri `v*`, rulat doar pe
   `push` la `main`.

## §1.5 Idiom non-trivial: dual-attestation

Pipeline-ul atestă SLSA v1.0 (standard OSS) **și** VBBI (custom). Sunt
ortogonale:

> SLSA v1.0 dovedește că workflow-ul s-a rulat într-un runner GitHub-hosted
> izolat, cu metadata de build non-forgeable, semnată de Fulcio. VBBI
> dovedește că pașii **din interiorul** workflow-ului s-au întâmplat în
> ordinea declarată, fiecare cu rezultate înregistrate criptografic.

Cu alte cuvinte: SLSA spune "build-ul e legitim"; VBBI spune "build-ul a
făcut exact ce a promis că face". Comentariul din `ci-cd.yaml:384-388`
formulează exact această distincție:

```yaml
# ci-cd.yaml:384-388
# Official SLSA v1.0 container provenance (independent of VBBI).
# VBBI proves the internal step ordering inside our pipeline;
# SLSA v1.0 proves the workflow itself ran in an isolated GitHub-hosted
# runner with non-forgeable build metadata signed by Fulcio.
# Together they form a dual-attestation: one OSS-standard, one custom.
```

## §1.6 Idiom non-trivial: producer vs consumer of evidence

Pipeline-ul **NU** trimite direct nimic către GUAC. Comentariul din
`ci-cd.yaml:440-446` explică decizia:

```yaml
# ci-cd.yaml:440-446
# NOTE: GUAC ingestion is intentionally NOT performed from CI/CD.
# The pipeline is the "producer of evidence" — it attests SBOM and VEX
# to the OCI registry via cosign. The cluster-side zta-operator is the
# "consumer and distributor of evidence" — at admission time it pulls
# those attestations from OCI and ingests them into GUAC asynchronously,
# so a private/air-gapped GUAC instance never has to be exposed to
# GitHub Actions. See docs §14.7 (Pull-based Threat Intel).
```

Acest principiu **pull-based threat intel** este central:

- Pipeline-ul scrie atestări în OCI (public).
- Operatorul citește din OCI la admission (intra-cluster).
- Operatorul scrie în GUAC (privat, air-gapped posibil).

Diferența față de un design naiv (GitHub Actions împinge direct în GUAC):
GUAC-ul nu trebuie expus pe internet, nu există credentiale GUAC stocate în
GitHub Secrets, iar ingestia poate fi reluată / repetată independent de
disponibilitatea GitHub Actions.

## §1.7 Ce urmează

Fiecare job e descris detaliat în fișierele următoare:

- `02-pipeline-build-push.md` — `build-push` + etichetare imutabilă.
- `03-pipeline-attestari-supply-chain.md` — SBOM, OpenVEX, cosign sign.
- `04-pipeline-vbbi-voucher.md` — custom action VBBI.
- `05-pipeline-zta-policy-attestor.md` — custom action ZTA policy.
- `06-pipeline-slsa-v1.md` — SLSA v1.0 reusable workflow.
- `07-pipeline-self-verify.md` — self-check și gate `expected_infra_hash`.
