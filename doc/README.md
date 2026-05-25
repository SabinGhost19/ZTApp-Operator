# `zta-operator` — Documentație Tehnică Granulară

> **Scop:** Această documentație descrie, **pas cu pas**, fluxul end-to-end de
> validare a unei aplicații Zero-Trust, de la momentul `git push` în repository-ul
> sursă, până la momentul în care `Pod`-ul este admis în cluster și monitorizat
> în runtime. Pentru fiecare pas există **două perspective oglindă**:
>
> 1. **Pipeline-ul CI/CD** — codul care *produce* artefacte (imagini, atestări,
>    semnături, vouchere).
> 2. **Operatorul `zta-operator`** (și operatorul satelit `provenance-enforcer`) —
>    codul care *consumă și validează* aceste artefacte la momentul admiterii
>    în cluster.
>
> Documentația este destinată unui audit tehnic / academic: fragmente de cod
> sunt extrase **1:1** din sursă cu referințe `fișier:linie`, pentru ca un
> evaluator să poată reproduce fluxul fără ambiguitate.

## Convenții

- **Citate de cod cu rigoare.** Fiecare excerpt are deasupra o linie de tip
  `# zta-operator/src/zta_operator/operator.py:303-343` care indică exact
  fișierul și intervalul de linii.
- **Analogii.** Fiecare pas începe cu o analogie concretă (vamă, biroul de
  notariat, lanț de custody penal) pentru a fixa intuiția înaintea
  formalizării.
- **Limbaj.** Română academică pentru explicații, engleză tehnică pentru
  identificatorii din cod, fără traducerea termenilor consacrați (SBOM, VEX,
  SLSA, attestation, provenance).
- **Granularitate.** Fiecare fișier acoperă **un singur pas logic**. Dacă un
  pas e prea complex, este descompus în sub-secțiuni numerotate (`§1.2.3`),
  nu în fișiere separate — pentru a păstra coeziunea.

## Ordinea de lectură

Recomandată în ordine numerică:

1. [`00-arhitectura-de-ansamblu.md`](00-arhitectura-de-ansamblu.md) — context
   sistem, actori, vocabular, diagrama de nivel înalt.

### Partea I — Pipeline-ul CI/CD (producția de evidență)

2. [`01-pipeline-cicd-overview.md`](01-pipeline-cicd-overview.md) — privire de
   ansamblu asupra `ci-cd.yaml`: job-uri, dependențe, permisiuni OIDC.
3. [`02-pipeline-build-push.md`](02-pipeline-build-push.md) — `docker build`,
   etichetarea imutabilă, `docker push` în GHCR, extragerea digest-ului.
4. [`03-pipeline-attestari-supply-chain.md`](03-pipeline-attestari-supply-chain.md)
   — `cosign sign`, SBOM cu `syft`, OpenVEX (`cosign attest`).
5. [`04-pipeline-vbbi-voucher.md`](04-pipeline-vbbi-voucher.md) — custom action
   `vbbi-voucher-attestor`: lanț HMAC + arbore Merkle peste pașii pipeline-ului.
6. [`05-pipeline-zta-policy-attestor.md`](05-pipeline-zta-policy-attestor.md) —
   custom action `zta-policy-attestor`: hash canonic al specificației ZTA.
7. [`06-pipeline-slsa-v1.md`](06-pipeline-slsa-v1.md) — SLSA v1.0 provenance
   generat de `slsa-github-generator/generator_container_slsa3.yml`.
8. [`07-pipeline-self-verify.md`](07-pipeline-self-verify.md) — pipeline-ul își
   verifică propriile atestări înainte de promovare (gate pre-cluster).

### Partea II — Operatorul `zta-operator` (consumul evidenței)

9. [`08-operator-reconcile-lifecycle.md`](08-operator-reconcile-lifecycle.md) —
   intrarea în reconcile via `kopf`, idempotență prin spec hash, ordinea
   exactă a fazelor.
10. [`09-operator-sca-policy-matching.md`](09-operator-sca-policy-matching.md) —
    rezolvarea `SupplyChainAttestation`, poarta provenance (`trustLevel`).
11. [`10-operator-cosign-trivy.md`](10-operator-cosign-trivy.md) — verificarea
    semnăturii keyless + scanarea Trivy + filtrarea VEX.
12. [`11-operator-attestation-verify.md`](11-operator-attestation-verify.md) —
    SBOM + ZTA policy attestation + `expected_infra_hash` + SLSA + OpenVEX.
13. [`12-operator-cel-rules.md`](12-operator-cel-rules.md) — `customRules` în
    CEL: semantica `Deny` / `Allow` / `Alert`.
14. [`13-operator-provisioning.md`](13-operator-provisioning.md) — generarea
    obiectelor K8s (Deployment, Service, Ingress, NetworkPolicy, etc.).
15. [`14-operator-runtime-falco-talon.md`](14-operator-runtime-falco-talon.md) —
    reguli Falco custom + regulile de izolare Talon.
16. [`15-operator-guac-ingest.md`](15-operator-guac-ingest.md) — ingestia
    asincronă SBOM/VEX în GUAC pentru analiza de blast radius.

### Partea III — Operatorul satelit `provenance-enforcer`

17. [`16-provenance-enforcer.md`](16-provenance-enforcer.md) — arhitectură de
    operator paralel, fluxul VBBI → HMAC → Merkle, write-back pe
    `status.trustLevel`, comunicarea cu `zta-operator`.

### Partea IV — Observabilitate și status

18. [`17-error-taxonomy-and-observability.md`](17-error-taxonomy-and-observability.md)
    — `status.errors[]`, `status.verifications[*]`, evenimente kopf,
    structured logs, timing.
19. [`18-status-fields-reference.md`](18-status-fields-reference.md) — referință
    completă a fiecărui câmp din `ZeroTrustApplication.status`.

## Glosar minimal

| Termen | Definiție operațională |
|---|---|
| **SCA** | `SupplyChainAttestation` — CRD cluster-scoped care declară regulile de admitere. |
| **ZTA** | `ZeroTrustApplication` — CRD namespace-scoped care declară o aplicație ce dorește admitere. |
| **ZTS** | `ZeroTrustSecret` — CRD pentru eliberarea condiționată a secretelor după validarea ZTA. |
| **SBOM** | Software Bill of Materials. Aici: format SPDX JSON generat de `syft`. |
| **VEX** | Vulnerability Exploitability eXchange. Aici: OpenVEX v0.2.0, declarații semnate de auditor care marchează CVE-uri ca neaplicabile. |
| **SLSA** | Supply-chain Levels for Software Artifacts. Aici: nivel 3 prin `slsa-github-generator`. |
| **VBBI** | *Verified Build-step Behavioral Integrity* — atestare custom care leagă criptografic pașii pipeline-ului printr-un lanț HMAC + un arbore Merkle. |
| **Cosign keyless** | Semnătură fără cheie pre-distribuită; identitatea semnatarului este URL-ul workflow-ului GitHub Actions, certificat de Fulcio. |
| **Predicate type** | URL stabil care identifică schema unei atestări (ex. `https://slsa.dev/provenance/v1`). |
| **OIDC issuer** | Pentru GitHub Actions: `https://token.actions.githubusercontent.com`. |
| **Reconcile** | În terminologia operator: ciclul în care controller-ul compară starea dorită (`spec`) cu cea reală și acționează. |
| **Kopf** | Framework Python pentru operator Kubernetes; oferă decoratori `@kopf.on.create`, `@kopf.on.field`, etc. |
| **Talon** | `falco-talon` — engine de reacție în timp real care primește evenimente Falco și aplică acțiuni K8s. |
| **GUAC** | Graph for Understanding Artifact Composition — graf de cunoaștere pentru supply chain (ingerează SBOM/VEX/SLSA). |

## Cross-references către alte zone ale documentației

- Document de proiect (high level): [`../../DOC/`](../../DOC/)
- Pipeline-ul în detaliu (perspectivă "supply chain"):
  [`../../ci-ci-and-k8s-workflow-supply-chain/`](../../ci-ci-and-k8s-workflow-supply-chain/)
- UI integration și real-time stream:
  [`../../DOC/what_is_now_on_latest_doc/realtime-stream-and-verifications.md`](../../DOC/what_is_now_on_latest_doc/realtime-stream-and-verifications.md)
