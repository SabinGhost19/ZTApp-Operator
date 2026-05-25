# 00 — Arhitectura de ansamblu

## §0.1 Analogie: lanțul vamal al unui produs farmaceutic

Imaginează-ți că o fabrică expediază un medicament către un spital. Înainte ca
medicamentul să fie administrat unui pacient, trebuie să existe o **înlănțuire
de garanții** care să răspundă, fiecare cu un document distinct, la întrebări
diferite:

1. *Cine a fabricat lotul?* — semnătură pe ambalaj.
2. *Ce conține lotul?* — fișa SPC (Summary of Product Characteristics).
3. *Există efecte secundare cunoscute pentru această versiune?* — declarația
   farmacovigilenței.
4. *Cum a fost transportat (lanț de rece)?* — semnături sigilate la fiecare nod
   logistic.
5. *Există o autoritate independentă care a re-validat lotul la frontieră?* —
   vama farmaceutică.

Fiecare document e produs de o entitate diferită, semnat criptografic și
verificat la destinație înainte ca medicamentul să intre în depozit.

În sistemul nostru:

| Întrebare | Artefact | Producător | Verificator |
|---|---|---|---|
| Cine a construit imaginea? | semnătură cosign keyless + cert Fulcio | pipeline CI/CD | `zta-operator` |
| Ce conține imaginea? | SBOM SPDX (semnat) | `syft` în pipeline | `zta-operator` |
| Ce CVE-uri sunt false-positive? | OpenVEX (semnat) | auditor; semnat în pipeline | `zta-operator` |
| Pașii pipeline-ului s-au întâmplat în ordinea declarată? | VBBI voucher (HMAC chain + Merkle) | custom action `vbbi-voucher-attestor` | `provenance-enforcer` |
| Specificația aplicației corespunde celei aprobate? | ZTA policy attestation (`expected_infra_hash`) | custom action `zta-policy-attestor` | `zta-operator` |
| Build-ul a rulat într-un runner izolat oficial? | SLSA v1.0 provenance | `slsa-github-generator` | `zta-operator` |

Operatorul este **vama**: respinge orice imagine care nu poate prezenta întreaga
înlănțuire, sau care o prezintă cu sigilii rupte.

## §0.2 Actori și granițe

```
┌────────────────────┐      git push       ┌────────────────────┐
│  Dezvoltator       │ ─────────────────▶ │  GitHub repo       │
└────────────────────┘                     │  demo-app/         │
                                           └────────┬───────────┘
                                                    │
                                           ┌────────▼───────────┐
                                           │ GitHub Actions     │
                                           │ ci-cd.yaml         │
                                           │ ┌────────────────┐ │
                                           │ │ build-push     │ │
                                           │ │ scan-image     │ │
                                           │ │ attestations   │ │
                                           │ │ slsa-provenance│ │
                                           │ │ sign-and-verify│ │
                                           │ └────────────────┘ │
                                           └─┬──────────────┬───┘
                                             │ image+digest │ attestations
                                             ▼              ▼
                                  ┌─────────────────────────────┐
                                  │ GHCR (ghcr.io/...)          │
                                  │ ─ OCI image                 │
                                  │ ─ cosign signature          │
                                  │ ─ referrers: SBOM, OpenVEX, │
                                  │   VBBI, ZTA policy, SLSA    │
                                  └────────────┬────────────────┘
                                               │ pull + verify
                                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Kubernetes cluster (k3s)                                        │
│                                                                  │
│  ┌────────────────────┐    ┌────────────────────────────┐        │
│  │ kubectl apply ZTA  │───▶│ ZeroTrustApplication CR    │        │
│  └────────────────────┘    └────────────┬───────────────┘        │
│                                         │  watch                  │
│                ┌────────────────────────┴────────────────────┐   │
│                │                                             │   │
│       ┌────────▼─────────┐                          ┌────────▼─┐ │
│       │ zta-operator     │                          │ provenance│ │
│       │ (kopf)           │◀── status.trustLevel ────│ -enforcer │ │
│       │                  │                          │  (kopf)   │ │
│       │ cosign + trivy + │                          │ VBBI fetch│ │
│       │ SBOM + policy +  │                          │ HMAC chain│ │
│       │ SLSA + OpenVEX + │                          │ Merkle    │ │
│       │ CEL + provisioning│                         └──────────┘ │
│       └────────┬─────────┘                                       │
│                │                                                 │
│       ┌────────▼─────────┐  ┌────────────┐  ┌─────────────┐      │
│       │ Deployment       │  │ Falco rule │  │ Talon rule  │      │
│       │ Service          │  │ ConfigMap  │  │ ConfigMap   │      │
│       │ NetworkPolicy    │  └────────────┘  └─────────────┘      │
│       │ AuthorizationPol │                                       │
│       │ WasmPlugin       │                                       │
│       └──────────────────┘                                       │
└──────────────────────────────────────────────────────────────────┘
                                               │ async
                                               ▼
                                       ┌────────────────┐
                                       │ GUAC graph     │
                                       │ (blast radius) │
                                       └────────────────┘
```

## §0.3 Vocabular esențial: producător vs. verificator

Confuzia clasică în supply chain security este între:

- **Atestare** (*attestation*) — declarație semnată: "afirm că X este adevărat
  despre acest artefact". Producătorul atestă.
- **Verificare** (*verification*) — operațiunea de a decide dacă o atestare e
  acceptabilă conform unei politici. Verificatorul verifică.

Aceeași entitate poate fi atât producător cât și verificator pentru artefacte
diferite. Pipeline-ul produce SBOM-ul (atestare) și **își verifică propriile
atestări** înainte de promovare (vezi `07-pipeline-self-verify.md`).
Operatorul nu produce nimic; doar verifică.

## §0.4 De ce două operatoare (zta-operator + provenance-enforcer)?

Răspunsul scurt: **separare de privilegii**.

`zta-operator` are RBAC larg: poate crea Deployment, Service, NetworkPolicy,
ConfigMap-uri Falco/Talon, etc. Dacă această componentă ar conține și logica
criptografică de verificare a lanțului HMAC din VBBI voucher (cod complex,
suprafață de atac mare), o vulnerabilitate într-un parser ar putea fi exploatată
pentru a obține controlul cluster-ului.

`provenance-enforcer` rulează ca operator **separat**, cu RBAC restrâns la
operațiuni read/patch pe `ZeroTrustApplication.status.trustLevel` și
`ZeroTrustApplication.status.provenance`. Nu poate crea Deployment-uri. Dacă e
compromis, atacatorul nu poate decât să fabrice un `trustLevel=Verified` —
ceea ce e protejat de gate-urile ulterioare din `zta-operator` (cosign,
attestation, CEL).

```
zta-operator RBAC        provenance-enforcer RBAC
─────────────────        ──────────────────────────
get/list/watch  ZTA      get/list/watch ZTA
patch/status    ZTA      patch/status   ZTA (doar provenance, trustLevel)
create/update   Deploy   get/list       SCA (read-only)
create/update   Service  get/list       Secret (HMAC key)
create/update   NetPol   ─
create/update   ConfigMap (Falco, Talon)
get/list/watch  SCA
get/list/watch  ZTS
create/update   Secret (rotation)
```

## §0.5 Cele trei CRD-uri și relația lor

```
SupplyChainAttestation (cluster-scoped)   ─── "regulile jocului"
       ▲
       │ securityPolicyRef.name
       │
ZeroTrustApplication (namespace-scoped)   ─── "aplicația care vrea acces"
       ▲
       │ applicationRef.name
       │
ZeroTrustSecret (namespace-scoped)        ─── "secretele eliberate condiționat"
```

- **SCA** declară: ce trebuie verificat (cosign, SBOM, attestări, CEL),
  pragurile (severitate maximă, SLSA level), trusted issuers, builder-i de
  încredere.
- **ZTA** referențiază o SCA și aplică acele reguli unei imagini concrete +
  unei politici de rețea + unei configurări runtime.
- **ZTS** referențiază o ZTA și eliberează secrete (din Vault prin ESO) doar
  dacă ZTA-ul referențiat este în starea `Running` cu `trustLevel=Verified`.

Detalii pentru fiecare CRD: vezi
[`18-status-fields-reference.md`](18-status-fields-reference.md).

## §0.6 De ce nu un admission webhook în loc de operator?

Întrebare academică pertinentă: validarea ar putea fi făcută la admission time
(înainte ca CRD-ul să fie persistat în etcd), nu post-admission ca operator.

**Răspuns:** validarea operatorului depinde de operațiuni I/O potențial lente:

- `cosign verify` — round-trip la Fulcio + Rekor (sute de ms).
- `trivy image` — pull strat-uri OCI + scanare (zeci de secunde).
- `cosign verify-attestation` × N atestări — fiecare un round-trip OCI.

Un admission webhook trebuie să răspundă rapid (sub 30s default), iar dacă
eșuează intermitent, blochează *toate* admission-urile cluster-ului. Un
operator are timeout flexibil, retry exponential prin `kopf.TemporaryError`,
și nu participă în path-ul critic al API server-ului.

Webhook-ul există totuși (`webhook.py`) pentru validări sintactice rapide
(spec.image format, securityPolicyRef.name nevid). Restul: operator.

## §0.7 Fluxul în trei propoziții

1. Pipeline-ul produce o imagine OCI plus 5 atestări semnate (cosign signature,
   SBOM SPDX, OpenVEX, VBBI voucher, ZTA policy, SLSA v1.0) și își verifică
   propriile atestări înainte de promovare.
2. La `kubectl apply` pe o ZTA, `zta-operator` rezolvă SCA-ul, așteaptă ca
   `provenance-enforcer` să marcheze `trustLevel=Verified` (după ce valida
   independent VBBI), apoi rulează cosign / trivy / SBOM / policy / SLSA /
   OpenVEX / CEL, scriind un rezultat granular în `status.verifications.*`.
3. Dacă toate trec, provisionează resursele K8s și configurează Falco/Talon
   pentru runtime; dacă vreuna pică, scrie `status.errors[]` cu cod stabil și
   intră în `Failed_SupplyChain` (permanent) sau `Degraded` (cu retry).

Următorul fișier: [`01-pipeline-cicd-overview.md`](01-pipeline-cicd-overview.md).
