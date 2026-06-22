# 18 — Referință completă: `ZeroTrustApplication.status`

> **Scop:** referință completă pentru fiecare câmp scris în
> `status` al CRD-ului `ZeroTrustApplication`. Pentru fiecare câmp:
> tip, valori posibile, cine scrie, cine citește, ce reprezintă semantic.

## §18.1 Schema CRD (sursă)

Definiția schemei e în
[`zta-operator/deploy/crd/zerotrustapplication-crd.yaml`](../deploy/crd/zerotrustapplication-crd.yaml).

Câmpurile din `status` sunt definite la liniile 128-181 ale fișierului.

## §18.2 Câmpurile top-level

### `status.phase` (string)

| Valori | Sens | Setat de |
|---|---|---|
| `Pending` | Așteaptă o resursă externă (SCA missing, provenance pending) | zta-operator |
| `Validating` | Verificările sunt în curs | zta-operator |
| `Provisioning` | Resursele K8s se creează | zta-operator |
| `Running` | Aplicație healthy, toate verificările trecute | zta-operator |
| `Degraded` | Anomalie tranzient (runtime drift, eroare K8s tranzient) | zta-operator |
| `Failed_SupplyChain` | Eșec permanent al verificărilor de policy | zta-operator |

UI-ul mapează `phase` la coloana **Phase** în lista de aplicații.

### `status.lastError` (string)

Ultimul mesaj de eroare uman. Folosit pentru afișare rapidă în UI și
`kubectl get zta`. **Nu** se mai face regex pe acest câmp (vezi
`status.verifications.*` pentru detalii structurate). Limită: 512 chars (în
practic, mesajele sunt mai scurte).

### `status.trustLevel` (string, enum)

```yaml
# crd:135-137
trustLevel:
  type: string
  enum: [ Untrusted, Verified, UntrustedProvenance ]
```

| Valoare | Sens | Setat de |
|---|---|---|
| `Untrusted` | Default la creație, nu s-a verificat încă | (default) |
| `Verified` | provenance-enforcer a aprobat VBBI | provenance-enforcer |
| `UntrustedProvenance` | provenance-enforcer a respins | provenance-enforcer |

Acesta e câmpul-poartă pe care zta-operator îl urmărește prin
`@kopf.on.field(field="status.trustLevel")` (vezi `09` §9.4).

### `status.securityState` (string)

Compound state mai bogat decât `phase`.

| Valoare | Sens |
|---|---|
| `Compliant` | Toate verificările trecute |
| `Alert` | A trecut dar cu warning (VEX-exempted CVEs, audit-mode hash drift) |
| `NonCompliant` | A picat o verificare |
| `WaitingForPolicy` | SCA-ul referențiat nu există încă |
| `PendingProvenance` | Așteaptă enforcer-ul |

### `status.lastVerified` (string, ISO 8601)

Timestamp-ul ultimei reconcile reușite. Scris doar pe success path.

### `status.activeViolations` (string[])

Listă deduplicată de policy violations care **NU** au blocat deploy-ul
(audit-mode). Scrisă de operator după `_unique_strings(violations)`.

### `status.specReconcileHash` (string)

SHA256 al `spec`-ului din ultima reconciliere reușită. Watermark de
idempotență (vezi `08` §8.4).

## §18.3 Câmpurile preserve-unknown-fields (obiecte schemaless)

Patru câmpuri sunt declarate ca `x-kubernetes-preserve-unknown-fields: true`
pentru flexibilitate (operatorul adaugă field-uri noi fără upgrade CRD).

### `status.provenance` (obiect)

Scris de **provenance-enforcer**. Structura tipică (după `set_failure_status`
sau success path):

```json
{
  "required": true,
  "verifiedAt": "2026-05-25T12:00:00Z",
  "attestationType": "https://devsecops.licenta.ro/VBBI/v1",
  "hmacMode": "shared-secret",
  "reason": "",
  "repository": "SabinGhost19/vulfastapi",
  "slsaLevel": 3,
  "voucher": {
    "buildContext": {...},
    "hmacChainProvider": "shared-secret",
    "slsaLevel": 3,
    "repository": "..."
  },
  "hmacChain": {
    "verified": true,
    "steps": 4
  },
  "merkle": {
    "verified": true,
    "computedRoot": "abc123...",
    "leafCount": 4,
    "merkleAlgorithm": "rfc6962-sha256"
  }
}
```

Câmpuri-cheie:

| Câmp | Tip | Sens |
|---|---|---|
| `verifiedAt` | ISO 8601 | Când a fost validat (null dacă pending) |
| `reason` | string | Motivul refuzului (dacă `trustLevel=UntrustedProvenance`) |
| `hmacChain.verified` | bool | HMAC chain integrity OK |
| `merkle.verified` | bool | Merkle root matches recompute |
| `voucher.buildContext` | obiect | predicate-ul VBBI brut |

### `status.attestations` (obiect)

Scris de **zta-operator** după `validate_admission_with_attestations`.

```json
{
  "policyName": "demo-app-security-policy",
  "resolvedImage": "ghcr.io/sabinghost19/demo-vulnerable-fastapi@sha256:abc...",
  "sbomDigest": "sha256:ef12...",
  "policyDigest": "sha256:cd34...",
  "sbomPackages": [
    {"name": "fastapi", "version": "0.104.1", "ecosystem": "pypi"},
    ...
  ],
  "policyPredicate": {...},
  "expectedInfraHash": "abc12345...",
  "computedInfraHash": "abc12345...",
  "celEvaluations": [
    {"name": "require-slsa-level-3", "expression": "...",
     "action": "Allow", "fired": false, "outcome": "true"}
  ]
}
```

| Câmp | Tip | Sens |
|---|---|---|
| `policyName` | string | Numele SCA-ului folosit |
| `resolvedImage` | string | Imaginea în formă imutabilă (cu digest) |
| `sbomDigest` | string | sha256 al predicate-ului SBOM |
| `sbomPackages` | array | Listă paranthe (name, version, ecosystem) extrase din SBOM |
| `policyDigest` | string | sha256 al predicate-ului ZTA policy |
| `expectedInfraHash` | string | `expected_infra_hash` din atestare |
| `computedInfraHash` | string | `expected_infra_hash` recalculat local |
| `celEvaluations` | array | Per-rule CEL evaluation log |

### `status.details` (obiect)

Scris de zta-operator pentru detalii Trivy. Sursă: `supply_chain.py`
`verify_trivy_threshold` → `_collect_findings`.

```json
{
  "highest": "HIGH",
  "threshold": "MEDIUM",
  "counts": {"CRITICAL": 0, "HIGH": 3, "MEDIUM": 5, "LOW": 12},
  "vexExempted": ["CVE-2024-1234"],
  "findings": [
    {
      "id": "CVE-2024-1234",
      "pkg": "starlette",
      "severity": "HIGH",
      "installed": "0.27.0",
      "fixedVersion": "0.40.0",
      "title": "Starlette multipart DoS",
      "target": "app/requirements.txt",
      "primaryUrl": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    }
  ]
}
```

| Câmp | Tip | Sens |
|---|---|---|
| `highest` | string | Cea mai mare severitate găsită (`CRITICAL`…`LOW`, `NONE`) |
| `threshold` | string | Pragul din policy (`maxVulnerabilities`) |
| `counts` | obiect | Contor per severitate `{CRITICAL,HIGH,MEDIUM,LOW}` (nu `severityCounts`) |
| `vexExempted` | string[] | CVE-uri exceptate prin OpenVEX |
| `findings` | array | Detaliu per-CVE (cap **300**) — `{id, pkg, severity, installed, fixedVersion, title, target, primaryUrl}`. UI linkează `primaryUrl` |

> **Notă:** câmpul de contor se numește **`counts`** (cheia scrisă de cod în
> `supply_chain.py:113`), nu `severityCounts`. Același obiect `details` e
> propagat și în `status.errors[].details` la breach și în
> `status.verifications.trivy` (vezi mai jos).

### `status.runtimeEnforcement` (obiect)

Scris de **zta-operator** la sfârșitul provisioning-ului (`operator.py` ~l.702-765),
reflectă starea enforcement-ului runtime Falco + Talon pentru aplicație. Vezi
`14-operator-runtime-falco-talon.md`.

```json
{
  "requested": true,
  "installed": true,
  "talonRulePatched": true,
  "missing": [],
  "reason": ""
}
```

| Câmp | Tip | Sens |
|---|---|---|
| `requested` | bool | `true` dacă `spec` cere runtime enforcement (`runtime`) |
| `installed` | bool \| null | **Tri-state:** `null`=necunoscut/necerut, `true`=stack Falco+Talon prezent, `false`=lipsește |
| `talonRulePatched` | bool | `true` dacă regula a fost adăugată în ConfigMap-ul Talon |
| `missing` | string[] | Componente lipsă când `installed=false` (ex. CRD/Deployment Talon) |
| `reason` | string | Mesaj explicativ când `installed=false` |

> Când stack-ul Falco/Talon nu e instalat, operatorul **nu** abortează reconcile-ul:
> Pod-ul rulează deja, iar UI-ul afișează un banner informativ pe baza
> `installed=false` + `missing=[...]` în loc de un chip roșu de eroare. Vezi și
> eroarea `runtime-infrastructure-missing` din `status.errors`.

### `status.verifications` (obiect, nou)

Ledger per-check, structurat. Vezi `17-error-taxonomy-and-observability.md` §17.2.

```json
{
  "cosign":      {"passed": true, "reason": "ok", "completedAt": "...", "durationMs": 1234},
  "trivy":       {"passed": true, "reason": "ok", "completedAt": "...", "durationMs": 8901,
                  "highest": "LOW", "threshold": "MEDIUM", "vexExempted": [],
                  "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 12},
                  "findings": [{"id": "CVE-...", "pkg": "...", "severity": "LOW",
                                "installed": "...", "fixedVersion": "...", "title": "...",
                                "target": "...", "primaryUrl": "..."}]},
  "sbom":        {"passed": true, "reason": "ok", "completedAt": "...", "durationMs": 567,
                  "digest": "sha256:...", "packageCount": 142},
  "policyAttestation": {"passed": true, "reason": "ok", "completedAt": "...", "durationMs": 234,
                        "attestationType": "https://devsecops.licenta.ro/attestations/custom-zta-policy/v1",
                        "digest": "sha256:...", "expectedInfraHash": "..."},
  "slsaProvenance":    {"passed": true, "reason": "ok", "completedAt": "...", "durationMs": 345,
                        "buildType": "...", "builderId": "...", "digest": "sha256:..."},
  "openvex":           {"passed": true, "reason": "ok", "completedAt": "...", "durationMs": 123,
                        "statementCount": 2, "digest": "sha256:..."}
}
```

### `status.errors` (array, nou)

Ring buffer (max 20). Vezi `17` §17.2.

```json
[
  {
    "code": "trivy-threshold-exceeded",
    "message": "Found CRITICAL severity vulnerability — policy threshold is HIGH",
    "phase": "SupplyChain",
    "retryable": false,
    "occurredAt": "2026-05-25T12:00:00Z",
    "details": {"highest": "CRITICAL", "threshold": "HIGH"}
  },
  ...
]
```

Cele 20 cele mai recente. UI afișează newest-first prin `ErrorLogPanel.vue`.

### `status.policyMatchDebug` (obiect)

Diagnostic emis când SCA-ul referențiat nu există. Scris de
`_collect_policy_match_diagnostics`.

```json
{
  "namespace": "default",
  "appName": "demo-api",
  "labels": {...},
  "securityPolicyRef": "demo-app-security-policy",
  "candidateCount": 3,
  "candidates": [
    {"policyName": "other-sca-1", "matchMode": "securityPolicyRef",
     "matched": false, "reasons": ["securityPolicyRef mismatch: expected 'demo-app-security-policy', got 'other-sca-1'"]},
    ...
  ]
}
```

## §18.4 Câmpurile GUAC ingestion

```yaml
# crd:157-163
guacIngestionStatus:
  type: string
  enum: [ "", InProgress, Completed, Failed, Disabled ]
guacIngestionMessage:
  type: string
guacIngestionCompletedAt:
  type: string
```

Detalii: `15-operator-guac-ingest.md`.

## §18.5 Annotation: `zta.devsecops/spec-reconcile-hash`

Belt-and-braces pentru `specReconcileHash` (vezi `08` §8.4). Stocată în
`metadata.annotations`, nu în `status` — funcționează chiar dacă CRD-ul
n-a fost upgraded.

## §18.6 Tabel sumar — scrieri concurente

Cele două operatoare care pot scrie pe același `status`:

| Câmp | zta-operator | provenance-enforcer |
|---|---|---|
| `phase` | ✓ | ✗ |
| `lastError` | ✓ | ✓ (la failure) |
| `trustLevel` | ✗ | ✓ |
| `securityState` | ✓ | ✗ |
| `lastVerified` | ✓ | ✗ |
| `activeViolations` | ✓ | ✗ |
| `specReconcileHash` | ✓ | ✗ |
| `provenance` | (citește) | ✓ |
| `attestations` | ✓ | ✗ |
| `details` | ✓ | ✗ |
| `runtimeEnforcement` | ✓ | ✗ |
| `verifications` | ✓ | ✗ |
| `errors` | ✓ | ✗ |
| `policyMatchDebug` | ✓ | ✗ |
| `guacIngestion*` | ✓ | ✗ |

Doar `lastError` are doi scriitori potențiali. Convenție: dacă
`trustLevel=UntrustedProvenance`, `lastError` e proprietatea
provenance-enforcer-ului și zta-operator nu îl suprascrie (verifică
`trust_level` înainte de patch în §9.4).

## §18.7 Tabel sumar — câmpuri citite de UI

Backend serializează `status.*` în două locuri:

- `application.status` — copie 1:1.
- `application.summary` — versiune denormalizată cu câmpuri convenabile
  derivate (ex. `summary.image`, `summary.lastErrorSummary`,
  `summary.hasViolations`).

Frontend citește în ordine:

1. `application.summary.*` pentru afișare standard.
2. `application.status.verifications.*` pentru `VerificationStatusTable`.
3. `application.status.errors` pentru `ErrorLogPanel`.
4. `application.status.attestations.celEvaluations` (via summary) pentru
   `CelEvaluationsTable`.
5. `application.status.provenance.{hmacChain,merkle}` pentru substeps în
   `ReconcileFlow`.

## §18.8 Ce urmează

Documentația este completă. Citire recomandată: `README.md` → linkuri către
fișierele numerotate 00-18.

Pentru auditori: secvența 00 → 07 → 08 → 11 → 16 → 17 acoperă fluxul
critic security. Restul (provisioning, GUAC, Falco/Talon, status reference)
sunt necesare pentru completitudine, dar nu strict pe path-ul de admission.
