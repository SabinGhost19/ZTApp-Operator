# 06 — Pipeline: SLSA v1.0 provenance

## §6.1 Analogie: factura unui producător auto care declară linia de fabricație

Un producător auto livrează o piesă către un client. Factura include nu doar
codul piesei, ci și: numărul liniei de producție, codul operatorului uman,
schimbul în care a fost fabricată, lotul de materie primă, certificările
mașinilor implicate. Aceste metadata nu spun nimic despre *calitatea*
piesei — spun *cum a ajuns să existe*.

SLSA v1.0 (Supply-chain Levels for Software Artifacts) este exact factura
asta pentru un artefact software. Predicate type-ul stabil este
`https://slsa.dev/provenance/v1`. Schema este standardizată (in-toto + SLSA
working group), independent de orice producător particular.

## §6.2 De ce un reusable workflow extern?

```yaml
# ci-cd.yaml:384-402
# Official SLSA v1.0 container provenance (independent of VBBI).
# VBBI proves the internal step ordering inside our pipeline;
# SLSA v1.0 proves the workflow itself ran in an isolated GitHub-hosted
# runner with non-forgeable build metadata signed by Fulcio.
# Together they form a dual-attestation: one OSS-standard, one custom.
slsa-provenance:
  needs:
    - build-push
  permissions:
    id-token: write
    packages: write
    actions: read
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
  with:
    image: ${{ needs.build-push.outputs.image_repo }}
    digest: ${{ needs.build-push.outputs.image_digest }}
    registry-username: ${{ github.actor }}
  secrets:
    registry-password: ${{ secrets.GITHUB_TOKEN }}
```

Trei aspecte importante:

1. **Reusable workflow, nu action.** Diferența:
   - Un *action* rulează în contextul (runner + permissions) ale workflow-ului
     care îl invocă.
   - Un *reusable workflow* rulează ca job separat, cu propria sa
     `permissions:` definită în fișierul `generator_container_slsa3.yml` al
     repository-ului `slsa-framework/slsa-github-generator`.

   Pentru SLSA, *separation* e fundamentală: producătorul atestării trebuie
   să fie o entitate distinctă de codul care rulează build-ul. Reusable
   workflow ne dă această izolare *for free* la nivel GitHub Actions.
2. **`uses: ...@v2.0.0`** — versiune pinned. SLSA generator are propriul
   ciclu de release; un upgrade necontrolat ar putea schimba `builder.id`
   din atestare → operatorul nostru (cu `trustedBuilders` în SCA) ar refuza
   imagini noi până se actualizează SCA-ul. Acest cuplaj e intenționat.
3. **`actions: read`** — pentru ca reusable workflow-ul să poată citi
   metadata workflow-ului apelant (run_id, workflow_ref, etc.) și să le
   includă în SLSA provenance.

## §6.3 Schema SLSA v1.0 predicate

Predicate type: `https://slsa.dev/provenance/v1`.

```json
{
  "buildDefinition": {
    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
    "externalParameters": {
      "workflow": {
        "ref": "refs/heads/main",
        "repository": "https://github.com/SabinGhost19/vulfastapi",
        "path": ".github/workflows/ci-cd.yaml"
      }
    },
    "internalParameters": { ... },
    "resolvedDependencies": [
      { "uri": "git+https://github.com/SabinGhost19/vulfastapi@sha256:...",
        "digest": { "sha1": "abc..." } }
    ]
  },
  "runDetails": {
    "builder": {
      "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0",
      "version": { "..." }
    },
    "metadata": {
      "invocationId": "https://github.com/...//runs/12345",
      "startedOn": "2026-05-25T12:00:00Z",
      "finishedOn": "2026-05-25T12:08:00Z"
    },
    "byproducts": [ ... ]
  }
}
```

Câmpurile critice pentru verificare:

| Câmp | Validare în operator |
|---|---|
| `buildDefinition.buildType` | Inclus în SCA `slsaProvenancePolicy.allowedBuildTypes` (dacă declarat) |
| `runDetails.builder.id` | Inclus în SCA `slsaProvenancePolicy.trustedBuilders` |
| `buildDefinition.resolvedDependencies[0].uri` | Implicit: repository-ul sursă (verificat indirect via cert identity) |

## §6.4 Cum se obține SLSA L3 specific

SLSA definește 4 niveluri (1-4). Nivelul 3 cere:

- **Hosted build platform** — runner-ul rulează la furnizor (GitHub Actions),
  nu pe mașina dev-ului.
- **Hardened build platform** — runner-ul nu poate fi influențat de
  pipeline-uri concurente.
- **Non-forgeable provenance** — atestarea e semnată de furnizorul de build,
  nu de codul rulat.

`generator_container_slsa3.yml` produce exact nivelul 3 prin:

- Runner GitHub-hosted (ubuntu-latest pool).
- Semnătura via Fulcio cu identitate workflow URL.
- Predicate-ul e calculat de **workflow-ul reusable**, nu de jobs-urile
  apelante (separation of duties).

## §6.5 Verificare operator

Vezi `11-operator-attestation-verify.md` §11.5 pentru codul exact. Pe scurt:

```python
# zta-operator/src/zta_operator/supply_chain_attestation.py:_verify_slsa_provenance
attestation = await _verify_attestation_by_type(
    image=image,
    attestation_type="slsaprovenance1",
    trusted_issuers=trusted_issuers,
)
predicate = attestation.get("predicate", {}) or {}
build_def = predicate.get("buildDefinition", {}) or {}
run_details = predicate.get("runDetails", {}) or {}
builder = (run_details.get("builder", {}) or {})
build_type = str(build_def.get("buildType", "")).strip()
builder_id = str(builder.get("id", "")).strip()
```

Cosign acceptă predicate type shorthand `slsaprovenance1` pentru
`https://slsa.dev/provenance/v1`. Pentru SLSA v0.2 (vechi) shorthand-ul ar
fi `slsaprovenance`. Operatorul nostru folosește v1.0.

## §6.6 Edge case: builder ID drift între minor versions

Documentat în SCA-ul de sample
[`demo-app-manifests-samples/demo-app/sca-sample.yaml`](../../demo-app-manifests-samples/demo-app/sca-sample.yaml):

```yaml
slsaProvenancePolicy:
  enforceSlsa: true
  requiredLevel: 3
  trustedBuilders:
    - "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"
```

URL-ul include exact `@refs/tags/v2.0.0`. Dacă cluster admin-ul actualizează
pipeline-ul la `v2.1.0` fără să actualizeze SCA-ul, operatorul respinge cu
`slsa-builder-untrusted`. Acesta e cuplaj intenționat: schimbarea
generatorului SLSA = schimbarea schemei atestării = decizie security
explicită.

## §6.7 Diferența VBBI vs SLSA, ortogonalitate completă

| Întrebare | Răspuns prin VBBI | Răspuns prin SLSA |
|---|---|---|
| Cine a invocat build-ul? | Repository GitHub | Builder identity URL |
| Build-ul a rulat într-un runner izolat? | (nu acoperă) | DA (L3) |
| Pașii de build au fost cei declarați? | DA (HMAC chain + Merkle) | (nu acoperă în detaliu) |
| Atestarea e ne-forjabilă? | DA (cu Vault Transit) | DA (Fulcio + Rekor) |
| Hash al codului sursă? | `commit_sha` | `resolvedDependencies[].digest.sha1` |
| Hash al rezultatelor pașilor? | `hmac_chain.steps[].metadata_hash` | (nu acoperă) |

Cele două sunt complementare. Dacă pipeline-ul ar avea doar SLSA, nu am ști
*ce s-a întâmplat* în pașii interni — doar că workflow-ul a rulat la GitHub.
Dacă ar avea doar VBBI, nu am avea garanția izolării runner-ului.

## §6.8 Ce urmează

După cele 5 atestări (cosign sig + SBOM + OpenVEX + VBBI + ZTA policy + SLSA),
pipeline-ul **își verifică propriile atestări** și gate-ul GitOps. Aceasta e
ultima etapă din pipeline înainte de promovare. Vezi
`07-pipeline-self-verify.md`.
