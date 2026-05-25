# 03 — Pipeline: SBOM, OpenVEX, cosign sign

## §3.1 Analogie: trei documente la vamă

Un container ajunge la vamă. Vamesul cere:

1. **Lista de pachete** (*manifest comercial*) — ce e înăuntru, cu ce versiuni
   și ce furnizori. Asta e SBOM-ul.
2. **Declarații de neaplicabilitate** (*certificate de excepție*) — "acest
   produs nu este supus restricției X, vezi avizul Y al laboratorului
   acreditat". Asta e OpenVEX.
3. **Sigiliul producătorului** pe ușa containerului — semnătura care
   identifică emitentul. Asta e `cosign sign`.

Sunt **trei artefacte ortogonale** care răspund la trei întrebări distincte.
La operator se vor verifica separat, în pași separați.

## §3.2 SBOM (SPDX JSON)

```yaml
# ci-cd.yaml:210-214
- name: Generate and attest SBOM (spdxjson)
  run: |
    IMAGE_REF=${{ needs.build-push.outputs.image_repo }}@${{ needs.build-push.outputs.image_digest }}
    syft "$IMAGE_REF" -o spdx-json > sbom.spdx.json
    cosign attest --yes --predicate sbom.spdx.json --type spdxjson "$IMAGE_REF"
```

Două operațiuni distincte:

1. **`syft IMAGE_REF -o spdx-json`** — analizează straturile imaginii OCI,
   detectează package manager-ele (apt/yum/pip/npm/...), produce un document
   SPDX cu fiecare pachet, versiune, licență, hash.
2. **`cosign attest --predicate sbom.spdx.json --type spdxjson IMAGE_REF`** —
   împachetează SBOM-ul într-o declarație DSSE (Dead Simple Signing
   Envelope), semnată cu certificatul Fulcio efemer al workflow-ului, și o
   atașează ca *OCI referrer* la `IMAGE_REF@sha256:...`. Predicate type
   shorthand `spdxjson` se expandează la
   `https://spdx.dev/Document` în envelope.

Rezultatul în registry: o atestare în `referrers` cu predicate type
`spdxjson`, semnată keyless, vizibilă cu:

```bash
cosign verify-attestation IMAGE_REF \
  --type spdxjson \
  --certificate-identity https://github.com/<owner>/<repo>/.github/workflows/ci-cd.yaml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## §3.3 OpenVEX (condițional)

```yaml
# ci-cd.yaml:216-228
- name: Attest OpenVEX statements (false-positive justifications)
  if: ${{ hashFiles('vex.json') != '' }}
  run: |
    IMAGE_REF=${{ needs.build-push.outputs.image_repo }}@${{ needs.build-push.outputs.image_digest }}
    # OpenVEX v0.2.0 predicate carries auditor-signed justifications for
    # Trivy false-positives. The operator (vex.py) ingests these to filter
    # CVEs at admission time, avoiding pipeline blocks on unreachable code.
    # cosign does not have a shorthand for VEX (unlike `spdxjson`), so the
    # full OpenVEX predicate-type URI is required.
    cosign attest --yes \
      --predicate vex.json \
      --type "https://openvex.dev/ns/v0.2.0" \
      "$IMAGE_REF"
```

**Schema OpenVEX v0.2.0** (extras conceptual):

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "author": "auditor@example.com",
  "timestamp": "2026-05-25T12:00:00Z",
  "statements": [
    {
      "vulnerability": { "name": "CVE-2024-1234" },
      "products": [{ "@id": "pkg:pypi/cryptography@41.0.0" }],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}
```

Câmpul `status` poate fi: `not_affected`, `affected`, `fixed`,
`under_investigation`. Operatorul folosește `not_affected` (cu `justification`
non-trivial) pentru a filtra CVE-uri din rezultatele Trivy — comportament
documentat în `vex.py`.

**Condiționarea `if: hashFiles('vex.json') != ''`** evită eșecul când
repository-ul nu are încă un fișier VEX. Operatorul de la cealaltă parte
tratează absența atestării ca "fără exempții" — nu ca o eroare.

## §3.4 Cosign sign keyless

```yaml
# ci-cd.yaml:420-424
- name: Sign image with Cosign keyless
  env:
    COSIGN_EXPERIMENTAL: "false"
  run: |
    cosign sign --yes ${{ needs.build-push.outputs.image_repo }}@${{ needs.build-push.outputs.image_digest }}
```

**Distincția semnătură vs. atestare:** cosign poate produce două lucruri
diferite:

| Operațiune | Conținut | Predicate type | Rol |
|---|---|---|---|
| `cosign sign` | doar referința la imagine | (niciuna) | "eu am emis această imagine" |
| `cosign attest --predicate X --type T` | predicate X + tipul T | T | "eu afirm fapt T despre această imagine" |

Operatorul verifică **ambele**: `cosign verify` (semnătura) ÎN PLUS de
`cosign verify-attestation --type ...` (fiecare atestare).

**Cum funcționează keyless:**

```
GitHub Actions ──── id-token JWT ────▶ Fulcio CA
                                          │
                                          │ emite cert X.509
                                          │ (valabil 15 min)
                                          ▼
                                    cosign folosește cert
                                          │
                              ┌───────────┴───────────┐
                              ▼                       ▼
                  semnează imaginea          publică în Rekor
                                              (transparency log)
```

Identitatea în certificat este:
`https://github.com/<owner>/<repo>/.github/workflows/ci-cd.yaml@refs/heads/main`

Emitentul OIDC este `https://token.actions.githubusercontent.com`.

Operatorul verifică ambele:

```python
# zta-operator/src/zta_operator/supply_chain.py:59-76
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
```

`allowed_signer` vine din SCA-ul aplicat (vezi
[`09-operator-sca-policy-matching.md`](09-operator-sca-policy-matching.md)
§9.4). Există o listă completă în SCA — operatorul încearcă fiecare identitate
până una se potrivește (algoritm "first-match-wins" la liniile 180-185).

## §3.5 Verificare la nivel pipeline (self-check al semnăturii)

```yaml
# ci-cd.yaml:426-431
- name: Verify image signature (self-check)
  run: |
    cosign verify \
      ${{ needs.build-push.outputs.image_repo }}@${{ needs.build-push.outputs.image_digest }} \
      --certificate-identity "https://github.com/${{ github.repository }}/.github/workflows/ci-cd.yaml@refs/heads/main" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Pipeline-ul își verifică propria semnătură imediat după ce o emite. Acest
*self-check* prinde:

- Probleme cu Rekor (semnătura emisă dar nu publicată în transparency log).
- Probleme cu Fulcio (cert emis cu identitate diferită — improbabil dar
  posibil dacă există un bug în GitHub OIDC injection).
- Probleme cu cosign însuși (versiune buggy a binarului).

Costul e mic (un round-trip la Rekor); beneficiul: pipeline-ul nu promovează
o imagine "semnată" pe care propriul cluster nu ar putea-o verifica.

## §3.6 Ce vede operatorul (sumar)

| Artefact produs aici | Predicate type | Verificat de operator în |
|---|---|---|
| Semnătura imaginii (cosign sign) | n/a | `supply_chain.py:verify_cosign_keyless` |
| SBOM SPDX | `spdxjson` | `supply_chain_attestation.py:_verify_attestation_by_type` (key=`sbom`) |
| OpenVEX | `https://openvex.dev/ns/v0.2.0` | `supply_chain_attestation.py:_verify_openvex_attestation` (key=`openvex`) + `vex.py:filter_trivy_vulnerabilities` (filtru CVE) |

Detaliile verificărilor: vezi 10 și 11.

## §3.7 Ce urmează

Atestările "industriale" (SBOM, OpenVEX, SLSA) răspund întrebări *despre*
imagine. Mai există două atestări *custom*, despre **integritatea pipeline-ului
însuși** și **identitatea politicii pe care imaginea o respectă**: VBBI și
ZTA policy. Vezi `04-pipeline-vbbi-voucher.md` și `05-pipeline-zta-policy-attestor.md`.
