# 07 — Pipeline: self-verify și gate `expected_infra_hash`

## §7.1 Analogie: cuvântul "OK" rostit cu voce tare de pilot

Înainte de decolare, pilotul nu doar bifează checklist-ul mental — îl
parcurge cu voce tare cu copilotul, pentru ca fiecare verificare să existe
public. Dacă o problemă apare după decolare, înregistrarea cabinei poate fi
folosită pentru a stabili dacă verificarea a fost într-adevăr făcută sau
doar bifată.

Pipeline-ul self-verify este acel checklist cu voce tare. Job-ul
`attestations` (după ce a creat toate atestările) le **verifică pe loc**
înainte ca rezultatul să fie considerat acceptabil. Și anume:

- Cosign verify pentru SBOM, ZTA policy, VBBI.
- Recalcularea hash-ului canonic al `spec`-ului ZTA.
- Compararea cu `expected_infra_hash` din atestarea proaspăt creată.
- Verificări structurale pe VBBI (provider, count steps, root match).

Dacă ceva nu se potrivește, pipeline-ul **eșuează** și nu promovează
imaginea în GitOps (job-ul `bump-manifests-repo` are `needs: sign-and-verify`).

## §7.2 Configurația trusted identity

```yaml
# ci-cd.yaml:267-272
- name: Verify attestations and expected infra hash
  run: |
    IMAGE_REF=${{ needs.build-push.outputs.image_repo }}@${{ needs.build-push.outputs.image_digest }}
    IDENTITY="https://github.com/${{ github.repository }}/.github/workflows/ci-cd.yaml@refs/heads/main"
    MANIFEST_DIR="./${{ env.MANIFESTS_CHECKOUT_PATH }}/${{ env.MANIFESTS_SUBPATH }}"
```

`IDENTITY` este URL-ul exact pe care îl emite Fulcio în cert atunci când
acest workflow rulează. **Aceeași identitate** este declarată în SCA-ul
operator:

```yaml
# demo-app-manifests-samples/demo-app/sca-sample.yaml:7-9
sourceValidation:
  enforceCosign: true
  trustedIssuers:
    - https://github.com/SabinGhost19/vulfastapi/.github/workflows/ci-cd.yaml@refs/heads/main
```

Dacă cluster-ul instalează altă SCA cu altă identitate, operatorul respinge
atestările proaspete; dacă pipeline-ul rulează din alt branch (ex.
`refs/heads/develop`), self-verify eșuează imediat.

## §7.3 Verificarea atestărilor

```yaml
# ci-cd.yaml:273-292
cosign verify-attestation \
  "$IMAGE_REF" \
  --type spdxjson \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  >/tmp/sbom-attestation.jsonl

cosign verify-attestation \
  "$IMAGE_REF" \
  --type "https://devsecops.licenta.ro/attestations/custom-zta-policy/v1" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  >/tmp/policy-attestation.jsonl

cosign verify-attestation \
  "$IMAGE_REF" \
  --type "https://devsecops.licenta.ro/VBBI/v1" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  >/tmp/vbbi-attestation.jsonl
```

Trei `verify-attestation` succesive, fiecare salvând output-ul DSSE-decoded
într-un `.jsonl` separat. Output-ul include payload-ul base64 + semnătura;
verificarea criptografică e făcută de cosign însuși (verifică certificatul
Fulcio + Rekor inclusion proof).

OpenVEX **nu** apare aici — atestarea este condițională (`if hashFiles('vex.json')`),
deci verificarea fail-ează dacă nu există. Decizia design: self-verify
verifică doar atestările obligatorii.

## §7.4 Recalculul hash-ului canonic (operator-equivalent)

```yaml
# ci-cd.yaml:294-309
mapfile -t YAML_FILES < <(find "$MANIFEST_DIR" -type f \( -name '*.yaml' -o -name '*.yml' \) | sort)
if [ ${#YAML_FILES[@]} -eq 0 ]; then
  echo "No YAML files found in manifest directory: $MANIFEST_DIR" >&2
  exit 1
fi

ZTA_SPECS_JSON="$(yq ea -o=json '[select(.kind == "ZeroTrustApplication") | .spec]' "${YAML_FILES[@]}")"
SPEC_COUNT="$(printf '%s' "$ZTA_SPECS_JSON" | jq 'length')"
if [ "$SPEC_COUNT" -ne 1 ]; then
  echo "Expected exactly one ZeroTrustApplication spec in manifest directory, found: $SPEC_COUNT" >&2
  exit 1
fi

CANONICAL_SPEC=$(printf '%s' "$ZTA_SPECS_JSON" | jq -c -S --arg image "$IMAGE_REF" '.[0] | .image = $image')
LOCAL_HASH=$(printf '%s' "$CANONICAL_SPEC" | sha256sum | awk '{print $1}')
LOCAL_HASH_NORMALIZED=$(echo "$LOCAL_HASH" | tr '[:upper:]' '[:lower:]' | sed 's/^sha256://')
```

**Punctul cheie:** acest cod este **echivalent** cu cel din ZTA policy
attestor și cu cel din operator. Trei implementări ale aceleiași funcții
trebuie să producă același output. Dacă vreuna diverge, gate-ul nu mai
funcționează.

Diferențe subtile pe care le-am uniformizat:

- `jq -c -S` (compact + sort keys) ≡ Python `json.dumps(separators=(',',':'), sort_keys=True)`.
- `tr '[:upper:]' '[:lower:]'` + `sed 's/^sha256://'` — normalizare a hash-ului
  pentru comparație. Operatorul folosește `_normalize_sha256()`
  (`supply_chain_attestation.py:119-123`).

## §7.5 Extragerea hash-ului atestat

```yaml
# ci-cd.yaml:311-320
mapfile -t ATTESTED_HASHES < <(
  jq -r '.payload' /tmp/policy-attestation.jsonl \
    | while read -r payload; do
        printf '%s' "$payload" | base64 -d | jq -r '.predicate.expected_infra_hash // empty'
      done \
    | sed '/^$/d' \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/^sha256://' \
    | sort -u
)
```

DSSE envelope-ul are `payload` base64-encoded → trebuie decodat înainte de
parsing JSON. Pipeline-ul iterează prin TOATE atestările (pot exista
multiple în referrers, ex. semnături multiple) și colectează toate
hash-urile prezente, deduplicate.

## §7.6 Gate-ul propriu-zis

```yaml
# ci-cd.yaml:322-340
if [ ${#ATTESTED_HASHES[@]} -eq 0 ]; then
  echo "No expected_infra_hash values found in policy attestations" >&2
  exit 1
fi

MATCH_FOUND="false"
for h in "${ATTESTED_HASHES[@]}"; do
  if [ "$h" = "$LOCAL_HASH_NORMALIZED" ]; then
    MATCH_FOUND="true"
    break
  fi
done

if [ "$MATCH_FOUND" != "true" ]; then
  echo "expected_infra_hash mismatch: none of attested hashes match local hash" >&2
  echo "attested_hashes=${ATTESTED_HASHES[*]}" >&2
  echo "local_hash=$LOCAL_HASH" >&2
  exit 1
fi
```

Comparație simplă set-membership. Dacă hash-ul calculat local nu apare în
**niciuna** dintre atestările verificate, fail.

Acesta este un *self-defense check*: dacă cineva ar reuși să strecoare o
atestare modificată în pipeline (ex. înlocuind temporar binarul `cosign`),
hash-ul calculat din manifestul real *aici* + manifestul atestat *acolo*
nu s-ar potrivi, iar pipeline-ul s-ar opri înainte de promovare.

## §7.7 Verificări structurale pe VBBI

```yaml
# ci-cd.yaml:342-364
VBBI_REPOSITORY=$(jq -r '.payload' /tmp/vbbi-attestation.jsonl | head -n1 | base64 -d | jq -r '.predicate.build_context.repository')
VBBI_ROOT=$(jq -r '.payload' /tmp/vbbi-attestation.jsonl | head -n1 | base64 -d | jq -r '.predicate.merkle_tree.root_hash')
VBBI_PROVIDER=$(jq -r '.payload' /tmp/vbbi-attestation.jsonl | head -n1 | base64 -d | jq -r '.predicate.hmac_chain.provider')
VBBI_STEP_COUNT=$(jq -r '.payload' /tmp/vbbi-attestation.jsonl | head -n1 | base64 -d | jq -r '.predicate.hmac_chain.steps | length')
if [ -z "$VBBI_REPOSITORY" ] || [ -z "$VBBI_ROOT" ] || [ "$VBBI_ROOT" = "null" ]; then
  echo "VBBI attestation is missing repository or merkle root" >&2
  exit 1
fi

if [ "$VBBI_PROVIDER" != "shared-secret" ]; then
  echo "Expected VBBI shared-secret provider but found: $VBBI_PROVIDER" >&2
  exit 1
fi

if [ "$VBBI_STEP_COUNT" != "4" ]; then
  echo "Expected exactly 4 VBBI steps but found: $VBBI_STEP_COUNT" >&2
  exit 1
fi

if [ "$VBBI_ROOT" != "${{ steps.vbbi.outputs.merkle-root }}" ]; then
  echo "VBBI merkle root mismatch between action output and attestation" >&2
  exit 1
fi
```

Patru gate-uri:

1. Repository și Merkle root non-vide.
2. Provider expected: `shared-secret` (pentru pipeline-ul demo; configurație
   production ar putea fi `vault-transit`).
3. Count steps == 4 (exact corespondență cu definiția `step-spec.json`).
4. **Cross-check**: root-ul Merkle din atestare = root-ul output de action.
   Dacă acțiunea VBBI ar fi compromisă și ar publica un root diferit de cel
   din predicate, aici se prinde.

## §7.8 Summary la sfârșit

```yaml
# ci-cd.yaml:368-382
echo "## Attestation Report" >> "$GITHUB_STEP_SUMMARY"
echo "- IMAGE_REF=$IMAGE_REF" >> "$GITHUB_STEP_SUMMARY"
echo "- POLICY_ATTESTATION_TYPE=https://devsecops.licenta.ro/attestations/custom-zta-policy/v1" >> "$GITHUB_STEP_SUMMARY"
...
echo "- ATTESTED_INFRA_HASHES=${ATTESTED_HASHES[*]}" >> "$GITHUB_STEP_SUMMARY"
echo "- COMPUTED_INFRA_HASH=$LOCAL_HASH" >> "$GITHUB_STEP_SUMMARY"
echo "- RESULT=PASS" >> "$GITHUB_STEP_SUMMARY"
```

`GITHUB_STEP_SUMMARY` produce un raport pe pagina run-ului în GitHub UI.
Pentru audit: include exact ce a fost verificat. Dacă run-ul e accesibil
public (sau intern auditor), raportul e dovada că self-verify a fost rulat.

## §7.9 Ce vede operatorul de la acest pas?

Direct: **nimic special**. Operatorul nu cunoaște dacă self-verify a fost
rulat. Indirect: operatorul reușește verificările propriile pentru că
pipeline-ul a validat că atestările sunt consistente.

Argumentul filosofic e simplu: self-verify nu adaugă siguranță față de
verificarea operatorului. Dar:

1. **Failure mai timpurie** — un build greșit eșuează în 10 secunde la
   self-verify, nu după ore de așteptare cluster.
2. **Audit trail public** — `GITHUB_STEP_SUMMARY` e public, dă auditor-ului
   un punct fix de referință.
3. **Protecție împotriva regresiunilor** — dacă cineva modifică
   `zta-policy-attestor` action-ul greșit, pipeline-ul prinde imediat.

## §7.10 Ce urmează

Pipeline-ul s-a terminat. Imaginea e în GHCR cu toate atestările. Manifestul
GitOps e actualizat cu noul digest.

Trece controlul către cluster. Următorul capitol: cum citește operatorul
toate aceste artefacte. Vezi `08-operator-reconcile-lifecycle.md`.
