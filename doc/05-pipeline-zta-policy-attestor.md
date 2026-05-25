# 05 — Pipeline: ZTA Policy Attestor

## §5.1 Analogie: "ștampila constructorului pe planul aprobat"

Un constructor de imobile primește planurile aprobate de primărie. Înainte de
a începe lucrarea, le ștampilează cu propria ștampilă + un hash criptografic
al planurilor. Acea ștampilă spune: "*acesta* este planul exact pe care îl
voi executa, nu o variantă; orice modificare făcută pe site, fără
re-ștampilare, va fi vizibilă imediat".

ZTA policy attestation joacă acest rol. Pipeline-ul:

1. Citește `security-policy.yaml` (politica security declarată pentru
   aplicație).
2. Citește manifestul `ZeroTrustApplication.spec` exact cum va fi aplicat în
   cluster.
3. Calculează `expected_infra_hash = sha256(canonical(spec))`.
4. Împachetează totul ca predicate + atestează cu cosign.

În cluster, operatorul:

1. Citește manifestul aplicat (`spec`-ul curent al ZTA).
2. Aplică aceeași canonicalizare.
3. Calculează propriul `computed_infra_hash`.
4. Compară cu `expected_infra_hash` din atestare.

Dacă cineva modifică manifestul ZTA între ce a fost atestat la build și ce
e aplicat în cluster (ex. adaugă un `extraEnvVar` cu un secret), hash-urile
nu se mai potrivesc → operatorul respinge.

## §5.2 Call site în pipeline

```yaml
# ci-cd.yaml:259-265
- name: Attach ZTA policy attestation
  uses: SabinGhost19/policyAttestor-action@main
  with:
    image: ${{ needs.build-push.outputs.image_repo }}@${{ needs.build-push.outputs.image_digest }}
    policy-path: ./security-policy.yaml
    manifest-dir: ./${{ env.MANIFESTS_CHECKOUT_PATH }}/${{ env.MANIFESTS_SUBPATH }}
    attestation-type: https://devsecops.licenta.ro/attestations/custom-zta-policy/v1
```

`manifest-dir` pointează către checkout-ul *celuilalt* repository
(`vulfastapi-manifests-samples`). Avantajul separării: hash-ul include
manifestul GitOps așa cum va fi aplicat, nu o versiune locală.

## §5.3 Conversia policy YAML → JSON predicate

```bash
# customGithubActionAction-zta-policy-attestor/action.yml (selecție)
test -f "${{ inputs.policy-path }}"
yq -o=json '.' "${{ inputs.policy-path }}" > /tmp/zta-policy-predicate.json
cat /tmp/zta-policy-predicate.json | jq . >/dev/null
```

Trivial: `yq` convertește YAML → JSON. Predicate-ul *de bază* este pur și
simplu `security-policy.yaml` reprezentat ca JSON.

## §5.4 Calculul `expected_infra_hash`

```bash
# action.yml (selecție)
ZTA_SPECS_JSON="$(yq ea -o=json '[select(.kind == "ZeroTrustApplication") | .spec]' "${YAML_FILES[@]}")"
SPEC_COUNT="$(printf '%s' "$ZTA_SPECS_JSON" | jq 'length')"
if [ "$SPEC_COUNT" -ne 1 ]; then
  echo "manifest-dir must contain exactly one ZeroTrustApplication spec; found: $SPEC_COUNT" >&2
  exit 1
fi

if [ "${{ inputs.sync-manifest-image }}" = "true" ]; then
  CANONICAL_SPEC="$(printf '%s' "$ZTA_SPECS_JSON" | jq -c -S --arg image "${{ inputs.image }}" '.[0] | .image = $image')"
else
  CANONICAL_SPEC="$(printf '%s' "$ZTA_SPECS_JSON" | jq -c -S '.[0]')"
fi
INFRA_HASH="$(printf '%s' "$CANONICAL_SPEC" | sha256sum | awk '{print $1}')"

jq --arg hash "$INFRA_HASH" '. + {expected_infra_hash: $hash}' /tmp/zta-policy-predicate.json > /tmp/final-predicate.json
```

Patru observații critice:

1. **`yq ea` (eval-all)** + `select(.kind == "ZeroTrustApplication")` —
   acceptă orice combinație de YAML-uri în manifest-dir, filtrează doar
   `ZeroTrustApplication`-ul. Dacă există 0 sau ≥2 ZTA-uri, eșuează zgomotos.
2. **Canonicalizare**: `jq -c -S` produce **JSON compact** (fără spații în
   plus, fără newline-uri) și **chei sortate** (`-S`). Aceleași două
   transformări sunt aplicate în operator (vezi §11). Două serializări JSON
   ale aceleiași date pot fi diferite bit-cu-bit fără canonicalizare → fără
   reguli stricte, hash-urile nu s-ar potrivi niciodată.
3. **`sync-manifest-image=true`** (default) — înlocuiește `.spec.image` cu
   noul digest înainte de a calcula hash-ul. Acesta e mecanismul care
   permite ca *manifestul GitOps* să fie actualizat după build (`bump-manifests-repo`)
   păstrând în același timp un `expected_infra_hash` valid: pipeline-ul
   atestă hash-ul cu **viitoarea** valoare a image-ului, apoi împinge
   exact acea valoare în GitOps.
4. **`. + {expected_infra_hash: $hash}`** — adaugă câmpul în predicate. Notă:
   `+` în jq face merge la nivel de top-level keys; dacă policy YAML-ul
   conține deja o cheie `expected_infra_hash`, este suprascrisă cu hash-ul
   calculat (intenționat).

## §5.5 Atestarea

```bash
# action.yml (final)
cosign attest --yes \
  --predicate /tmp/final-predicate.json \
  --type "$ATTESTATION_TYPE" \
  "${{ inputs.image }}"
```

Predicate type stabil: `https://devsecops.licenta.ro/attestations/custom-zta-policy/v1`.

Conținutul atestării include:

- Toate câmpurile din `security-policy.yaml` (politica completă).
- `expected_infra_hash` (sha256-ul `spec`-ului ZTA cu noul digest).

## §5.6 Verificare operator (perspectivă pipeline)

Operatorul nu doar verifică semnătura atestării. Recalculează independent
hash-ul. Citez codul operator:

```python
# zta-operator/src/zta_operator/supply_chain_attestation.py:113-117
def _hash_spec_payload(payload: dict[str, Any]) -> str:
    obj = _to_jsonable(payload)
    encoded = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
```

Observă:

- `sort_keys=True` — echivalent cu jq `-S`.
- `separators=(",", ":")` — echivalent cu jq `-c`.
- `_to_jsonable(...)` — normalizator suplimentar pentru tipuri Python
  (Decimal → str, set → list sortată, etc.). Necesar pentru că obiectul
  primit de operator a fost serializat/deserializat de kubernetes-client.

## §5.7 Atac specific neutralizat: "GitOps drift attack"

Scenariu fără ZTA policy attestation:

1. Atacatorul obține acces la repository-ul GitOps de manifeste.
2. Modifică `ZeroTrustApplication.spec.runtimeSecurity.allowedPaths` să
   permită `/etc/`.
3. ArgoCD reconciliază; operatorul aplică deployment-ul cu noua configurație.

Cu ZTA policy attestation:

1. Modificarea schimbă `canonical(spec)`.
2. `computed_infra_hash` în operator devine X'.
3. Atestarea atașată imaginii conține `expected_infra_hash = X` (vechiul).
4. Operatorul detectează `X' != X` → `Failed_SupplyChain`.

Atacatorul ar trebui să poată **și** modifica manifestul GitOps, **și** să
poată re-ataşa o atestare nouă semnată ca workflow-ul oficial — ceea ce
necesită compromiterea credentialelor GitHub Actions ale workflow-ului
(scope `id-token: write`), o suprafață mult mai mică.

## §5.8 Verificare în cluster (referință)

Vezi `11-operator-attestation-verify.md` §11.4 pentru codul exact din
`supply_chain_attestation.py` care:

1. Cheamă `_verify_attestation_by_type(image, type="https://devsecops.licenta.ro/attestations/custom-zta-policy/v1", trusted_issuers)`.
2. Extrage `predicate.expected_infra_hash`.
3. Recalculează `_hash_spec_payload(spec)`.
4. Compară. Mismatch → `attestation-hash-validated` violation.

## §5.9 Ce urmează

A treia atestare custom *despre build* (după VBBI și ZTA policy) este SLSA
v1.0: `06-pipeline-slsa-v1.md`.
