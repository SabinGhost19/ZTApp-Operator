# 02 — Pipeline: build + push imagine

## §2.1 Analogie: certificat de naștere al unei opere de artă

O pictură este pictată într-un atelier. La final, galeria îi atribuie un cod
de identificare unic, gravat pe spate, care nu mai poate fi modificat. Acel
cod e *digestul* operei. Numele atelierului, autorul, data, dimensiunea sunt
metadate. Codul (digestul) este cheia care permite oricărei autorități să
spună mai târziu, fără ambiguitate: "*aceasta* este pictura X, nu o copie".

În OCI, digest-ul `sha256:...` joacă acest rol. Tag-urile (`v1.0.0`, `latest`)
sunt nume mutabile (etichete care pot fi mutate pe altă imagine). Operatorul
nostru refuză imagini fără digest: vezi
[`10-operator-cosign-trivy.md`](10-operator-cosign-trivy.md) §10.2.

## §2.2 Job `build-push`

```yaml
# ci-cd.yaml:78-127 (selecție)
build-push:
  runs-on: ubuntu-latest
  needs: build-metadata
  outputs:
    image_repo: ${{ steps.imagevars.outputs.image_repo }}
    image_digest: ${{ steps.build-and-push.outputs.digest }}

  steps:
    - name: Normalize image repository name
      id: imagevars
      shell: bash
      run: |
        echo "image_repo=${REGISTRY}/${GITHUB_REPOSITORY_OWNER,,}/demo-vulnerable-fastapi" >> "$GITHUB_OUTPUT"
```

**Detaliu non-trivial:** `${GITHUB_REPOSITORY_OWNER,,}` aplică *bash parameter
expansion* care normalizează la litere mici. GHCR cere lowercase pentru
namespace; dacă owner-ul GitHub e `SabinGhost19`, GHCR îl așteaptă ca
`sabinghost19`. O simplă variabilă referențiată direct ar produce un push
406 Not Acceptable.

## §2.3 Login GHCR

```yaml
# ci-cd.yaml:101-106
- name: Log in to GHCR
  uses: docker/login-action@v3
  with:
    registry: ${{ env.REGISTRY }}
    username: ${{ github.actor }}
    password: ${{ secrets.GITHUB_TOKEN }}
```

`secrets.GITHUB_TOKEN` este injectat de runtime cu scope-ul declarat în
`permissions.packages: write`. Token-ul are durata de viață a job-ului.
Niciun PAT (Personal Access Token) nu e folosit — toate operațiunile pe
GHCR rulează pe identitatea efemeră a workflow-ului.

## §2.4 Metadata + tags

```yaml
# ci-cd.yaml:108-117
- name: Extract metadata
  id: meta
  uses: docker/metadata-action@v5
  with:
    images: ${{ steps.imagevars.outputs.image_repo }}
    tags: |
      type=ref,event=branch
      type=ref,event=tag
      type=sha,prefix=sha-
      type=raw,value=v1.1.8,enable={{is_default_branch}}
```

Genereează simultan mai multe tag-uri pentru aceeași imagine:

- `main` (din `event=branch`).
- `v1.2.3` (din `event=tag`).
- `sha-abc123...` (din `event=sha`, prefix `sha-`).
- `v1.1.8` (raw, doar pe branch-ul default).

Important: indiferent de câte tag-uri pointează spre ea, imaginea este una
singură în registry, identificabilă unic prin digest. Tag-urile sunt
*aliasuri*, digest-ul este *identitatea*.

## §2.5 Build și push

```yaml
# ci-cd.yaml:119-126
- name: Build and push image
  id: build-and-push
  uses: docker/build-push-action@v6
  with:
    context: .
    push: true
    tags: ${{ steps.meta.outputs.tags }}
    labels: ${{ steps.meta.outputs.labels }}
```

`docker/build-push-action@v6` returnează în `outputs.digest` exact șirul
`sha256:...` al manifestului OCI (nu al stratului root, nu al config-ului).
Toate operațiunile downstream — semnătură, atestări, scan, manifest update —
folosesc **digest-ul**, nu tag-urile. Un atacator care reușește să mute tag-ul
`v1.1.8` pe o imagine compromisă în GHCR nu poate păcăli operatorul, pentru
că ZTA-ul aplicat referențiază digest-ul (`@sha256:...`), nu tag-ul.

## §2.6 Output-urile job-ului

```yaml
# ci-cd.yaml:81-84
outputs:
  image_repo: ${{ steps.imagevars.outputs.image_repo }}
  image_digest: ${{ steps.build-and-push.outputs.digest }}
```

Aceste două output-uri sunt re-folosite în 5 job-uri downstream
(`scan-image`, `attestations`, `slsa-provenance`, `sign-and-verify`,
`bump-manifests-repo`). Toate construiesc referința imutabilă
`${image_repo}@${image_digest}`. Nicăieri în restul pipeline-ului nu se
manipulează vreun tag.

## §2.7 Ce vede operatorul în legătură cu acest pas?

**Operatorul nu participă direct în build-push.** Operatorul doar consumă
output-ul: imaginea referențiată în ZTA-ul aplicat. Verificările imediate ale
operatorului pe această imagine:

```python
# zta-operator/src/zta_operator/supply_chain.py:47-56
def validate_image_reference(image: str) -> None:
    if not image.startswith("ghcr.io/"):
        raise SupplyChainError("Image must use ghcr.io registry.")
    if "@sha256:" in image:
        return
    if ":" not in image.rsplit("/", 1)[-1]:
        raise SupplyChainError("Image tag is required and must be immutable (e.g. v1.0.0).")
    tag = image.rsplit(":", 1)[-1]
    if tag.lower() == "latest":
        raise SupplyChainError("Tag 'latest' is forbidden.")
```

Trei constrângeri exprimate aici:

1. **Registry constraint:** doar `ghcr.io/...`. Un atacator care reușește să
   convingă un dev să aplice un ZTA cu `docker.io/evil/foo` este blocat imediat.
2. **Digest preferred:** dacă imaginea conține `@sha256:`, e acceptată
   imediat (chiar și fără tag). Aceasta e calea recomandată.
3. **No `latest`:** tag-ul `latest` e refuzat explicit. Permite scenarii ca:
   un dev rulează `kubectl apply` cu `image: ghcr.io/.../foo:v1.0.0` în timp
   ce un atacator a împins o imagine compromisă cu același tag `v1.0.0` între
   timp. Pentru a închide complet acest vector, atacatorul ar trebui să poată
   muta tag-uri în GHCR — ceea ce necesită `packages: write`, controlat de
   `GITHUB_TOKEN`-ul propriu al repository-ului.

Notă: această verificare se face *după* poarta de provenance (vezi
[`09-operator-sca-policy-matching.md`](09-operator-sca-policy-matching.md)
§9.3), nu înaintea ei. Logica completă: §10.

## §2.8 Eșecuri tipice și efectul lor

| Cauză | Simptom în pipeline | Efect în operator |
|---|---|---|
| GHCR rate limit | push fails | Job blocat; reconcile pe ZTA-ul vechi continuă |
| GITHUB_TOKEN fără `packages:write` | login OK, push 403 | Idem |
| Imagine cu owner case-sensitive | push 406 | Idem |
| Buildx out of disk | build fail mid-step | Idem |

Per design, operatorul nu cunoaște și nu poate cunoaște aceste eșecuri.
Pipeline-ul fail-ează zgomotos în GitHub Actions UI; operatorul continuă să
ruleze cu ultima imagine validă deja referențiată în cluster.

## §2.9 Ce urmează

După push, imaginea este *anonimă* pentru operator — fără semnătură, fără
atestări. Următorul pas atașează semnăturile (`03-pipeline-attestari-supply-chain.md`).
