# 04 — Pipeline: VBBI voucher (Voucher-Based Build Integrity)

## §4.1 Analogie: registru notarial cu lanț de custody

Un act notarial nu garantează doar conținutul ultimei semnături. Garantează
**lanțul** de evenimente: notarul semnează A, apoi B, apoi C, fiecare
semnătură incluzând hash-ul semnăturii anterioare. Dacă cineva încearcă să
schimbe retroactiv B, semnătura lui C devine invalidă; nu există modalitate
de a "rescrie istoria" fără a invalida tot ce vine după.

VBBI face exact asta pentru pașii pipeline-ului. Fiecare pas (lint, test,
build, scan) produce un *receipt* JSON. Action-ul construiește:

1. Un **lanț HMAC** unde HMAC-ul fiecărui pas include hash-ul receipt-ului
   curent + HMAC-ul pasului anterior.
2. Un **arbore Merkle** peste toate HMAC-urile, cu un *root hash* unic.

Predicate-ul atașat ca atestare conține lanțul complet + root-ul Merkle.
Operatorul `provenance-enforcer` recalculează lanțul + root-ul independent
și compară. Dacă cineva a modificat un receipt sau a reordonat pașii, root-ul
nu se mai potrivește.

## §4.2 Anatomia call site-ului

```yaml
# ci-cd.yaml:249-257
- name: Attach VBBI attestation
  id: vbbi
  uses: SabinGhost19/Voucher-Based-Build-Integrity-Action@1.0
  with:
    image: ${{ needs.build-push.outputs.image_repo }}@${{ needs.build-push.outputs.image_digest }}
    commit-sha: ${{ github.sha }}
    step-spec-path: /tmp/vbbi/step-spec.json
    hmac-key: ${{ secrets.VBBI_HMAC_KEY || 'dev-only-vbbi-key' }}
    slsa-level: "3"
```

**`step-spec-path`** referențiază un JSON construit anterior în pipeline:

```yaml
# ci-cd.yaml:240-247
cat > /tmp/vbbi/step-spec.json <<'EOF'
[
  {"name": "linting", "file": "/tmp/vbbi/lint-results.json"},
  {"name": "unit-tests", "file": "/tmp/vbbi/test-results.json"},
  {"name": "image-build", "file": "/tmp/vbbi/build-results.json"},
  {"name": "vulnerability-scan", "file": "/tmp/vbbi/scan-results.json"}
]
EOF
```

Patru pași, fiecare cu un fișier de receipt. Ordinea contează: HMAC-ul
pasului N depinde de HMAC-ul pasului N-1.

## §4.3 Lanțul HMAC

```python
# customGithubActionAction-vbbi-voucher-attestor/action.yml:107-109
def local_hmac_step(secret_key: str, metadata_hash: str, previous_hash: str) -> str:
  payload = f"{metadata_hash}{previous_hash}".encode("utf-8")
  return hmac.new(secret_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
```

Formula:

```
h_0 = sha256(commit_sha)                                      # seed
h_n = HMAC_sha256(secret_key, sha256(receipt_n) || h_{n-1})   # step n
```

Final voucher = `h_N` (HMAC-ul ultimului pas). Lanțul are proprietatea că
modificarea oricărui receipt (sau a ordinii) schimbă `h_N` în mod
non-reversibil pentru cineva care nu cunoaște `secret_key`.

**Două variante de cheie:**

1. **`shared-secret`** (default) — `secret_key` e un GitHub secret. Slab
   pentru "true zero-trust" pentru că GitHub Actions cunoaște cheia, dar
   demonstrează principiul.
2. **`vault-transit`** — cheia rămâne în Vault; HMAC-ul e calculat de Vault
   prin API-ul Transit. Niciodată nu părăsește Vault-ul (function call vs
   key call). Acesta e modul *production-grade*.

```python
# action.yml:111-151 (selecție)
def vault_hmac_step(metadata_hash: str, previous_hash: str) -> str:
  ...
  req = request.Request(
    f"{vault_address.rstrip('/')}/v1/{transit_mount}/hmac/{transit_key}/{transit_algorithm}",
    data=json.dumps(
      {
        "input": base64.b64encode(
          f"{metadata_hash}{previous_hash}".encode("utf-8")
        ).decode("utf-8")
      }
    ).encode("utf-8"),
    headers={...},
    method="POST",
  )
```

## §4.4 Arborele Merkle

```python
# action.yml:97-105
# RFC 6962 domain-separated hashing for the Merkle tree:
#   MTH({d}) = SHA-256(0x00 || d)
#   MTH(left,right) = SHA-256(0x01 || left || right)
# Prevents second-preimage attacks (leaf vs internal node ambiguity).
def merkle_leaf_hash(data_hex: str) -> str:
  return hashlib.sha256(b"\x00" + bytes.fromhex(data_hex)).hexdigest()

def merkle_node_hash(left_hex: str, right_hex: str) -> str:
  return hashlib.sha256(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()
```

**De ce RFC 6962 (Certificate Transparency) și nu un Merkle vanilla?**
Domain separation (byte prefix `0x00` pentru frunze, `0x01` pentru noduri
interne) previne *second-preimage attacks* — un atacator ar putea altfel
construi un nod intern cu același hash ca al unei frunze.

```python
# action.yml:160-171
def merkle_root(leaves: list[str]) -> str:
  if not leaves:
    raise SystemExit("step-spec must contain at least one step")
  nodes = [merkle_leaf_hash(normalized_hash(item)) for item in leaves]
  while len(nodes) > 1:
    next_level = []
    for index in range(0, len(nodes), 2):
      left = nodes[index]
      right = nodes[index + 1] if index + 1 < len(nodes) else left
      next_level.append(merkle_node_hash(left, right))
    nodes = next_level
  return nodes[0]
```

**Detaliu academic:** când numărul de frunze este impar, ultima frunză e
duplicată (`right = left`). Aceasta e tehnica RFC 6962 standard pentru
arbori dezechilibrați. Un atacator nu poate exploata duplicarea pentru a
crea două structuri Merkle cu același root din date diferite, datorită
domain separation-ului.

## §4.5 Construcția predicate-ului

```python
# action.yml:222-246
predicate = {
  "build_context": {
    "repository": os.environ.get("GITHUB_REPOSITORY", ""),
    "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
    "run_id": os.environ.get("GITHUB_RUN_ID", ""),
    "event": os.environ.get("GITHUB_EVENT_NAME", ""),
    "issuer_oidc": "https://token.actions.githubusercontent.com",
    "slsa_level": int(os.environ["INPUT_SLSA_LEVEL"]),
    "image": os.environ["INPUT_IMAGE"],
    "commit_sha": os.environ["INPUT_COMMIT_SHA"],
  },
  "hmac_chain": {
    "provider": "vault-transit" if use_vault else "shared-secret",
    "algorithm": os.environ["INPUT_VAULT_TRANSIT_ALGORITHM"] if use_vault else "sha256",
    "h0_seed": seed,
    "steps": steps,
    "final_voucher": previous,
  },
  "merkle_tree": {
    "version": 2,
    "algorithm": "rfc6962-sha256",
    "leaves": leaves,
    "root_hash": merkle_root([item["hash"] for item in leaves]),
  },
}
```

**Versiunea 2 a Merkle tree** indică RFC 6962. Versiunea 1 a fost o
implementare simplistă fără domain separation (n-am inclus-o în această
versiune a action-ului; verificarea backward-compat din `provenance-enforcer`
o detectează ca `plain-sha256`).

## §4.6 Atestarea propriu-zisă

```yaml
# action.yml:257-265
- name: Attest VBBI voucher with Cosign keyless
  shell: bash
  env:
    COSIGN_EXPERIMENTAL: "false"
  run: |
    cosign attest --yes \
      --predicate "${{ steps.build-predicate.outputs.predicate_path }}" \
      --type "${{ inputs.attestation-type }}" \
      "${{ inputs.image }}"
```

Predicate type-ul default este `https://devsecops.licenta.ro/VBBI/v1`. Acesta
este URL-ul stabil pe care `provenance-enforcer` îl filtrează prin
`cosign verify-attestation --type ...`.

## §4.7 Ce se atestă vs ce se semnează

Crucial de înțeles: cosign **nu** semnează receipt-urile JSON propriu-zise.
Cosign semnează *predicate-ul VBBI* (care la rândul lui include hash-uri ale
receipt-urilor). Receipt-urile rămân în GitHub Actions artifacts (storage
efemer, 90 zile default). Operatorul nu le mai poate citi direct.

**Consecință:** dacă cineva ar reuși să modifice un receipt după build dar
înainte de atestare, ar fi prins doar prin gate-ul de verificare propriu al
pipeline-ului (§07) — pentru că HMAC-ul actual nu s-ar mai potrivi cu cel
calculat pe baza receipt-ului modificat. Operatorul nu vede receipt-urile;
verifică doar **lanțul HMAC** (cu cheia secretă disponibilă în Vault) +
**root-ul Merkle** recalculat.

## §4.8 Ce verifică operatorii (sumar)

| Pas | Ce face | Cod |
|---|---|---|
| `provenance-enforcer` | fetch VBBI via cosign | `provenance_enforcer/services/evaluation.py` |
| `provenance-enforcer` | recalcul HMAC chain | `provenance_enforcer/voucher.py` |
| `provenance-enforcer` | recalcul Merkle root | `provenance_enforcer/voucher.py` |
| `provenance-enforcer` | scrie `status.trustLevel` | `provenance_enforcer/k8s/status.py` |
| `zta-operator` | verifică doar **structura** (count steps, provider) | `zta_operator/supply_chain_attestation.py:_verify_attestation_by_type` |

Verificarea criptografică *deep* trăiește exclusiv în `provenance-enforcer`,
nu în `zta-operator`. Vezi
[`16-provenance-enforcer.md`](16-provenance-enforcer.md).

## §4.9 Ce urmează

VBBI răspunde *cum* s-a construit. Următorul artefact custom răspunde *ce
politică respectă*: `05-pipeline-zta-policy-attestor.md`.
