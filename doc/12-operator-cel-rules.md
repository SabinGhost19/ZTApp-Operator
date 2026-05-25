# 12 — Operator: reguli CEL custom

## §12.1 Analogie: regulamentul de circulație vs ordonanțele locale

Codul rutier național e fix — viteza maximă, prioritatea pe semafor.
Ordonanțele locale (consiliu municipal) pot adăuga reguli specifice: "în
zona X interzis camioane peste Y tone". Polițistul aplică ambele: prima
sunt statice, scrise în lege; a doua sunt configurabile per oraș.

Pentru ZTA-uri, codul rutier este logica hardcodată în
`supply_chain_attestation.py` (cosign, trivy, SBOM forbiddenPackages,
manifest hash). Ordonanțele locale sunt **regulile CEL** (Common Expression
Language) declarate în `spec.customRules` al SCA-ului.

CEL este același limbaj folosit de Kubernetes pentru `x-kubernetes-validations`
și de Cloud APIs (IAM, BigQuery, Cloud Armor). E **non-Turing-complete**
prin design: nu suportă loop-uri arbitrare, deci nu poate cauza hang în
operator.

## §12.2 De ce CEL și nu Rego (OPA) sau Lua?

| Limbaj | Pro | Contra |
|---|---|---|
| **CEL** | Standard Kubernetes; non-Turing; sintaxă familiară (similar JavaScript); bindings Python (`celpy`) | Mai puțin expresiv decât Rego |
| **Rego (OPA)** | Foarte expresiv; ecosistem matur | Server OPA separat sau sidecar; complexitate operațională |
| **Lua** | Embeddable | Turing-complete; necesită sandbox-uri pentru siguranță |

Pentru un operator simplu, CEL e *sweet spot*: zero infra extra, sintaxă
admisă deja de devs care folosesc CRD validation rules.

## §12.3 Contextul disponibil în CEL

Documentația în-cod:

```python
# zta-operator/src/zta_operator/cel_eval.py:1-16
"""CEL (Common Expression Language) evaluator for SupplyChainAttestation customRules.

Why CEL: YAML-based policies are static and force every new requirement
through an operator code change. CEL is the same expression language used
by Kubernetes admission and validation (CRD `x-kubernetes-validations`),
giving administrators a non-Turing-complete but expressive interface for
ad-hoc rules without learning Rego/OPA.

Each rule receives a uniform context:
    voucher   — VBBI predicate (build_context, hmac_chain, merkle_tree)
    image     — resolved OCI reference (string)
    zta       — ZeroTrustApplication.spec
    vex       — list of OpenVEX statements parsed for this image
    sbom      — SBOM predicate (or {} if not attested)
"""
```

Cinci variabile injectate în contextul fiecărei reguli. Permit regulilor
să facă match cross-artifact (ex. "Dacă VBBI declară SLSA L4 dar SBOM-ul
conține un pachet de versiune sub X, refuză").

## §12.4 Semantica `Deny` / `Allow` / `Alert`

```python
# cel_eval.py:99-115
truthy = bool(outcome)
fired = False
# Semantics:
#   Deny rules fire when expression is True (it describes a violation).
#   Allow rules fire when expression is False (a required condition failed).
#   Alert rules surface as warnings without blocking.
if action == "Deny" and truthy:
    result.deny.append(f"{name}: {expression}")
    fired = True
elif action == "Allow" and not truthy:
    result.deny.append(f"{name} (required condition false): {expression}")
    fired = True
elif action == "Alert" and truthy:
    result.alert.append(f"{name}: {expression}")
    fired = True
elif action == "Allow" and truthy:
    result.allow.append(name)
```

Trei moduri, semantici diferite:

| Action | Expression | Efect |
|---|---|---|
| `Deny` | true | Violation (blocking) |
| `Deny` | false | No-op |
| `Allow` | true | Condition met (log only) |
| `Allow` | false | Violation (blocking — required condition failed) |
| `Alert` | true | Warning (non-blocking) |
| `Alert` | false | No-op |

**Intuiție:**

- Un `Deny` *descrie o violare* (ex. `image.startsWith('docker.io/')` →
  "imagine de pe docker.io, NU acceptăm"). Adevărat = violare.
- Un `Allow` *descrie o cerință* (ex. `voucher.build_context.slsa_level >= 3`
  → "cer SLSA L3+"). Adevărat = OK, fals = violare.
- Un `Alert` e un *warning*, nu blochează.

## §12.5 Trei reguli din SCA-ul sample

```yaml
# demo-app-manifests-samples/demo-app/sca-sample.yaml:40-52
customRules:
  - name: require-slsa-level-3
    description: VBBI voucher must declare SLSA Build L3 or higher
    expression: "voucher.build_context.slsa_level >= 3"
    action: Allow
  - name: deny-non-ghcr-images
    description: Only images from the official GHCR registry are allowed
    expression: "!image.startsWith('ghcr.io/')"
    action: Deny
  - name: alert-large-sbom
    description: Surface a warning when SBOM exceeds 500 packages
    expression: "size(sbom.packages) > 500"
    action: Alert
```

Trei pattern-uri exemplificate. Niciuna nu poate fi exprimată direct prin
câmpuri statice din SCA — toate combină informații cross-artifact (voucher
× image × sbom).

## §12.6 Evaluatorul: bucla principală

```python
# cel_eval.py:61-115 (selecție)
def evaluate_custom_rules(
    custom_rules: list[dict[str, Any]],
    context: dict[str, Any],
) -> CelEvalResult:
    """Evaluate a list of CEL rules and bucket outcomes by action.

    If celpy is not installed (operator deployed without the CEL dependency),
    we degrade gracefully: rules are skipped with a single error message
    rather than crashing reconciliation.
    """
    result = CelEvalResult()
    if not custom_rules:
        return result

    try:
        import celpy  # type: ignore
    except Exception as exc:  # ImportError or runtime issue
        result.errors.append(f"CEL evaluator unavailable: {exc}")
        return result

    env = celpy.Environment()

    cel_context: dict[str, Any] = {}
    for key, value in context.items():
        cel_context[key] = celpy.json_to_cel(value) if value is not None else celpy.json_to_cel({})

    for rule in custom_rules:
        name = str(rule.get("name", "<unnamed>")).strip()
        expression = str(rule.get("expression", "")).strip()
        action = str(rule.get("action", "Deny")).strip()
        if not expression:
            result.errors.append(f"rule {name!r} has no expression")
            result.evaluations.append({...})
            continue
        try:
            program = env.program(env.compile(expression))
            outcome = program.evaluate(cel_context)
        except Exception as exc:
            result.errors.append(f"rule {name!r} evaluation failed: {exc}")
            result.evaluations.append({...})
            continue
        ...
```

Note inginerești:

1. **Graceful degradation** la `import celpy` failure — operator continuă
   fără reguli CEL, log warning. Permite deployment fără dependența opțională.
2. **Compile + run** sunt separate. Erorile de compilare (`expression`
   invalid) sunt prinse și înregistrate per regulă, nu doboară toate
   regulile.
3. **`json_to_cel`** convertește dict-uri Python (din K8s API) în obiectele
   CEL native (`celpy.MapType`, `celpy.ListType`, etc.). Comparațiile între
   tipuri Python pure și CEL pot eșua silent.

## §12.7 Logger silenced

```python
# cel_eval.py:23-37
# celpy ships with very chatty internal loggers that emit one INFO line per
# AST node visited. On non-trivial CEL expressions this floods the operator
# logs with thousands of "Tree(...)", "Evaluator", "NameContainer" lines per
# reconcile, drowning out real events. Silence them at import time.
for _noisy in (
    "celpy",
    "celpy.evaluation",
    "Evaluator",
    "NameContainer",
    "Environment",
    "evaluation",
):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
```

Detaliu operațional pur, dar important: fără acest filtru, log-urile
operator-ului erau inutilizabile. Documentația cere această atenție pentru
că o problemă similară (logger chatty) poate apărea cu orice dependență
nouă; pattern-ul de silencing aplicat la import time e general.

## §12.8 Bug-fix istoric: `celEvaluations` se pierdea la denial

```python
# supply_chain_attestation.py (după bug-fix)
cel_result = evaluate_custom_rules(custom_rules, cel_ctx)
cel_evaluations = list(cel_result.evaluations)
# Persist celEvaluations to the status subresource *before* any
# downstream raise. Otherwise a denying rule would short-circuit
# the function with `raise SupplyChainPolicyError(...)` and the
# CelEvaluationsTable on the UI would never see why the app was
# rejected — exactly when the user needs that diagnostic most.
# Uses merge-patch so other attestation fields are preserved.
try:
    _status_patch(
        custom, namespace, app_name,
        {"attestations": {"celEvaluations": cel_evaluations}},
    )
except ApiException:
    logger.debug("status.attestations.celEvaluations early-patch failed")
```

Problema istorică: `cel_result.evaluations` era persistat doar în return-ul
final al funcției. Dacă o regulă `Deny` adăuga la `violations`, codul
ridica `SupplyChainPolicyError` *înainte* de return, iar `celEvaluations`
nu ajungea niciodată în status. UI-ul afișa un tabel gol exact pentru
aplicațiile respinse.

Fix: scriere proactivă cu merge-patch înainte de orice `raise`. Costul
unui PATCH extra e neglijabil; valoarea diagnostică e mare.

## §12.9 Persistare în UI

Backend serializează `status.attestations.celEvaluations` ca
`summary.celEvaluations[]`:

```python
# userInterfaceDashboard/backend/app/services/serializers.py:140,195
cel_evaluations = attestations.get("celEvaluations", []) or []
...
"celEvaluations": cel_evaluations,
```

Frontend îl afișează în `CelEvaluationsTable.vue` cu coloane `Rule`,
`Action`, `Status (fired)`, `Expression`, `Outcome`.

## §12.10 Ce urmează

CEL e ultima poartă de policy. Dacă totul a trecut,
`validate_admission_with_attestations` returnează cu success → operatorul
intră în faza de provisioning. Vezi `13-operator-provisioning.md`.
