# 14 — Operator: Falco rules + Talon runtime enforcement

## §14.1 Analogie: alarma de incendiu + sistemul de stingere automat

Într-un mall:
- **Detectorul de fum** (Falco) doar *detectează* — emite un semnal sonor
  când vede fum.
- **Sistemul de stingere** (Talon) e *executorul* — primește semnalul de la
  detector, acționează valvele, închide ușile, oprește ventilația.

Cele două componente sunt deliberate separate. Detectorul are reguli simple
(„dacă temperatura > X, alarmă"); executorul are reguli complexe ("dacă
alarmă în zona Y, închide ușile către Z, dar lasă deschis ieșirea de
urgență V").

În cluster:
- **Falco** observă syscall-uri prin eBPF/kernel module, emite evenimente
  pe baza regulilor declarate.
- **Talon** (`falco-talon`) primește evenimente de la Falco prin webhook,
  aplică acțiuni K8s (izolare prin NetworkPolicy, kill pod, log).

Operatorul nostru configurează **ambele**:
1. ConfigMap cu regula Falco custom per-aplicație.
2. Adaugă o entry în ConfigMap-ul global Talon care leagă regula Falco de
   o acțiune K8s.

## §14.2 ConfigMap-ul Falco (creat în provisioning loop)

```python
# operator.py:683-686 (din §13)
if runtime:
    objects.append(
        build_falco_rule_configmap(name=name, namespace=namespace, image=image, allowed_paths=allowed_paths, owner=owner)
    )
```

Conținutul (din `resources.py:build_falco_rule_configmap`, conceptual):

```yaml
- rule: Unauthorized_Write_<ns>_<name>
  desc: Detect writes outside allowed paths for <ns>/<name>
  condition: >
    container.image.repository = "<image_repo>"
    and evt.type in (open, openat, openat2)
    and (evt.arg.flags contains O_WRONLY or evt.arg.flags contains O_RDWR)
    and not fd.name startswith "<allowed_path_1>"
    and not fd.name startswith "<allowed_path_2>"
  output: "Unauthorized write attempt in <ns>/<name>"
  priority: WARNING
```

Numele regulii este generat deterministic:

```python
# operator.py:224-225
def _falco_rule_name(namespace: str, name: str) -> str:
    return f"Unauthorized_Write_{namespace}_{name}".replace("-", "_")
```

Falco nu acceptă cratime în numele regulilor — substituite cu underscore.

## §14.3 Upsert Talon

```python
# operator.py:699-721 (selecție, după resource apply loop)
if runtime:
    falco_rule_name = _falco_rule_name(namespace, name)
    try:
        upsert_talon_rule(
            core=core,
            app_namespace=namespace,
            app_name=name,
            falco_rule_name=falco_rule_name,
        )
        adapter.info(
            "Talon rule upserted",
            extra={"event": "talon-configmap-upsert", "falco_rule": falco_rule_name},
        )
    except TalonConfigError as exc:
        adapter.warning(
            "Talon rule upsert failed",
            extra={"event": "talon-configmap-error", "error": str(exc)},
        )
```

Talon are un singur ConfigMap global (`falco-talon-rules` în namespace
`falco-talon`), partajat de toate aplicațiile.

## §14.4 Cum arată regula Talon

```python
# talon.py:58-72
def _build_rule(namespace: str, app_name: str, falco_rule_name: str) -> dict:
    return {
        "name": _rule_name(namespace, app_name),
        "description": f"Isolate compromised app {namespace}/{app_name}",
        "match": {
            "rules": [falco_rule_name],
        },
        "actionner": "kubernetes:networkpolicy",
        "parameters": {
            "namespace": namespace,
            "pod_selector": f"app={app_name}",
            "type": "isolate",
        },
    }
```

Câmpurile:

- `match.rules` — listează regula Falco care declanșează această acțiune.
  Match exact pe nume.
- `actionner: kubernetes:networkpolicy` — built-in actionner Talon care
  scrie o NetworkPolicy.
- `parameters.type: isolate` — modul `isolate` aplică NetworkPolicy cu
  `policyTypes: [Ingress, Egress]` și liste vide (= deny-all).

## §14.5 Read-modify-write pe ConfigMap

```python
# talon.py:74-107
def upsert_talon_rule(core: client.CoreV1Api, app_namespace: str, app_name: str, falco_rule_name: str) -> None:
    try:
        cm = core.read_namespaced_config_map(name=TALON_CONFIGMAP_NAME, namespace=TALON_NAMESPACE)
    except ApiException as exc:
        raise TalonConfigError(
            f"Cannot read Talon ConfigMap {TALON_NAMESPACE}/{TALON_CONFIGMAP_NAME}: {exc.reason}"
        ) from exc

    data = cm.data or {}
    raw_rules = data.get(TALON_CONFIGMAP_KEY, "")
    root, rules, mode = _parse_rules_yaml(raw_rules)

    name = _rule_name(app_namespace, app_name)
    rule = _build_rule(namespace=app_namespace, app_name=app_name, falco_rule_name=falco_rule_name)

    index = next((i for i, item in enumerate(rules) if isinstance(item, dict) and item.get("name") == name), None)
    if index is None:
        rules.append(rule)
    else:
        rules[index] = rule

    data[TALON_CONFIGMAP_KEY] = _serialize_rules(root=root, mode=mode)
    body = client.V1ConfigMap(metadata=client.V1ObjectMeta(name=TALON_CONFIGMAP_NAME), data=data)
    core.patch_namespaced_config_map(name=TALON_CONFIGMAP_NAME, namespace=TALON_NAMESPACE, body=body)
```

Pattern read-modify-write clasic pe un ConfigMap. **Race condition
potențială**: dacă două ZTA-uri se reconciliează simultan, ambele pot citi
versiunea curentă a ConfigMap-ului și pot suprascrie modificările celuilalt.

**Mitigation parțial:** `patch_namespaced_config_map` folosește merge-patch
care, pentru un map de chei (`data`), gestionează merge la nivel de cheie.
Dar `data[TALON_CONFIGMAP_KEY]` este *un singur string* (YAML serialized),
deci modificările concurrent în acel string nu sunt safe.

**Decizia design:** se acceptă această race condition pentru că:
- ZTA-urile rar se aplică simultan (sunt aplicate prin GitOps secvențial).
- Operatorul rulează singur instance (nu HA), deci nu sunt două reconcile-uri
  concurrent pe același ZTA.
- Dacă apare totuși o pierdere, următoarea reconciliere a ZTA-ului
  „pierdut" va re-aplica regula.

Soluția completă (Optimistic Concurrency Control prin `resourceVersion`) ar
adăuga complexitate disproporționată.

## §14.6 Format YAML al rules.yaml

```python
# talon.py:28-46
def _parse_rules_yaml(raw: str) -> tuple[dict | list, list, str]:
    parsed = yaml.safe_load(raw) if raw.strip() else []
    if parsed is None:
        parsed = []

    if isinstance(parsed, list):
        return parsed, parsed, "list"

    if isinstance(parsed, dict):
        rules = parsed.get("rules")
        if rules is None:
            parsed["rules"] = []
            return parsed, parsed["rules"], "dict"
        if not isinstance(rules, list):
            raise TalonConfigError("rules.yaml has invalid format: 'rules' is not a list")
        return parsed, rules, "dict"

    raise TalonConfigError("rules.yaml has invalid YAML root type")
```

Talon acceptă **două** formate:

1. Lista YAML top-level: `[ rule1, rule2, ... ]`.
2. Map cu cheie `rules`: `{ rules: [ rule1, ... ] }`.

Operatorul detectează automat formatul, păstrează „mode-ul" și
re-serializează în același format. Această dualitate permite admin-ilor să
extindă manual ConfigMap-ul cu meta-config (ex. global notifications) fără
să strice operatorul.

## §14.7 Pe scurt: lanțul de detectare → reacție

```
Pod execută syscall non-permis (ex. write în /etc/)
        │
        ▼
Falco DaemonSet (eBPF probe) prinde syscall
        │
        ▼
Falco evaluează rule Unauthorized_Write_<ns>_<app>
        │ match
        ▼
Falco emite event → webhook către falco-talon
        │
        ▼
Talon evaluează rule zta-<ns>-<app>-isolate
        │ match
        ▼
Talon apelează kubernetes:networkpolicy actionner
        │
        ▼
NetworkPolicy creată în namespace cu deny-all
        │
        ▼
Pod izolat — nu mai poate vorbi cu nimic
```

Timpul total end-to-end pe un cluster local: ~1-3 secunde de la syscall la
NetworkPolicy aplicată. Pentru atacuri lente (data exfiltration), e
suficient. Pentru atacuri rapide (RCE → fork bomb), nu — Talon nu poate
preveni execuția, doar conține efectele după ce s-au întâmplat.

## §14.8 Ce urmează

Ultimul pas în provisioning: ingestia asincronă în GUAC. Vezi
`15-operator-guac-ingest.md`.
