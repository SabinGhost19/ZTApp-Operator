# 13 — Operator: provisioning resurse K8s

## §13.1 Analogie: șantierul după aprobarea proiectului

După ce planurile sunt aprobate la primărie (cosign + atestări), maistrul
începe efectiv lucrarea. Comandă materialele (Deployment), trasează
fundațiile (Service), ridică gardurile (NetworkPolicy), instalează
sistemele de alarmă (Falco rules). Fiecare element are owner-ul aceluiași
proiect — dacă proiectul e anulat, toată construcția trebuie demolată.
Acesta e rolul `ownerReferences` în K8s.

## §13.2 Transition în faza Provisioning

```python
# operator.py:568-583
_status_patch(
    custom, namespace, name,
    {
        "phase": "Provisioning",
        "lastError": "",
        "securityState": effective_security_state,
        "attestations": attestations,
        "policyMatchDebug": policy_match_debug,
        "activeViolations": effective_violations,
        "lastVerified": attestation_status.get("lastVerified"),
        "provenance": current_status.get("provenance", {}),
        "details": vulnerability_details,
    },
)
```

Tranziție de fază. Toate atestările sunt acum cunoscute și persistate în
`status`. UI-ul afișează `ReconcileFlow` stage 4 (Attestation) ca terminat
și stage 5/6 (Provisioning) ca în curs.

## §13.3 Owner references — cleanup automat

```python
# operator.py:212-221
def _owner_reference(body: dict[str, Any]) -> dict:
    metadata = body.get("metadata", {})
    return {
        "apiVersion": f"{GROUP}/{VERSION}",
        "kind": KIND,
        "name": metadata["name"],
        "uid": metadata["uid"],
        "controller": True,
        "blockOwnerDeletion": True,
    }
```

Fiecare resursă creată de operator are acest owner ref. Consecințe:

- `kubectl delete zta foo` → kubelet detectează `ownerReferences` →
  cascade-delete pentru Deployment, Service, NetworkPolicy etc.
- `blockOwnerDeletion: True` — Garbage Collector așteaptă ștergerea finalizers
  înainte să șteargă ZTA-ul (evită orphans).
- `controller: True` — niciun alt controller nu poate „adopta" aceste
  resurse.

## §13.4 Resursele de bază

```python
# operator.py:585-597
owner = _owner_reference(body)
objects = [
    build_deployment(
        name=name,
        namespace=namespace,
        image=image,
        replicas=replicas,
        allowed_paths=allowed_paths,
        owner=owner,
        runtime_security_enabled=bool(runtime),
    ),
    build_service(name=name, namespace=namespace, owner=owner, port=service_port),
]
```

Întotdeauna create:

1. **Deployment** — workload-ul propriu-zis.
2. **Service** — ClusterIP, expune deployment-ul intern.

Restul sunt opt-in pe baza `spec`-ului ZTA.

## §13.5 Ingress + OAuth2 proxy

```python
# operator.py:599-655 (selecție)
if ingress_enabled:
    if not ingress_host:
        raise ValueError("spec.ingress.host is required when ingress.enabled is true")
    ...
    if oauth2_enabled:
        if not oauth2_service_namespace:
            raise ValueError("spec.ingress.oauth2ServiceNamespace is required when oauth2Enabled is true")

        oauth2_external_name = f"{oauth2_service_name}.{oauth2_service_namespace}.svc.cluster.local"
        objects.append(build_external_name_service(...))
        objects.append(build_oauth2_ingress(...))

    objects.append(build_ingress(
        name=f"{name}-ingress",
        ...
        auth_url=auth_url,
        auth_signin=auth_signin,
        auth_response_headers=auth_headers,
        jit_group=f"jit-access-{name}",
        groups_header=groups_header,
        groups_header_fallback=groups_header_fallback,
    ))
```

Două resurse pentru OAuth2 proxy:

1. **ExternalName Service** local în namespace — pointează către serviciul
   real `oauth2-proxy.oauth2-proxy.svc.cluster.local`. Permite ingress-ului
   să referențieze un serviciu cross-namespace fără cross-namespace network
   policy.
2. **Auth subrequest Ingress** — `/oauth2/auth` rută separată folosită de
   nginx ingress controller via annotation `auth-url`.

Ingress-ul principal include `jit_group` — un parametru folosit de JIT
access platform pentru a controla cine poate face request la app (JWT
group claim).

## §13.6 NetworkPolicy (zero-trust)

```python
# operator.py:657-666
if ingress_allowed_from or egress_allowed_to:
    objects.append(
        build_network_policy(
            name=name,
            namespace=namespace,
            ingress_allowed_from=ingress_allowed_from,
            egress_allowed_to=egress_allowed_to,
            owner=owner,
        )
    )
```

Aplicat **doar** dacă ZTA declară regulile. **Nu există default deny** la
nivel de operator (default deny e responsabilitatea cluster admin-ului prin
SCA sau o NetworkPolicy globală).

Structura tipică (din `resources.py`):

```yaml
spec:
  podSelector:
    matchLabels:
      app: <name>
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: <ns>
  egress:
    - to:
        - namespaceSelector: {...}
      ports:
        - protocol: TCP
          port: <port>
```

## §13.7 Istio (opțional)

```python
# operator.py:668-680
# Istio resources are opt-in: when wafConfig is absent, skip service-mesh provisioning.
if waf:
    objects.append(
        build_authorization_policy(
            name=name,
            namespace=namespace,
            ingress_allowed_from=ingress_allowed_from,
            owner=owner,
        )
    )
    objects.append(
        build_wasm_plugin(name=name, namespace=namespace, mode=waf_mode, app_profile=app_profile, owner=owner)
    )
```

Două resurse Istio create doar dacă `wafConfig` e declarat:

1. **AuthorizationPolicy** — restricționează tipul de trafic acceptat
   (mTLS, headers, surse).
2. **WasmPlugin** — încărcat de Envoy sidecar, rulează un mini-firewall WAF
   per-cerere (OWASP CRS via Coraza).

## §13.8 Falco rule ConfigMap (opțional)

```python
# operator.py:682-686
# Falco/Talon resources are opt-in: when runtimeSecurity is absent, skip runtime enforcement provisioning.
if runtime:
    objects.append(
        build_falco_rule_configmap(name=name, namespace=namespace, image=image, allowed_paths=allowed_paths, owner=owner)
    )
```

ConfigMap-ul conține regula custom Falco pentru această aplicație, generată
template-based din `allowedPaths`. Falco daemon (rulează ca DaemonSet la
nivel cluster) îl descoperă automat prin folder watch
(`/etc/falco/rules.d/`).

Detalii Falco/Talon: vezi `14-operator-runtime-falco-talon.md`.

## §13.9 Apply loop

```python
# operator.py:688-697
for obj in objects:
    apply_object(api_client=api_client, obj=obj)
    adapter.info(
        "Applied resource",
        extra={
            "event": "resource-applied",
            "resource_kind": obj["kind"],
            "resource_name": obj["metadata"]["name"],
        },
    )
```

`apply_object` (din `resources.py`) face *server-side apply* (SSA). SSA
gestionează automat conflictele cu manageri de field-uri concurenți:
operatorul declară doar field-urile pe care le posedă, restul rămân
atinse de alți manageri. Dacă alt operator a setat o adnotare pe
deployment, SSA nu o șterge.

Loop-ul e secvențial, nu concurrent — important pentru ordering: Service
înainte de Deployment ar fi avut ca rezultat un Service fără endpoint-uri
momentan, fără consecințe funcționale dar zgomotos în UI.

Evenimentul `resource-applied` e emis pentru fiecare obiect, prinde în
`EventsTimelinePanel` (UI).

## §13.10 Ce urmează

Pasul `runtime` (Falco + Talon) merită propriul fișier:
`14-operator-runtime-falco-talon.md`.
