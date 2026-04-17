from copy import deepcopy

from kubernetes import client
from kubernetes.client.exceptions import ApiException

from .config import FALCO_RULE_LABEL_KEY, FALCO_RULE_LABEL_VALUE, WASM_PLUGIN_API_VERSION, WASM_PLUGIN_KIND


CUSTOM_OBJECT_PLURALS = {
    ("security.istio.io", "AuthorizationPolicy"): "authorizationpolicies",
    ("extensions.istio.io", "WasmPlugin"): "wasmplugins",
}

CUSTOM_OBJECT_VERSION_FALLBACKS = {
    ("security.istio.io", "AuthorizationPolicy"): ("v1", "v1beta1"),
    ("extensions.istio.io", "WasmPlugin"): (WASM_PLUGIN_API_VERSION.split("/", 1)[1],),
}


def _metadata(name: str, namespace: str, owner: dict) -> dict:
    return {
        "name": name,
        "namespace": namespace,
        "labels": {"app": name, "managed-by": "zta-operator"},
        "ownerReferences": [owner],
    }


def build_deployment(
    name: str,
    namespace: str,
    image: str,
    replicas: int,
    allowed_paths: list[str],
    owner: dict,
    runtime_security_enabled: bool,
) -> dict:
    volume_mounts = [{"name": f"writable-{i}", "mountPath": path} for i, path in enumerate(allowed_paths)]
    volumes = [{"name": f"writable-{i}", "emptyDir": {}} for i, _ in enumerate(allowed_paths)]

    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": _metadata(name, namespace, owner),
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "containers": [
                        {
                            "name": name,
                            "image": image,
                            "securityContext": {
                                "readOnlyRootFilesystem": runtime_security_enabled,
                                "allowPrivilegeEscalation": False,
                            },
                            "volumeMounts": volume_mounts,
                        }
                    ],
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "fsGroup": 10001,
                    },
                    "volumes": volumes,
                },
            },
        },
    }


def build_service(name: str, namespace: str, owner: dict, port: int = 80) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": _metadata(name, namespace, owner),
        "spec": {
            "selector": {"app": name},
            "ports": [{"port": port, "targetPort": port, "protocol": "TCP", "name": "http"}],
        },
    }


def build_authorization_policy(name: str, namespace: str, ingress_allowed_from: list[dict], owner: dict) -> dict:
    rules = []
    if ingress_allowed_from:
        from_entries = []
        for item in ingress_allowed_from:
            source = {}
            ns = item.get("namespace")
            if ns:
                source["namespaces"] = [ns]
            if source:
                from_entries.append({"source": source})
        if from_entries:
            rules.append({"from": from_entries})

    return {
        "apiVersion": "security.istio.io/v1",
        "kind": "AuthorizationPolicy",
        "metadata": _metadata(name, namespace, owner),
        "spec": {
            "selector": {"matchLabels": {"app": name}},
            "action": "ALLOW",
            "rules": rules,
        },
    }


def build_network_policy(name: str, namespace: str, ingress_allowed_from: list[dict], egress_allowed_to: list[dict], owner: dict) -> dict:
    ingress = []
    for item in ingress_allowed_from:
        ns = item.get("namespace")
        if ns:
            ingress.append({"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}}}]})

    egress = []
    for item in egress_allowed_to:
        ns = item.get("namespace")
        ports = item.get("ports", [])
        block = {}
        if ns:
            block["to"] = [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}}}]
        if ports:
            block["ports"] = [{"protocol": "TCP", "port": p} for p in ports]
        if block:
            egress.append(block)

    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": _metadata(name, namespace, owner),
        "spec": {
            "podSelector": {"matchLabels": {"app": name}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": ingress,
            "egress": egress,
        },
    }


def build_wasm_plugin(name: str, namespace: str, mode: str, app_profile: str, owner: dict) -> dict:
    if app_profile != "REST-API":
        raise ValueError(f"Unsupported wafConfig.appProfile: {app_profile}")
    coraza_mode = "On" if mode == "Block" else "DetectionOnly"
    plugin_name = f"{name}-coraza"
    return {
        "apiVersion": WASM_PLUGIN_API_VERSION,
        "kind": WASM_PLUGIN_KIND,
        "metadata": _metadata(plugin_name, namespace, owner),
        "spec": {
            "selector": {"matchLabels": {"app": name}},
            "url": "oci://ghcr.io/corazawaf/coraza-proxy-wasm:main",
            "phase": "AUTHN",
            "pluginConfig": {
                "directives_map": {
                    "default": [
                        "SecRuleEngine " + coraza_mode,
                        "Include @owasp_crs/*.conf",
                    ]
                }
            },
        },
    }


def build_falco_rule_configmap(name: str, namespace: str, image: str, allowed_paths: list[str], owner: dict) -> dict:
    rule_name = f"Unauthorized_Write_{namespace}_{name}".replace("-", "_")
    allowed_expr = " and ".join([f'fd.name != \"{p}\"' for p in allowed_paths])
    if not allowed_expr:
        allowed_expr = "true"

    content = (
        "- rule: "
        + rule_name
        + "\n"
        + f"  desc: Detect writes outside allowed paths for {namespace}/{name}\n"
        + "  condition: >\n"
        + "    evt.type = open and evt.dir = < and container.image.repository = \""
        + image.rsplit(":", 1)[0]
        + "\" and "
        + allowed_expr
        + "\n"
        + "  output: Write outside allowed paths (file=%fd.name)\n"
        + "  priority: CRITICAL\n"
    )

    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": f"falco-rule-{name}",
            "namespace": namespace,
            "labels": {
                "app": name,
                "managed-by": "zta-operator",
                FALCO_RULE_LABEL_KEY: FALCO_RULE_LABEL_VALUE,
            },
            "ownerReferences": [owner],
        },
        "data": {"custom_rule.yaml": content},
    }


def _iter_custom_object_candidates(obj: dict) -> list[tuple[str, str, str, dict]]:
    group, _, version = obj["apiVersion"].partition("/")
    kind = obj["kind"]
    plural = CUSTOM_OBJECT_PLURALS.get((group, kind))
    if plural is None:
        raise ValueError(f"Unsupported object kind for apply: {obj['apiVersion']} {kind}")

    versions = []
    for candidate in (version, *CUSTOM_OBJECT_VERSION_FALLBACKS.get((group, kind), ())):
        if candidate and candidate not in versions:
            versions.append(candidate)

    candidates = []
    for candidate_version in versions:
        candidate_obj = deepcopy(obj)
        candidate_obj["apiVersion"] = f"{group}/{candidate_version}"
        candidates.append((group, candidate_version, plural, candidate_obj))
    return candidates


def apply_object(api_client: client.ApiClient, obj: dict) -> None:
    group, _, version = obj["apiVersion"].partition("/")
    if not version:
        group = ""
        version = obj["apiVersion"]

    kind = obj["kind"]
    metadata = obj.get("metadata", {})
    name = metadata["name"]
    namespace = metadata.get("namespace")

    core = client.CoreV1Api(api_client)
    apps = client.AppsV1Api(api_client)
    networking = client.NetworkingV1Api(api_client)

    try:
        if group == "" and kind == "Service":
            core.read_namespaced_service(name=name, namespace=namespace)
            core.patch_namespaced_service(name=name, namespace=namespace, body=obj)
            return
        if group == "" and kind == "ConfigMap":
            core.read_namespaced_config_map(name=name, namespace=namespace)
            core.patch_namespaced_config_map(name=name, namespace=namespace, body=obj)
            return
        if group == "apps" and kind == "Deployment":
            apps.read_namespaced_deployment(name=name, namespace=namespace)
            apps.patch_namespaced_deployment(name=name, namespace=namespace, body=obj)
            return
        if group == "networking.k8s.io" and kind == "NetworkPolicy":
            networking.read_namespaced_network_policy(name=name, namespace=namespace)
            networking.patch_namespaced_network_policy(name=name, namespace=namespace, body=obj)
            return

        last_exc = None
        for custom_group, custom_version, plural, candidate_obj in _iter_custom_object_candidates(obj):
            co = client.CustomObjectsApi(api_client)
            try:
                co.get_namespaced_custom_object(
                    group=custom_group,
                    version=custom_version,
                    namespace=namespace,
                    plural=plural,
                    name=name,
                )
                co.patch_namespaced_custom_object(
                    group=custom_group,
                    version=custom_version,
                    namespace=namespace,
                    plural=plural,
                    name=name,
                    body=candidate_obj,
                )
                return
            except ApiException as exc:
                last_exc = exc
                if exc.status != 404:
                    raise

                try:
                    co.create_namespaced_custom_object(
                        group=custom_group,
                        version=custom_version,
                        namespace=namespace,
                        plural=plural,
                        body=candidate_obj,
                    )
                    return
                except ApiException as create_exc:
                    last_exc = create_exc
                    if create_exc.status == 404:
                        continue
                    raise

        if last_exc is not None:
            raise last_exc
        raise ValueError(f"Unsupported object kind for apply: {obj['apiVersion']} {kind}")
    except ApiException as exc:
        if exc.status != 404:
            raise
        if group == "" and kind == "Service":
            core.create_namespaced_service(namespace=namespace, body=obj)
            return
        if group == "" and kind == "ConfigMap":
            core.create_namespaced_config_map(namespace=namespace, body=obj)
            return
        if group == "apps" and kind == "Deployment":
            apps.create_namespaced_deployment(namespace=namespace, body=obj)
            return
        if group == "networking.k8s.io" and kind == "NetworkPolicy":
            networking.create_namespaced_network_policy(namespace=namespace, body=obj)
            return

        last_exc = None
        for custom_group, custom_version, plural, candidate_obj in _iter_custom_object_candidates(obj):
            co = client.CustomObjectsApi(api_client)
            try:
                co.create_namespaced_custom_object(
                    group=custom_group,
                    version=custom_version,
                    namespace=namespace,
                    plural=plural,
                    body=candidate_obj,
                )
                return
            except ApiException as create_exc:
                last_exc = create_exc
                if create_exc.status == 404:
                    continue
                raise

        if last_exc is not None:
            raise last_exc
        raise ValueError(f"Unsupported object kind for apply: {obj['apiVersion']} {kind}")
