import yaml
from kubernetes import client
from kubernetes.client.exceptions import ApiException

from .config import TALON_CONFIGMAP_KEY, TALON_CONFIGMAP_NAME, TALON_NAMESPACE


class TalonConfigError(Exception):
    pass


class TalonInfrastructureMissingError(TalonConfigError):
    """Raised when the Falco/Talon stack is not installed in the cluster.

    Distinct from generic TalonConfigError so the reconcile can degrade
    gracefully (warn + skip + write a structured status field) instead of
    erroring out the whole admission flow. The Pod is already running by
    the time we attempt the upsert — runtime enforcement is an *additional*
    layer, not a precondition.
    """
    def __init__(self, message: str, *, missing: list[str]):
        super().__init__(message)
        # List of component identifiers the operator could not find,
        # e.g. ["falco-talon-rules ConfigMap", "falco-talon namespace"].
        self.missing = list(missing)


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


def _serialize_rules(root: dict | list, mode: str) -> str:
    if mode == "list":
        return yaml.safe_dump(root, sort_keys=False)
    return yaml.safe_dump(root, sort_keys=False)


def _rule_name(namespace: str, app_name: str) -> str:
    return f"zta-{namespace}-{app_name}-isolate"


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


def upsert_talon_rule(core: client.CoreV1Api, app_namespace: str, app_name: str, falco_rule_name: str) -> None:
    try:
        cm = core.read_namespaced_config_map(name=TALON_CONFIGMAP_NAME, namespace=TALON_NAMESPACE)
    except ApiException as exc:
        # 404 = the Falco/Talon stack isn't installed. Treat as a soft,
        # actionable error so the caller can degrade gracefully. Any other
        # API error (5xx, RBAC, etc.) stays as the generic TalonConfigError.
        if int(getattr(exc, "status", 0) or 0) == 404:
            raise TalonInfrastructureMissingError(
                f"Falco/Talon stack is not installed: "
                f"ConfigMap {TALON_NAMESPACE}/{TALON_CONFIGMAP_NAME} not found",
                missing=[f"ConfigMap {TALON_NAMESPACE}/{TALON_CONFIGMAP_NAME}"],
            ) from exc
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


def delete_talon_rule(core: client.CoreV1Api, app_namespace: str, app_name: str) -> None:
    try:
        cm = core.read_namespaced_config_map(name=TALON_CONFIGMAP_NAME, namespace=TALON_NAMESPACE)
    except ApiException as exc:
        if exc.status == 404:
            return
        raise TalonConfigError(
            f"Cannot read Talon ConfigMap {TALON_NAMESPACE}/{TALON_CONFIGMAP_NAME}: {exc.reason}"
        ) from exc

    data = cm.data or {}
    raw_rules = data.get(TALON_CONFIGMAP_KEY, "")
    root, rules, mode = _parse_rules_yaml(raw_rules)

    name = _rule_name(app_namespace, app_name)
    filtered = [item for item in rules if not (isinstance(item, dict) and item.get("name") == name)]
    if len(filtered) == len(rules):
        return

    if isinstance(root, list):
        root[:] = filtered
    else:
        root["rules"] = filtered

    data[TALON_CONFIGMAP_KEY] = _serialize_rules(root=root, mode=mode)
    body = client.V1ConfigMap(metadata=client.V1ObjectMeta(name=TALON_CONFIGMAP_NAME), data=data)
    core.patch_namespaced_config_map(name=TALON_CONFIGMAP_NAME, namespace=TALON_NAMESPACE, body=body)
