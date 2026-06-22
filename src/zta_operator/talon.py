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


def _serialize_rules(root: dict | list) -> str:
    # Both the list-root and dict-root (`{rules: [...]}`) shapes serialize the
    # same way; the in-place rules list is already linked to `root`.
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


# (connect, read) timeouts for every K8s call, so a stalled API server can't
# block a reconcile forever (the operator's async timeout doesn't cover the
# synchronous kubernetes client I/O).
_K8S_TIMEOUT = (3.05, 10)
# Retries when a concurrent writer bumps the ConfigMap resourceVersion (HTTP 409).
_MAX_CONFLICT_RETRIES = 4


def _mutate_rules(core: client.CoreV1Api, mutate) -> None:
    """Optimistic-concurrency read-modify-write on the Talon rules ConfigMap.

    `mutate(rules)` edits the rules list IN PLACE and returns True iff it changed
    anything (False → no write). The write is a `replace` carrying the read
    resourceVersion, so a concurrent ZTA reconcile that wrote in between yields a
    409; we then re-read and retry. This removes the lost-update race two
    simultaneous reconciles previously had with a blind patch.
    """
    for attempt in range(_MAX_CONFLICT_RETRIES):
        try:
            cm = core.read_namespaced_config_map(
                name=TALON_CONFIGMAP_NAME, namespace=TALON_NAMESPACE, _request_timeout=_K8S_TIMEOUT
            )
        except ApiException as exc:
            status = int(getattr(exc, "status", 0) or 0)
            # 404 = stack not installed → soft, actionable error so the caller
            # can degrade gracefully. Anything else stays a generic config error.
            if status == 404:
                raise TalonInfrastructureMissingError(
                    f"Falco/Talon stack is not installed: "
                    f"ConfigMap {TALON_NAMESPACE}/{TALON_CONFIGMAP_NAME} not found",
                    missing=[f"ConfigMap {TALON_NAMESPACE}/{TALON_CONFIGMAP_NAME}"],
                ) from exc
            raise TalonConfigError(
                f"Cannot read Talon ConfigMap {TALON_NAMESPACE}/{TALON_CONFIGMAP_NAME}: {exc.reason}"
            ) from exc

        data = cm.data or {}
        root, rules, _mode = _parse_rules_yaml(data.get(TALON_CONFIGMAP_KEY, ""))
        if not mutate(rules):
            return  # idempotent no-op
        data[TALON_CONFIGMAP_KEY] = _serialize_rules(root)

        body = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(
                name=TALON_CONFIGMAP_NAME,
                namespace=TALON_NAMESPACE,
                resource_version=cm.metadata.resource_version,  # optimistic concurrency
            ),
            data=data,
        )
        try:
            core.replace_namespaced_config_map(
                name=TALON_CONFIGMAP_NAME, namespace=TALON_NAMESPACE, body=body,
                _request_timeout=_K8S_TIMEOUT,
            )
            return
        except ApiException as exc:
            status = int(getattr(exc, "status", 0) or 0)
            if status == 409 and attempt < _MAX_CONFLICT_RETRIES - 1:
                continue  # concurrent write — re-read and retry
            raise TalonConfigError(
                f"Cannot update Talon ConfigMap {TALON_NAMESPACE}/{TALON_CONFIGMAP_NAME}: {exc.reason}"
            ) from exc

    raise TalonConfigError(
        f"Exhausted {_MAX_CONFLICT_RETRIES} conflict retries updating "
        f"{TALON_NAMESPACE}/{TALON_CONFIGMAP_NAME}"
    )


def upsert_talon_rule(core: client.CoreV1Api, app_namespace: str, app_name: str, falco_rule_name: str) -> None:
    name = _rule_name(app_namespace, app_name)
    rule = _build_rule(namespace=app_namespace, app_name=app_name, falco_rule_name=falco_rule_name)

    def mutate(rules: list) -> bool:
        index = next(
            (i for i, item in enumerate(rules) if isinstance(item, dict) and item.get("name") == name),
            None,
        )
        if index is None:
            rules.append(rule)
            return True
        if rules[index] == rule:
            return False  # already up to date
        rules[index] = rule
        return True

    _mutate_rules(core, mutate)


def delete_talon_rule(core: client.CoreV1Api, app_namespace: str, app_name: str) -> None:
    name = _rule_name(app_namespace, app_name)

    def mutate(rules: list) -> bool:
        filtered = [item for item in rules if not (isinstance(item, dict) and item.get("name") == name)]
        if len(filtered) == len(rules):
            return False  # not present
        rules[:] = filtered
        return True

    try:
        _mutate_rules(core, mutate)
    except TalonInfrastructureMissingError:
        return  # stack already gone — nothing to clean up
