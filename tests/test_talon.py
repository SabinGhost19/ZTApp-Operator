"""Unit tests for the Talon rules read-modify-write (talon.py).

Covers the parser/builder, upsert/delete idempotency, the 404 →
TalonInfrastructureMissingError mapping, and the optimistic-concurrency
409-retry path added to fix the lost-update race.
"""

import pytest
import yaml
from kubernetes.client.exceptions import ApiException

from zta_operator import talon
from zta_operator.config import TALON_CONFIGMAP_KEY
from zta_operator.talon import (
    TalonInfrastructureMissingError,
    _build_rule,
    _parse_rules_yaml,
    _rule_name,
    delete_talon_rule,
    upsert_talon_rule,
)


class _Meta:
    def __init__(self, rv: str):
        self.resource_version = rv


class _CM:
    def __init__(self, data: dict, rv: str):
        self.data = data
        self.metadata = _Meta(rv)


class FakeCore:
    """Minimal in-memory stand-in for CoreV1Api with optimistic concurrency."""

    def __init__(self, initial=None, missing=False, conflict_times=0):
        self._data = dict(initial or {})
        self._rv = 1
        self._missing = missing
        self._conflict_times = conflict_times
        self.reads = 0
        self.replaces = 0

    def read_namespaced_config_map(self, name, namespace, _request_timeout=None):
        self.reads += 1
        if self._missing:
            raise ApiException(status=404, reason="Not Found")
        return _CM(dict(self._data), str(self._rv))

    def replace_namespaced_config_map(self, name, namespace, body, _request_timeout=None):
        self.replaces += 1
        if self._conflict_times > 0:
            self._conflict_times -= 1
            self._rv += 1  # a concurrent writer moved the resourceVersion
            raise ApiException(status=409, reason="Conflict")
        if body.metadata.resource_version != str(self._rv):
            raise ApiException(status=409, reason="Conflict")
        self._data = dict(body.data)
        self._rv += 1

    def rules(self):
        return yaml.safe_load(self._data.get(TALON_CONFIGMAP_KEY, "")) or []


def test_parse_rules_yaml_shapes():
    assert _parse_rules_yaml("")[1] == []
    root, rules, mode = _parse_rules_yaml("- name: a\n")
    assert mode == "list" and rules == [{"name": "a"}] and root is rules
    root, rules, mode = _parse_rules_yaml("rules:\n  - name: a\n")
    assert mode == "dict" and rules == [{"name": "a"}] and root["rules"] is rules
    # dict root without a rules key gets one created
    root, rules, mode = _parse_rules_yaml("foo: bar\n")
    assert mode == "dict" and rules == [] and root["rules"] is rules


def test_build_rule_shape():
    r = _build_rule(namespace="default", app_name="web", falco_rule_name="Unauthorized_Write_default_web")
    assert r["name"] == "zta-default-web-isolate" == _rule_name("default", "web")
    assert r["match"]["rules"] == ["Unauthorized_Write_default_web"]
    assert r["actionner"] == "kubernetes:networkpolicy"
    assert r["parameters"] == {"namespace": "default", "pod_selector": "app=web", "type": "isolate"}


def test_upsert_adds_rule():
    core = FakeCore()
    upsert_talon_rule(core, "default", "web", "Unauthorized_Write_default_web")
    rules = core.rules()
    assert [r["name"] for r in rules] == ["zta-default-web-isolate"]
    assert core.replaces == 1


def test_upsert_is_idempotent():
    core = FakeCore()
    upsert_talon_rule(core, "default", "web", "Unauthorized_Write_default_web")
    upsert_talon_rule(core, "default", "web", "Unauthorized_Write_default_web")
    assert len(core.rules()) == 1
    assert core.replaces == 1  # second upsert is a no-op (no write)


def test_upsert_two_apps_coexist():
    core = FakeCore()
    upsert_talon_rule(core, "default", "web", "Unauthorized_Write_default_web")
    upsert_talon_rule(core, "default", "api", "Unauthorized_Write_default_api")
    assert sorted(r["name"] for r in core.rules()) == ["zta-default-api-isolate", "zta-default-web-isolate"]


def test_delete_removes_rule():
    core = FakeCore()
    upsert_talon_rule(core, "default", "web", "Unauthorized_Write_default_web")
    delete_talon_rule(core, "default", "web")
    assert core.rules() == []


def test_delete_absent_is_noop():
    core = FakeCore()
    delete_talon_rule(core, "default", "web")  # nothing to remove
    assert core.replaces == 0


def test_upsert_missing_stack_raises():
    core = FakeCore(missing=True)
    with pytest.raises(TalonInfrastructureMissingError):
        upsert_talon_rule(core, "default", "web", "Unauthorized_Write_default_web")


def test_delete_missing_stack_is_noop():
    core = FakeCore(missing=True)
    delete_talon_rule(core, "default", "web")  # must not raise


def test_upsert_retries_on_conflict():
    core = FakeCore(conflict_times=1)  # first replace → 409, then succeeds
    upsert_talon_rule(core, "default", "web", "Unauthorized_Write_default_web")
    assert core.reads == 2 and core.replaces == 2
    assert [r["name"] for r in core.rules()] == ["zta-default-web-isolate"]


def test_timeout_is_passed():
    captured = {}
    core = FakeCore()
    orig = core.read_namespaced_config_map

    def spy(name, namespace, _request_timeout=None):
        captured["timeout"] = _request_timeout
        return orig(name, namespace, _request_timeout=_request_timeout)

    core.read_namespaced_config_map = spy
    upsert_talon_rule(core, "default", "web", "Unauthorized_Write_default_web")
    assert captured["timeout"] == talon._K8S_TIMEOUT
