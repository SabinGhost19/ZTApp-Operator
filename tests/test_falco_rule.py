"""Unit tests for the Falco-rule image match.

Regression: digest-pinned images (which the admission webhook *requires*) used to
yield ``repo@sha256`` for ``container.image.repository``, so the per-app Falco rule
never matched and Talon never isolated. ``_image_repository`` fixes that.
"""

from zta_operator.resources import _image_repository, build_falco_rule_configmap

OWNER = {
    "apiVersion": "devsecops.licenta.ro/v1",
    "kind": "ZeroTrustApplication",
    "name": "webhook-relay",
    "uid": "00000000-0000-0000-0000-000000000000",
}
DIGEST = "sha256:" + "a" * 64


def test_image_repository_strips_digest():
    assert _image_repository(f"ghcr.io/sabinghost19/webhook-relay@{DIGEST}") == "ghcr.io/sabinghost19/webhook-relay"


def test_image_repository_strips_tag():
    assert _image_repository("ghcr.io/sabinghost19/webhook-relay:v1.2.3") == "ghcr.io/sabinghost19/webhook-relay"


def test_image_repository_strips_tag_and_digest():
    assert _image_repository(f"ghcr.io/x/y:v1@{DIGEST}") == "ghcr.io/x/y"


def test_image_repository_keeps_registry_host_port():
    assert _image_repository(f"registry.local:5000/team/app@{DIGEST}") == "registry.local:5000/team/app"


def test_image_repository_plain():
    assert _image_repository("ghcr.io/x/y") == "ghcr.io/x/y"


def test_falco_rule_matches_digest_pinned_repository():
    image = f"ghcr.io/sabinghost19/webhook-relay@{DIGEST}"
    cm = build_falco_rule_configmap("webhook-relay", "default", image, ["/tmp"], OWNER)
    rule = cm["data"]["custom_rule.yaml"]
    # The match must be the bare repository — never the malformed "...@sha256".
    assert 'container.image.repository = "ghcr.io/sabinghost19/webhook-relay"' in rule
    assert "@sha256" not in rule
    assert 'fd.name != "/tmp"' in rule
    assert "Unauthorized_Write_default_webhook_relay" in rule
    assert cm["metadata"]["name"] == "falco-rule-webhook-relay"
