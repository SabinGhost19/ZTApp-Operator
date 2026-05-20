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

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

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


@dataclass
class CelEvalResult:
    deny: list[str] = field(default_factory=list)
    alert: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _evaluate_rule(env: Any, rule: dict[str, Any], context: dict[str, Any]) -> tuple[str | None, bool]:
    name = str(rule.get("name", "<unnamed>")).strip()
    expression = str(rule.get("expression", "")).strip()
    action = str(rule.get("action", "Deny")).strip()
    if not expression:
        return name, False

    program = env.program(env.compile(expression))
    result = program.evaluate(context)
    truthy = bool(result)
    return action, truthy


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
            continue
        try:
            program = env.program(env.compile(expression))
            outcome = program.evaluate(cel_context)
        except Exception as exc:
            result.errors.append(f"rule {name!r} evaluation failed: {exc}")
            continue

        truthy = bool(outcome)
        # Semantics:
        #   Deny rules fire when expression is True (it describes a violation).
        #   Allow rules fire when expression is False (a required condition failed).
        #   Alert rules surface as warnings without blocking.
        if action == "Deny" and truthy:
            result.deny.append(f"{name}: {expression}")
        elif action == "Allow" and not truthy:
            result.deny.append(f"{name} (required condition false): {expression}")
        elif action == "Alert" and truthy:
            result.alert.append(f"{name}: {expression}")
        elif action == "Allow" and truthy:
            result.allow.append(name)

    return result
