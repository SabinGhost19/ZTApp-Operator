"""CEL (Common Expression Language) evaluator for SupplyChainAttestation customRules.

Why CEL: YAML-based policies are static and force every new requirement
through an operator code change. CEL is the same expression language used
by Kubernetes admission and validation (CRD `x-kubernetes-validations`),
giving administrators a non-Turing-complete but expressive interface for
ad-hoc rules without learning Rego/OPA.

Each rule receives a uniform context:
    voucher      — VBBI predicate (build_context, hmac_chain, merkle_tree)
    image        — resolved OCI reference (string)
    zta          — ZeroTrustApplication.spec
    vex          — list of OpenVEX statements parsed for this image
    sbom         — SBOM predicate (or {} if not attested)
    securityScan — security-scan/v1 predicate (gitleaks/checkov/semgrep
                   aggregate: {summary, findings, metadata, gating}), or {}
                   if the securityScanPolicy is not enforced / not attested.
                   e.g. "securityScan.summary.secrets.critical == 0"
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Bound each CEL evaluation so a pathological/expensive customRule cannot hang
# the reconcile loop indefinitely. CEL is non-Turing-complete, so the realistic
# risk is a very large expression rather than an infinite loop; a wall-clock
# timeout plus a length cap is sufficient defense.
_CEL_EVAL_TIMEOUT_SECONDS = float(os.getenv("CEL_EVAL_TIMEOUT_SECONDS", "2"))
_CEL_MAX_EXPRESSION_LEN = int(os.getenv("CEL_MAX_EXPRESSION_LEN", "4096"))

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
    # Per-rule evaluation log surfaced to the UI via
    # status.attestations.celEvaluations. Each entry:
    # { name, expression, action, fired: bool, outcome: str, error?: str }
    evaluations: list[dict[str, Any]] = field(default_factory=list)


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
            result.evaluations.append({
                "name": name, "expression": expression, "action": action,
                "fired": False, "outcome": "", "error": "no expression",
            })
            continue
        if len(expression) > _CEL_MAX_EXPRESSION_LEN:
            msg = f"expression too long ({len(expression)} > {_CEL_MAX_EXPRESSION_LEN} chars)"
            result.errors.append(f"rule {name!r} rejected: {msg}")
            result.evaluations.append({
                "name": name, "expression": expression[:200], "action": action,
                "fired": False, "outcome": "", "error": msg,
            })
            continue
        # Evaluate in a worker thread with a wall-clock timeout. On timeout we
        # do NOT block on shutdown (the celpy eval is not interruptible), so a
        # pathological rule leaks at most one thread instead of wedging reconcile.
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(lambda: env.program(env.compile(expression)).evaluate(cel_context))
            outcome = future.result(timeout=_CEL_EVAL_TIMEOUT_SECONDS)
        except concurrent.futures.TimeoutError:
            result.errors.append(f"rule {name!r} evaluation timed out (> {_CEL_EVAL_TIMEOUT_SECONDS}s)")
            result.evaluations.append({
                "name": name, "expression": expression, "action": action,
                "fired": False, "outcome": "", "error": "timeout",
            })
            executor.shutdown(wait=False)
            continue
        except Exception as exc:
            result.errors.append(f"rule {name!r} evaluation failed: {exc}")
            result.evaluations.append({
                "name": name, "expression": expression, "action": action,
                "fired": False, "outcome": "", "error": str(exc),
            })
            executor.shutdown(wait=False)
            continue
        executor.shutdown(wait=False)

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

        result.evaluations.append({
            "name": name, "expression": expression, "action": action,
            "fired": fired, "outcome": "true" if truthy else "false",
        })

    return result
