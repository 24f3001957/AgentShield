"""Policy decisions: the required table, determinism, and fail-closed defaults."""

from __future__ import annotations

import pytest

from agentshield.models import Decision, PolicyOutcome, POLICY_VERSION
from agentshield.policy import (
    HARD_DENY_REASON_CODES,
    PolicyConfig,
    PolicyEngine,
    is_hard_denial,
)
from agentshield.validator import validate

from conftest import (
    external_send,
    internal_send,
    public_read,
    restricted_read,
    restricted_transfer,
)


def decide(raw, engine: PolicyEngine | None = None) -> PolicyOutcome:
    """Run the same validate -> evaluate path the gateway uses."""
    engine = engine or PolicyEngine()
    validation = validate(raw)
    if validation.ok:
        return engine.evaluate(validation.request, validation)
    return engine.evaluate(None, validation)


REQUIRED_BEHAVIOURS = [
    ("public read", public_read, Decision.ALLOW, "public_read"),
    ("restricted read", restricted_read, Decision.DENY, "restricted_resource"),
    (
        "internal send",
        internal_send,
        Decision.ALLOW,
        "internal_recipient",
    ),
    (
        "external send",
        external_send,
        Decision.APPROVAL,
        "external_send",
    ),
    (
        "restricted transfer to unapproved destination",
        restricted_transfer,
        Decision.DENY,
        "restricted_data_transfer",
    ),
    (
        "unknown tool",
        lambda **kw: {
            "request_id": "req-unknown",
            "actor_id": "a",
            "session_id": "s",
            "tool_name": "shell_tool",
            "operation": "exec",
            "arguments": {"command": "ls"},
        },
        Decision.DENY,
        "unknown_tool",
    ),
    (
        "malformed arguments",
        lambda **kw: {
            "request_id": "req-malformed",
            "actor_id": "a",
            "session_id": "s",
            "tool_name": "email_tool",
            "operation": "send",
            "arguments": {"subject": "no recipient"},
        },
        Decision.DENY,
        "invalid_request",
    ),
]


@pytest.mark.parametrize(
    "label, builder, expected_decision, expected_reason",
    REQUIRED_BEHAVIOURS,
    ids=[row[0] for row in REQUIRED_BEHAVIOURS],
)
def test_required_policy_behaviours(label, builder, expected_decision, expected_reason):
    outcome = decide(builder())
    assert outcome.decision is expected_decision, f"{label}: {outcome}"
    assert outcome.reason_code == expected_reason, f"{label}: {outcome}"
    assert outcome.policy_version == POLICY_VERSION
    assert is_hard_denial(outcome) is (expected_decision is Decision.DENY)


def test_decisions_are_deterministic():
    engine = PolicyEngine()
    first = decide(external_send(), engine)
    second = decide(external_send(), engine)
    assert first.model_dump() == second.model_dump()


def test_restricted_external_send_is_deny_not_approval():
    """One action must never be ambiguous between DENY and APPROVAL."""
    raw = external_send(data_classification="restricted")
    outcome = decide(raw)
    assert outcome.decision is Decision.DENY
    assert outcome.reason_code == "restricted_data_transfer"
    assert is_hard_denial(outcome)


def test_external_send_approval_is_configurable():
    engine = PolicyEngine(
        PolicyConfig(require_approval_for_external_send=False)
    )
    outcome = decide(external_send(), engine)
    assert outcome.decision is Decision.ALLOW


def test_default_deny_for_unmatched_action():
    """An action no rule matches is denied, never silently allowed."""
    raw = public_read()
    raw["arguments"] = {"path": "/var/lib/app/data.db"}
    raw["resource"] = None
    outcome = decide(raw)
    assert outcome.decision is Decision.DENY
    assert outcome.reason_code == "resource_out_of_scope"
    assert is_hard_denial(outcome)


def test_policy_version_mismatch_is_denied():
    raw = public_read(policy_version="1999-01-01-v0")
    outcome = decide(raw)
    assert outcome.decision is Decision.DENY
    assert outcome.reason_code == "policy_version_mismatch"
    assert is_hard_denial(outcome)


def test_approval_reason_codes_are_never_hard_denials():
    for reason in ("external_send", "restricted_transfer", "approved_destination"):
        assert reason not in HARD_DENY_REASON_CODES
    assert is_hard_denial(
        PolicyOutcome(decision=Decision.DENY, reason_code="restricted_resource")
    )
    assert not is_hard_denial(
        PolicyOutcome(decision=Decision.APPROVAL, reason_code="external_send")
    )
    assert not is_hard_denial(
        PolicyOutcome(decision=Decision.ALLOW, reason_code="public_read")
    )


def test_every_hard_denial_is_reachable_as_a_denial():
    """Spot-check the hard-deny codes the required table exercises."""
    for raw, reason in [
        (restricted_read(), "restricted_resource"),
        (restricted_transfer(), "restricted_data_transfer"),
        (
            {
                "request_id": "x",
                "actor_id": "a",
                "session_id": "s",
                "tool_name": "shell_tool",
                "operation": "exec",
                "arguments": {},
            },
            "unknown_tool",
        ),
    ]:
        outcome = decide(raw)
        assert outcome.decision is Decision.DENY
        assert outcome.reason_code == reason
        assert is_hard_denial(outcome)


def test_traversal_path_is_rejected_before_policy():
    outcome = decide(
        public_read(
            arguments={"path": "/public/../../etc/passwd"},
            resource="/public/../../etc/passwd",
        )
    )
    assert outcome.decision is Decision.DENY
    assert outcome.reason_code == "invalid_request"
