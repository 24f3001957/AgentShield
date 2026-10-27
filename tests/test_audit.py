"""Audit chain tests: valid chain, tamper detection, fail-closed behaviour
(acceptance tests 13-15)."""

from __future__ import annotations

import pytest

from agentshield.audit import AuditError, AuditLog

from conftest import public_read, restricted_read


def test_audit_chain_is_valid_after_a_mixed_workload(gateway):
    """13: receipts, decisions, approvals, authorizations and executions chain."""
    gateway.submit(public_read(request_id="req-a1"))
    gateway.submit(restricted_read(request_id="req-a2"))
    external = {
        "request_id": "req-a3",
        "actor_id": "a",
        "session_id": "s",
        "tool_name": "email_tool",
        "operation": "send",
        "arguments": {
            "recipient": "partner@example.com",
            "subject": "hi",
            "body": "hello",
        },
        "destination": "partner@example.com",
        "data_classification": "internal",
    }
    response = gateway.submit(external)
    approval_id = response["approval"]["approval_id"]
    gateway.approvals.decide(approval_id, approver="sec-lead", approve=True)
    gateway.execute_approved(external, approval_id)

    result = gateway.audit.verify(expected_count=gateway.audit.count())
    assert result.valid, result.failures
    assert result.event_count == gateway.audit.count()
    assert result.head == gateway.audit.head()
    assert result.event_count > 8


def test_altered_event_fails_verification(gateway, tmp_path):
    """14: editing a stored payload breaks the recomputed hash."""
    gateway.submit(public_read(request_id="req-t1"))
    copy = gateway.db.backup_to(str(tmp_path / "copy.db"))
    original = AuditLog(copy).verify()
    assert original.valid

    row = copy.query_one(
        "SELECT seq, payload_json FROM audit_events "
        "WHERE event_type = 'policy_decision' LIMIT 1"
    )
    tampered = str(row["payload_json"]).replace(
        '"public_read"', '"internal_recipient"', 1
    )
    copy.execute(
        "UPDATE audit_events SET payload_json = ? WHERE seq = ?",
        (tampered, int(row["seq"])),
    )

    result = AuditLog(copy).verify()
    assert not result.valid
    assert any("hash mismatch" in failure for failure in result.failures)


def test_deleted_event_detected_with_expected_count(gateway, tmp_path):
    """14: dropping an event is caught when a trusted count is supplied."""
    for index in range(3):
        gateway.submit(public_read(request_id=f"req-d{index}"))
    expected = gateway.audit.count()
    copy = gateway.db.backup_to(str(tmp_path / "chain.db"))
    copy.execute("DELETE FROM audit_events WHERE seq = 2")

    result = AuditLog(copy).verify(expected_count=expected)
    assert not result.valid
    assert any("event count mismatch" in f for f in result.failures) or any(
        "sequence gap" in f for f in result.failures
    )


def test_truncated_chain_without_anchor_is_a_documented_limit(gateway, tmp_path):
    """An internally consistent truncated chain verifies: this is the stated
    limitation, and the test pins it so the README claim stays honest."""
    for index in range(3):
        gateway.submit(public_read(request_id=f"req-t{index}"))
    copy = gateway.db.backup_to(str(tmp_path / "trunc.db"))
    last = AuditLog(copy).events()[-1]
    copy.execute("DELETE FROM audit_events WHERE seq = ?", (last["seq"],))

    unanchored = AuditLog(copy).verify()
    anchored = AuditLog(copy).verify(expected_head=gateway.audit.head())
    assert unanchored.valid  # internally consistent ...
    assert not anchored.valid  # ... but detectable with a trusted head


@pytest.mark.parametrize("failing_event", ["tool_call_received", "authorization_issued"])
def test_audit_failure_fails_closed(gateway, db, monkeypatch, failing_event):
    """15: if the audit trail cannot be written, the action does not run."""
    original = gateway.audit.append
    before_outbox = db.count("mock_outbox")
    before_ledger = db.count("execution_ledger")

    def broken_append(event_type, payload):
        if event_type == failing_event:
            raise AuditError("simulated audit outage")
        return original(event_type, payload)

    monkeypatch.setattr(gateway.audit, "append", broken_append)

    response = gateway.submit(public_read(request_id="req-audit-outage"))

    assert response["status"] == "AUDIT_FAILURE"
    assert response["reason_code"] == "audit_unavailable"
    assert response["result"] is None
    assert db.count("mock_outbox") == before_outbox
    assert db.count("execution_ledger") == before_ledger


def test_audit_failure_during_approval_execution_fails_closed(gateway, db, monkeypatch):
    """The approval path is fail-closed too: no consumption, no side effect."""
    request = {
        "request_id": "req-audit-2",
        "actor_id": "a",
        "session_id": "s",
        "tool_name": "email_tool",
        "operation": "send",
        "arguments": {
            "recipient": "partner@example.com",
            "subject": "hi",
            "body": "hello",
        },
        "destination": "partner@example.com",
        "data_classification": "internal",
    }
    response = gateway.submit(request)
    approval_id = response["approval"]["approval_id"]
    gateway.approvals.decide(approval_id, approver="sec-lead", approve=True)

    original = gateway.audit.append
    before_outbox = db.count("mock_outbox")

    def broken_append(event_type, payload):
        if event_type == "authorization_issued":
            raise AuditError("simulated audit outage")
        return original(event_type, payload)

    monkeypatch.setattr(gateway.audit, "append", broken_append)
    outcome = gateway.execute_approved(request, approval_id)

    assert outcome["status"] == "AUDIT_FAILURE"
    assert db.count("mock_outbox") == before_outbox
    assert db.count("execution_ledger") == 0


def test_verification_can_be_recorded_as_an_event(gateway):
    gateway.submit(public_read(request_id="req-v"))
    result = gateway.audit.verify(record=True)
    assert result.valid
    types = list(gateway.audit.event_types())
    assert types[-1] == "audit_verification"
    # Recording must not corrupt the chain it just checked.
    assert gateway.audit.verify().valid
