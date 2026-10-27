"""Gateway acceptance tests: side effects only ever happen through the
controlled executor, and denials leave no trace in the mock stores.

Tests inspect the execution ledger and mock stores - never a textual claim.
"""

from __future__ import annotations

import pytest

from agentshield.authorization import Authorization
from agentshield.executor import ExecutionDenied
from agentshield.models import Decision, action_fingerprint
from agentshield.validator import validate

from conftest import public_read, restricted_read, restricted_transfer


def test_public_read_executes_and_returns_content(gateway, db):
    response = gateway.submit(public_read())

    assert response["status"] == "EXECUTED"
    assert response["decision"] == Decision.ALLOW.value
    assert response["reason_code"] == "public_read"
    assert "main auditorium" in response["result"]["output"]["content"]

    ledger = db.query_one(
        "SELECT * FROM execution_ledger WHERE request_id = ?", ("req-public",)
    )
    assert ledger is not None
    assert ledger["outcome"] == "EXECUTED"


def test_restricted_read_is_denied_without_contents(gateway, db):
    before = db.count("execution_ledger")
    response = gateway.submit(restricted_read())

    assert response["status"] == "DENIED"
    assert response["decision"] == Decision.DENY.value
    assert response["reason_code"] == "restricted_resource"
    assert response["result"] is None
    assert "CONFIDENTIAL" not in str(response)
    assert db.count("execution_ledger") == before
    assert db.query_one(
        "SELECT * FROM execution_ledger WHERE request_id = ?", ("req-secret",)
    ) is None
    status = gateway.get_status("req-secret")
    assert status["state"] == "DENIED"


def test_prohibited_restricted_transfer_has_no_side_effect(gateway, db):
    before = db.count("mock_transfers")
    response = gateway.submit(restricted_transfer())

    assert response["status"] == "DENIED"
    assert response["reason_code"] == "restricted_data_transfer"
    assert db.count("mock_transfers") == before
    assert db.query_one(
        "SELECT * FROM mock_transfers WHERE destination = ?",
        ("cloud.external.example",),
    ) is None


def test_unknown_tool_is_rejected(gateway, db):
    response = gateway.submit(
        {
            "request_id": "req-shell",
            "actor_id": "a",
            "session_id": "s",
            "tool_name": "shell_tool",
            "operation": "exec",
            "arguments": {"command": "rm -rf /"},
        }
    )
    assert response["status"] == "DENIED"
    assert response["reason_code"] == "unknown_tool"
    assert db.count("execution_ledger") == 0


def test_malformed_arguments_are_rejected(gateway, db):
    response = gateway.submit(
        {
            "request_id": "req-bad",
            "actor_id": "a",
            "session_id": "s",
            "tool_name": "email_tool",
            "operation": "send",
            "arguments": {"subject": "no recipient, no body"},
        }
    )
    assert response["status"] == "DENIED"
    assert response["reason_code"] == "invalid_request"
    assert db.count("mock_outbox") == 0


def test_client_cannot_smuggle_approval_flag(make_request, gateway):
    """``approved: true`` is not a schema field, so it cannot change a verdict."""
    raw = restricted_read()
    raw["approved"] = True
    raw["approver"] = "attacker"
    response = gateway.submit(raw)
    assert response["status"] == "DENIED"
    assert response["reason_code"] == "invalid_request"


def test_executor_rejects_fabricated_authorization(gateway, db):
    """Even with a policy ALLOW, a forged token never reaches the tool."""
    request_payload = public_read(request_id="req-forged")
    validation = validate(request_payload)
    assert validation.ok
    request = validation.request
    fingerprint = action_fingerprint(request)

    forged = Authorization(
        authorization_id="az_forged",
        request_id=request.request_id,
        fingerprint=fingerprint,
        kind="ALLOW",
        issued_at=0.0,
        expires_at=9_999_999_999.0,
        token="0" * 64,
    )
    before = db.count("mock_outbox") + db.count("mock_transfers")

    with pytest.raises(ExecutionDenied) as excinfo:
        gateway.executor.execute(request, forged, fingerprint)

    assert excinfo.value.reason_code in {
        "unknown_authorization",
        "invalid_authorization",
    }
    after = db.count("mock_outbox") + db.count("mock_transfers")
    assert after == before
    assert db.count("execution_ledger") == 0


def test_authorization_event_precedes_execution_event(gateway, db):
    gateway.submit(public_read(request_id="req-order"))
    events = gateway.audit.events()
    issued = next(e["seq"] for e in events if e["event_type"] == "authorization_issued")
    started = next(e["seq"] for e in events if e["event_type"] == "execution_started")
    completed = next(
        e["seq"] for e in events if e["event_type"] == "execution_completed"
    )
    assert issued < started < completed


def test_audit_does_not_record_message_contents(gateway):
    response = gateway.submit(
        {
            "request_id": "req-secret-body",
            "actor_id": "a",
            "session_id": "s",
            "tool_name": "email_tool",
            "operation": "send",
            "arguments": {
                "recipient": "alice@corp.example",
                "subject": "hi",
                "body": "VERY-SENSITIVE-PAYLOAD",
            },
            "destination": "alice@corp.example",
            "data_classification": "internal",
        }
    )
    assert response["status"] == "EXECUTED"
    serialised = str(gateway.audit.events())
    assert "VERY-SENSITIVE-PAYLOAD" not in serialised
    # The stored tool-call payload redacts the body too.
    row = gateway.db.query_one(
        "SELECT payload_json FROM tool_calls WHERE request_id = ?",
        ("req-secret-body",),
    )
    assert "VERY-SENSITIVE-PAYLOAD" not in str(row["payload_json"])
    assert "[redacted]" in str(row["payload_json"])


def test_denied_requests_never_create_authorizations(gateway, db):
    gateway.submit(restricted_read(request_id="req-noauth"))
    assert db.count("authorizations") == 0
