"""Approval lifecycle tests: pending, valid, mutated, expired, replayed,
concurrent and hard-deny cases (acceptance tests 6-12)."""

from __future__ import annotations

import threading

import pytest

from agentshield.approval import ApprovalError

from conftest import external_send, public_read, restricted_read


def _submit_and_approve(gateway, request):
    """Submit an approval-requiring call and approve it. Returns the approval id."""
    response = gateway.submit(request)
    assert response["status"] == "AWAITING_APPROVAL", response
    approval_id = response["approval"]["approval_id"]
    updated = gateway.approvals.decide(approval_id, approver="sec-lead", approve=True)
    assert updated.state == "APPROVED"
    return approval_id


def test_pending_approval_causes_no_execution(gateway, db):
    """6: a pending approval executes nothing."""
    request = external_send()
    response = gateway.submit(request)

    assert response["status"] == "AWAITING_APPROVAL"
    assert response["decision"] == "APPROVAL"
    assert response["result"] is None
    assert db.count("mock_outbox") == 0
    assert db.count("execution_ledger") == 0

    # Trying to execute before an approval decision also does nothing.
    early = gateway.execute_approved(request, response["approval"]["approval_id"])
    assert early["status"] == "NO_EXECUTION"
    assert early["reason_code"] == "approval_not_approved"
    assert db.count("mock_outbox") == 0


def test_valid_unchanged_approval_executes_once(gateway, db):
    """7: an unchanged, approved action runs exactly once."""
    request = external_send()
    approval_id = _submit_and_approve(gateway, request)
    before = db.count("mock_outbox")

    response = gateway.execute_approved(request, approval_id)

    assert response["status"] == "EXECUTED"
    assert response["decision"] == "APPROVAL"
    assert response["reason_code"] == "external_send"
    assert db.count("mock_outbox") == before + 1
    status = gateway.get_status(request["request_id"])
    assert status["approval"]["state"] == "EXECUTED"
    assert status["execution"]["outcome"] == "EXECUTED"


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            lambda r: {**r, "arguments": {**r["arguments"], "recipient": "evil@external.example"},
                       "destination": "evil@external.example"},
            id="changed-recipient",
        ),
        pytest.param(
            lambda r: {**r, "arguments": {**r["arguments"], "subject": "rescheduled"}},
            id="changed-subject",
        ),
        pytest.param(
            lambda r: {**r, "arguments": {**r["arguments"], "body": "different body"}},
            id="changed-body",
        ),
        pytest.param(
            lambda r: {**r, "session_id": "sess-attacker"},
            id="changed-session",
        ),
    ],
)
def test_mutation_invalidates_approval(gateway, db, mutation):
    """8: altering an authorization-relevant field invalidates the approval."""
    request = external_send()
    approval_id = _submit_and_approve(gateway, request)
    mutated = mutation(request)
    before = db.count("mock_outbox")

    response = gateway.execute_approved(mutated, approval_id)

    assert response["status"] == "NO_EXECUTION"
    assert response["reason_code"] == "approval_mutation"
    assert db.count("mock_outbox") == before


def test_changed_resource_invalidates_approval(gateway, db):
    """8: a changed resource also invalidates (send -> different call entirely)."""
    request = external_send()
    approval_id = _submit_and_approve(gateway, request)
    swapped = {**request, "tool_name": "file_tool", "operation": "read",
               "arguments": {"path": "/secret/acquisition.txt"},
               "resource": "/secret/acquisition.txt", "data_classification": "restricted"}
    response = gateway.execute_approved(swapped, approval_id)
    assert response["status"] == "NO_EXECUTION"
    # A hard denial is reported before the approval is even considered.
    assert response["reason_code"] == "restricted_resource"
    assert db.count("mock_outbox") == 0


def test_expired_approval_is_rejected(gateway, db, clock):
    """9: approvals expire; the execution path and the decision path both refuse."""
    request = external_send()
    approval_id = _submit_and_approve(gateway, request)

    clock.advance(301)

    response = gateway.execute_approved(request, approval_id)
    assert response["status"] == "NO_EXECUTION"
    assert response["reason_code"] == "approval_expired"
    assert db.count("mock_outbox") == 0
    assert gateway.approvals.get(approval_id).state == "EXPIRED"

    # Deciding an already-expired pending approval also fails closed.
    pending = gateway.submit(external_send(request_id="req-pending-2"))
    second_id = pending["approval"]["approval_id"]
    clock.advance(301)
    with pytest.raises(ApprovalError) as excinfo:
        gateway.approvals.decide(second_id, approver="sec-lead", approve=True)
    assert excinfo.value.reason_code == "approval_expired"


def test_consumed_approval_cannot_execute_twice(gateway, db):
    """10: replay of a consumed approval is refused and adds no side effect."""
    request = external_send()
    approval_id = _submit_and_approve(gateway, request)

    first = gateway.execute_approved(request, approval_id)
    second = gateway.execute_approved(request, approval_id)

    assert first["status"] == "EXECUTED"
    assert second["status"] == "NO_EXECUTION"
    assert second["reason_code"] == "approval_already_consumed"
    assert db.count("mock_outbox") == 1
    assert db.count(
        "execution_ledger", "request_id = ?", (request["request_id"],)
    ) == 1


def test_hard_deny_cannot_be_overridden_by_approval(gateway, db):
    """11: a restricted read is never approvable and never executes."""
    denied = gateway.submit(restricted_read(request_id="req-hard-deny"))
    assert denied["status"] == "DENIED"
    assert denied["approval"] is None
    # No approval record exists, so there is nothing an attacker could approve.
    assert gateway.approvals.get("apr_fabricated") is None

    # Even presenting an unrelated, legitimately approved id does not help:
    # policy is re-evaluated first and a hard denial stops execution.
    benign = external_send(request_id="req-benign")
    approval_id = _submit_and_approve(gateway, benign)
    forged = {**restricted_read(), "request_id": "req-benign"}
    response = gateway.execute_approved(forged, approval_id)

    assert response["status"] == "NO_EXECUTION"
    assert response["decision"] == "DENY"
    assert response["reason_code"] == "restricted_resource"
    assert "approval cannot override" in (response["detail"] or "")
    assert db.count("mock_outbox") == 0


def test_concurrent_consumption_wins_once(gateway, db):
    """12: two racing executions of one approval - exactly one runs."""
    request = external_send()
    approval_id = _submit_and_approve(gateway, request)

    results = []
    barrier = threading.Barrier(2)

    def attempt():
        barrier.wait()
        results.append(gateway.execute_approved(request, approval_id))

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    statuses = sorted(r["status"] for r in results)
    assert statuses == ["EXECUTED", "NO_EXECUTION"], results
    assert db.count("mock_outbox") == 1
    assert (
        db.count("execution_ledger", "request_id = ?", (request["request_id"],)) == 1
    )


def test_approval_records_the_exact_action_binding(gateway):
    """The approval binds to a canonical fingerprint of the exact action."""
    request = external_send()
    response = gateway.submit(request)
    approval = gateway.approvals.get(response["approval"]["approval_id"])
    binding = approval.binding

    for key in (
        "actor_id",
        "session_id",
        "tool_name",
        "operation",
        "arguments",
        "resource",
        "destination",
        "data_classification",
        "policy_version",
        "canonicalization_version",
    ):
        assert key in binding, key
    assert len(approval.fingerprint) == 64
    assert approval.state == "PENDING_APPROVAL"


def test_pending_approvals_are_listed(gateway):
    gateway.submit(external_send(request_id="req-list-1"))
    pending = gateway.approvals.list("PENDING_APPROVAL")
    assert len(pending) == 1
    assert pending[0].state == "PENDING_APPROVAL"
    # Rejected approvals are explicit terminal states.
    gateway.approvals.decide(pending[0].approval_id, approver="sec-lead", approve=False)
    assert gateway.approvals.get(pending[0].approval_id).state == "REJECTED"
    assert gateway.approvals.list("PENDING_APPROVAL") == []
