"""API surface tests: predictable responses, no direct-execution escape hatch."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agentshield.api import create_app

from conftest import external_send, public_read, restricted_read


@pytest.fixture
def client(tmp_path):
    app = create_app(db_path=str(tmp_path / "api.db"))
    with TestClient(app) as test_client:
        yield test_client


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "file_tool" in body["tools"]
    assert body["policy_version"]


def test_submit_allowed_call(client):
    response = client.post("/tool-calls", json=public_read())
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "EXECUTED"
    assert body["decision"] == "ALLOW"
    assert "main auditorium" in body["result"]["output"]["content"]


def test_submit_denied_call(client):
    response = client.post("/tool-calls", json=restricted_read())
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "DENIED"
    assert body["reason_code"] == "restricted_resource"
    assert body["result"] is None


def test_status_endpoint_and_404(client):
    client.post("/tool-calls", json=public_read(request_id="req-status"))
    response = client.get("/tool-calls/req-status")
    assert response.status_code == 200
    assert response.json()["state"] == "EXECUTED"
    assert response.json()["execution"]["outcome"] == "EXECUTED"

    missing = client.get("/tool-calls/does-not-exist")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "not_found"


def test_approval_flow_over_http(client):
    request = external_send(request_id="req-http-approval")
    submitted = client.post("/tool-calls", json=request).json()
    assert submitted["status"] == "AWAITING_APPROVAL"
    approval_id = submitted["approval"]["approval_id"]

    pending = client.get("/approvals", params={"state": "PENDING_APPROVAL"}).json()
    assert [a["approval_id"] for a in pending["approvals"]] == [approval_id]
    assert pending["approvals"][0]["executed_at"] is None if "executed_at" in pending["approvals"][0] else True

    decided = client.post(
        f"/approvals/{approval_id}/decision",
        json={"approver": "sec-lead", "decision": "APPROVE"},
    )
    assert decided.status_code == 200
    assert decided.json()["approval"]["state"] == "APPROVED"
    # Approving never executes anything by itself.
    assert decided.json()["executed"] is False

    executed = client.post(
        f"/tool-calls/{request['request_id']}/execute",
        json={"approval_id": approval_id, "request": request},
    )
    assert executed.status_code == 200
    assert executed.json()["status"] == "EXECUTED"

    replay = client.post(
        f"/tool-calls/{request['request_id']}/execute",
        json={"approval_id": approval_id, "request": request},
    )
    assert replay.json()["status"] == "NO_EXECUTION"
    assert replay.status_code == 409
    assert replay.json()["reason_code"] == "approval_already_consumed"


def test_execute_with_unknown_approval_is_404(client):
    request = public_read(request_id="req-unknown-approval")
    client.post("/tool-calls", json=request)
    response = client.post(
        f"/tool-calls/{request['request_id']}/execute",
        json={"approval_id": "apr_nope", "request": request},
    )
    assert response.status_code == 404
    assert response.json()["reason_code"] == "approval_not_found"


def test_cannot_smuggle_approval_field(client):
    raw = restricted_read()
    raw["approved"] = True
    response = client.post("/tool-calls", json=raw)
    assert response.status_code == 200
    assert response.json()["status"] == "DENIED"
    assert response.json()["reason_code"] == "invalid_request"


def test_non_object_body_is_rejected(client):
    response = client.post("/tool-calls", json=["not", "an", "object"])
    assert response.status_code == 422


def test_no_direct_execution_route_exists(client):
    """There is no endpoint that runs a tool without the gateway."""
    for path in ("/tools/execute", "/execute", "/tool-calls/execute", "/admin/execute"):
        response = client.post(path, json={"tool_name": "email_tool"})
        # 404 = no such route; 405 = path exists for another method only.
        # Neither runs anything: no tool-call record and no ledger row appears.
        assert response.status_code in {404, 405}
    assert client.get("/tool-calls").json()["tool_calls"] == []


def test_audit_endpoints(client):
    client.post("/tool-calls", json=public_read(request_id="req-audit"))

    events = client.get("/audit/events").json()
    assert events["count"] >= 4
    assert {e["event_type"] for e in events["events"]} >= {
        "tool_call_received",
        "policy_decision",
        "authorization_issued",
        "execution_completed",
    }

    verified = client.get("/audit/verify").json()
    assert verified["valid"] is True
    assert verified["event_count"] == events["count"]
    assert "trust_anchor" in verified

    anchored = client.get(
        "/audit/verify", params={"expected_count": events["count"]}
    ).json()
    assert anchored["valid"] is True

    wrong = client.get("/audit/verify", params={"expected_count": events["count"] + 5})
    assert wrong.json()["valid"] is False


def test_evaluation_endpoints(client):
    run = client.post("/evaluation/run")
    assert run.status_code == 200
    body = run.json()
    assert body["fixture_count"] == 11
    assert body["metrics"]["attack_success_rate"]["firewall_on"]["numerator"] == 0
    assert body["metrics"]["attack_success_rate"]["firewall_on"]["denominator"] == 6

    results = client.get("/evaluation/results").json()
    assert results["run_id"] == body["run_id"]

    exported = client.get("/evaluation/export")
    assert exported.status_code == 200
    assert "attachment" in exported.headers["content-disposition"]
    assert exported.json()["run_id"] == body["run_id"]


def test_evaluation_results_404_before_any_run(tmp_path):
    app = create_app(db_path=str(tmp_path / "fresh.db"))
    with TestClient(app) as fresh_client:
        response = fresh_client.get("/evaluation/results")
        assert response.status_code == 404
