"""Secret-read simulation: real gateway path, real denial, no fabricated result."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from agentshield.api import create_app


@pytest.fixture
def client(tmp_path) -> TestClient:
    return TestClient(create_app(str(tmp_path / "sim.db")))


def test_secret_read_runs_through_the_gateway(client: TestClient):
    response = client.post("/simulations/secret-read")
    assert response.status_code == 200
    record = response.json()

    assert record["scenario"] == "secret-read"
    assert record["scenario_label"] == "Secret-read exfiltration"
    assert len(record["steps"]) == 2

    read, exfil = record["steps"]
    assert read["response"]["status"] == "EXECUTED"
    assert read["observed"]["classification"] == "confidential"
    assert len(read["observed"]["provenance"]) == 1
    serialized = json.dumps(read["response"]["result"]["output"])
    assert "Meridian Logistics" not in serialized
    assert "omitted from simulation output" in read["response"]["result"]["output"]["content"]

    # The attack is decided by policy, carrying the provenance it just minted.
    assert exfil["response"]["decision"] == "DENY"
    assert exfil["response"]["reason_code"] == "confidential_data_transfer"
    assert exfil["request"]["provenance"] == read["observed"]["provenance"]

    result = record["result"]
    assert result["executed"] is False
    assert result["side_effect"] is False
    assert result["outbox_before"] == result["outbox_after"] == 0
    assert result["execution_rows"] == 0
    assert result["blocked_at"] == "policy_engine"


def test_simulation_events_are_real_audit_events(client: TestClient):
    record = client.post("/simulations/secret-read").json()
    exfil_events = record["steps"][1]["audit_events"]
    types = [event["event_type"] for event in exfil_events]
    assert types[0] == "tool_call_received"
    assert "policy_decision" in types
    # A denied call never reaches authorization or the executor.
    assert "authorization_issued" not in types
    assert "execution_started" not in types

    decision = next(e for e in exfil_events if e["event_type"] == "policy_decision")
    assert decision["payload"]["decision"] == "DENY"
    assert decision["payload"]["final_decision"] == "DENY"
    assert decision["payload"]["classifier"]["model_version"]

    # The events returned are the same events the audit log stores.
    stored = {
        event["seq"]: event["event_hash"]
        for event in client.get("/audit/events?limit=500").json()["events"]
    }
    for event in exfil_events:
        assert stored[event["seq"]] == event["event_hash"]


def test_simulation_is_persisted_and_listed(client: TestClient):
    record = client.post("/simulations/secret-read").json()
    run_id = record["run_id"]

    latest = client.get("/simulations/latest")
    assert latest.status_code == 200
    assert latest.json()["run_id"] == run_id

    detail = client.get(f"/simulations/{run_id}")
    assert detail.status_code == 200
    assert detail.json()["result"]["decision"] == "DENY"

    listing = client.get("/simulations").json()["simulations"]
    assert listing[0]["run_id"] == run_id
    assert listing[0]["outcome"] == "DENY"
    assert listing[0]["reason_code"] == "confidential_data_transfer"

    assert client.get("/simulations/sim_missing").status_code == 404


def test_latest_reports_404_before_any_run(client: TestClient):
    response = client.get("/simulations/latest")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_metrics_reflect_the_simulation(client: TestClient):
    client.post("/simulations/secret-read")
    metrics = client.get("/metrics").json()

    assert metrics["decisions"] == {"ALLOW": 1, "DENY": 1, "APPROVAL": 0}
    assert metrics["executions"] == 1
    assert metrics["unauthorized_executions"] == 0
    assert metrics["pending_approvals"] == 0
    assert metrics["simulations"]["count"] == 1
    assert metrics["audit"]["valid"] is True
    assert metrics["classifier"]["authority"] == "advisory only"
    assert metrics["classifier"]["dataset_size"] == 120


def test_repeated_runs_use_fresh_sessions(client: TestClient):
    first = client.post("/simulations/secret-read").json()
    second = client.post("/simulations/secret-read").json()
    assert first["run_id"] != second["run_id"]
    assert first["session_id"] != second["session_id"]
    # A second run must not be tainted by the first run's provenance.
    assert second["steps"][1]["response"]["decision"] == "DENY"
    assert second["steps"][1]["response"]["reason_code"] == "confidential_data_transfer"
    assert client.get("/metrics").json()["simulations"]["count"] == 2
