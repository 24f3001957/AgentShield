"""FastAPI surface for AgentShield.

Design rules:

* No endpoint executes a tool directly - every call goes through
  ``Gateway.submit`` or ``Gateway.execute_approved``.
* No endpoint lets a client mint an authorization; authorizations are issued
  server-side only, after validation, policy and approval checks.
* Errors return predictable JSON: ``{"error": {"code", "detail"}}`` with a
  status derived from the reason code.

Run locally::

    uvicorn --factory agentshield.api:create_app --reload
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .approval import ApprovalError
from .audit import AuditError
from .evaluation import EvaluationRunner
from .gateway import Gateway
from .models import CANONICALIZATION_VERSION, POLICY_VERSION

DEFAULT_DB_PATH = "agentshield.db"

_REASONS_HTTP = {
    "approval_not_found": 404,
    "approval_request_mismatch": 409,
    "approval_mutation": 409,
    "approval_expired": 409,
    "approval_already_consumed": 409,
    "approval_rejected": 409,
    "approval_not_approved": 409,
    "approval_revalidation_conflict": 409,
    "approval_consumption_conflict": 409,
    "approval_not_pending": 409,
    "audit_unavailable": 503,
}


class ApprovalDecisionBody(BaseModel):
    """Approver decision. Approver identity is simulated in this prototype."""

    model_config = ConfigDict(extra="forbid")

    approver: str = Field(min_length=1, max_length=128)
    decision: Literal["APPROVE", "REJECT"]


class ExecuteBody(BaseModel):
    """A full re-submitted request plus the approval it claims to consume.

    The request is revalidated and re-fingerprinted server-side: changing any
    authorization-relevant field invalidates the approval.
    """

    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(min_length=1, max_length=128)
    request: dict[str, Any]


def _error(code: str, detail: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status, content={"error": {"code": code, "detail": detail}}
    )


def create_app(db_path: str | None = None) -> FastAPI:
    """Application factory (used by ``uvicorn --factory`` and by the tests)."""
    path = db_path or os.environ.get("AGENTSHIELD_DB", DEFAULT_DB_PATH)
    gateway = Gateway(path)

    app = FastAPI(
        title="AgentShield",
        version="0.1.0",
        description=(
            "Permission firewall and audit trail for autonomous AI-agent tool "
            "calls. Mock tools only: no real files, mail or network access."
        ),
    )
    app.state.gateway = gateway

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "policy_version": POLICY_VERSION,
            "audit_events": gateway.audit.count(),
            "tools": sorted(gateway.registry()),
        }

    # -- tool calls ---------------------------------------------------------
    @app.post("/tool-calls")
    async def submit_tool_call(request: Request) -> Any:
        raw = await request.json()
        if not isinstance(raw, dict):
            return _error("invalid_request", "body must be a JSON object", 422)
        return gateway.submit(raw)

    @app.get("/tool-calls")
    def list_tool_calls(limit: int = Query(default=100, ge=1, le=500)) -> dict[str, Any]:
        return {"tool_calls": gateway.list_tool_calls(limit=limit)}

    @app.get("/tool-calls/{request_id}")
    def get_tool_call(request_id: str) -> Any:
        status = gateway.get_status(request_id)
        if status is None:
            return _error("not_found", f"unknown request_id {request_id}", 404)
        return status

    @app.post("/tool-calls/{request_id}/execute")
    def execute_tool_call(request_id: str, body: ExecuteBody) -> Any:
        submitted = dict(body.request)
        submitted.setdefault("request_id", request_id)
        if submitted.get("request_id") != request_id:
            return _error(
                "invalid_request", "request.request_id does not match the path", 400
            )
        response = gateway.execute_approved(submitted, body.approval_id)
        reason = response.get("reason_code")
        status = _REASONS_HTTP.get(str(reason), 200)
        if status != 200:
            return JSONResponse(status_code=status, content=response)
        return response

    # -- policy -------------------------------------------------------------
    @app.get("/policy")
    def policy() -> dict[str, Any]:
        """Read-only description of the active policy for the reviewer UI."""
        return {
            **gateway.policy.describe(),
            "canonicalization_version": CANONICALIZATION_VERSION,
            "tools": gateway.registry(),
        }

    # -- approvals ----------------------------------------------------------
    @app.get("/approvals")
    def list_approvals(state: str | None = None) -> dict[str, Any]:
        records = gateway.approvals.list(state)
        return {"approvals": [record.to_dict() for record in records]}

    @app.post("/approvals/{approval_id}/decision")
    def decide_approval(approval_id: str, body: ApprovalDecisionBody) -> Any:
        try:
            record = gateway.approvals.decide(
                approval_id, approver=body.approver, approve=body.decision == "APPROVE"
            )
        except ApprovalError as exc:
            return _error(exc.reason_code, exc.detail, _REASONS_HTTP.get(exc.reason_code, 409))
        try:
            gateway.audit.append(
                "approval_decided",
                {
                    "approval_id": approval_id,
                    "approver": body.approver,
                    "decision": body.decision,
                    "state": record.state,
                },
            )
        except AuditError as exc:
            return _error("audit_unavailable", str(exc), 503)
        return {"approval": record.to_dict(), "executed": False}

    # -- audit --------------------------------------------------------------
    @app.get("/audit/events")
    def audit_events(limit: int = Query(default=200, ge=1, le=2000)) -> dict[str, Any]:
        events = gateway.audit.events(limit=limit)
        return {"events": events, "count": gateway.audit.count()}

    @app.get("/audit/verify")
    def audit_verify(
        expected_count: int | None = Query(default=None, ge=1),
        expected_head: str | None = Query(default=None, max_length=64),
        record: bool = Query(default=False),
    ) -> Any:
        try:
            result = gateway.audit.verify(
                expected_count=expected_count, expected_head=expected_head, record=record
            )
        except AuditError as exc:
            return _error("audit_unavailable", str(exc), 503)
        return {
            **result.to_dict(),
            "trust_anchor": {
                "expected_count": expected_count,
                "expected_head": expected_head,
                "note": (
                    "Without an externally held count or head, verification proves "
                    "internal consistency, not completeness: a truncated chain still "
                    "verifies."
                ),
            },
        }

    # -- evaluation ---------------------------------------------------------
    @app.post("/evaluation/run")
    def run_evaluation() -> Any:
        try:
            runner = EvaluationRunner(store_db=gateway.db)
            results = runner.run()
        except AuditError as exc:
            return _error("audit_unavailable", str(exc), 503)
        return results

    @app.get("/evaluation/results")
    def evaluation_results(run_id: str | None = None) -> Any:
        if run_id:
            row = gateway.db.query_one(
                "SELECT results_json FROM evaluation_runs WHERE run_id = ?", (run_id,)
            )
        else:
            row = gateway.db.query_one(
                "SELECT results_json FROM evaluation_runs "
                "ORDER BY created_at DESC LIMIT 1"
            )
        if row is None:
            return _error("not_found", "no evaluation run recorded", 404)
        return json.loads(str(row["results_json"]))

    @app.get("/evaluation/export")
    def evaluation_export() -> Any:
        row = gateway.db.query_one(
            "SELECT run_id, created_at, results_json FROM evaluation_runs "
            "ORDER BY created_at DESC LIMIT 1"
        )
        if row is None:
            return _error("not_found", "no evaluation run recorded", 404)
        payload = str(row["results_json"])
        return JSONResponse(
            content=json.loads(payload),
            headers={
                "Content-Disposition": f'attachment; filename="{row["run_id"]}.json"'
            },
        )

    # -- reviewer UI (optional) ---------------------------------------------
    # When the frontend has been built (`npm run build` in ./frontend), serve it
    # from the same origin so one uvicorn process runs the whole demo. API
    # routes above take precedence; no second execution path is introduced.
    dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
    if (dist / "index.html").is_file():
        assets = dist / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="ui-assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        def serve_ui(full_path: str) -> FileResponse:
            """Serve the built SPA, including client-side routes."""
            candidate = (dist / full_path).resolve()
            if full_path and candidate.is_file() and dist.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(dist / "index.html")

    return app