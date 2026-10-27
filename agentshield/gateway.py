"""Gateway: the trusted server-side path for every proposed tool call.

Flow for a submitted call::

    validate -> policy -> DENY? stop (no side effect)
                          APPROVAL? create pending approval, stop
                          ALLOW? issue authorization -> executor -> audit

Flow for an approved call (``execute_approved``)::

    validate -> policy -> DENY? stop   (a hard denial can never be overridden)
            -> bind approval to this exact action (fingerprint + request id)
            -> revalidate -> consume (atomic, single use)
            -> issue authorization -> executor -> mark approval EXECUTED

A client-supplied ``approved: true`` field is not part of the schema and has no
effect anywhere in this module.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from .approval import ApprovalError, ApprovalRecord, ApprovalService
from .audit import AuditError, AuditLog
from .authorization import AuthorizationService
from .db import Database
from .executor import ControlledExecutor, ExecutionDenied, ExecutionResult
from .models import (
    POLICY_VERSION,
    Decision,
    PolicyOutcome,
    ToolCallRequest,
    action_fingerprint,
    canonical_json,
)
from .policy import PolicyEngine
from .tools import MockToolHost, TOOL_REGISTRY
from .validator import ValidationResult, validate

#: Argument keys never copied into stored payloads or audit records.
REDACTED_ARGUMENT_KEYS = frozenset({"body", "content", "password", "secret", "token"})

_VALID = "DENIED"
_APPROVAL = "AWAITING_APPROVAL"
_EXECUTED = "EXECUTED"
_FAILED = "FAILED"
_NO_EXECUTION = "NO_EXECUTION"
_AUDIT_FAILURE = "AUDIT_FAILURE"


def _peek(raw: Any, key: str, default: str = "") -> str:
    if isinstance(raw, dict):
        value = raw.get(key)
        return value if isinstance(value, str) else default
    return default


def redact_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Drop message bodies and other secrets before persisting an action."""
    return {
        key: ("[redacted]" if key.lower() in REDACTED_ARGUMENT_KEYS else value)
        for key, value in arguments.items()
    }


class Gateway:
    """Trusted host: owns policy, approvals, authorization and the executor."""

    def __init__(
        self,
        db: Database | str = "agentshield.db",
        *,
        clock: "callable" = time.time,
        policy: PolicyEngine | None = None,
        approval_ttl: float = 300.0,
        authorization_ttl: float = 300.0,
        authz_secret: bytes | None = None,
    ) -> None:
        self.db = db if isinstance(db, Database) else Database(db)
        self.clock = clock
        self.policy = policy or PolicyEngine()
        self.tools = MockToolHost(
            self.db,
            internal_domains=self.policy.config.internal_domains,
            approved_destinations=self.policy.config.approved_destinations,
        )
        self.approvals = ApprovalService(self.db, clock=clock, ttl_seconds=approval_ttl)
        self.authorizations = AuthorizationService(
            self.db, secret=authz_secret, clock=clock, ttl_seconds=authorization_ttl
        )
        self.audit = AuditLog(self.db, clock=clock)
        self.executor = ControlledExecutor(
            self.db, self.tools, self.authorizations, self.audit, clock=clock
        )

    # ------------------------------------------------------------------ submit
    def submit(self, raw: Any) -> dict[str, Any]:
        """Validate, decide, and (only when allowed) execute one tool call."""
        request_id = _peek(raw, "request_id") or "req_" + uuid.uuid4().hex
        actor_id = _peek(raw, "actor_id", "-")
        session_id = _peek(raw, "session_id", "-")
        tool_name = _peek(raw, "tool_name", "-")
        operation = _peek(raw, "operation", "-")

        # 1. Receipt event. If the audit trail cannot be written, stop here.
        try:
            self.audit.append(
                "tool_call_received",
                {
                    "actor_id": actor_id,
                    "operation": operation,
                    "request_id": request_id,
                    "session_id": session_id,
                    "tool_name": tool_name,
                },
            )
        except AuditError as exc:
            return self._response(
                request_id,
                _AUDIT_FAILURE,
                reason_code="audit_unavailable",
                detail=str(exc),
            )

        # 2. Validation (schema, registry, arguments, resource safety).
        validation = validate(raw)
        if not validation.ok:
            self._record_event("validation_failed", request_id, validation)
        outcome = self.policy.evaluate(
            validation.request if validation.ok else None, validation
        )
        self._record_decision(request_id, validation.request, outcome)
        if outcome.decision is Decision.DENY:
            self._persist(
                request_id=request_id,
                actor_id=actor_id,
                session_id=session_id,
                tool_name=tool_name,
                operation=operation,
                raw=raw,
                state=_VALID,
                outcome=outcome,
            )
            return self._response(
                request_id,
                _VALID,
                decision=outcome,
                detail=validation.detail,
            )

        request = validation.request
        assert request is not None
        fingerprint = action_fingerprint(request, self.policy.policy_version)

        # 3a. APPROVAL: register the pending approval, execute nothing.
        if outcome.decision is Decision.APPROVAL:
            approval = self.approvals.create(
                request, fingerprint, self.policy.policy_version
            )
            self.audit.append(
                "approval_created",
                {
                    "approval_id": approval.approval_id,
                    "expires_at": approval.expires_at,
                    "fingerprint": fingerprint,
                    "reason_code": outcome.reason_code,
                    "request_id": request_id,
                },
            )
            self._persist(
                request_id=request_id,
                actor_id=actor_id,
                session_id=session_id,
                tool_name=tool_name,
                operation=operation,
                raw=raw,
                state=_APPROVAL,
                outcome=outcome,
                approval_id=approval.approval_id,
            )
            return self._response(
                request_id, _APPROVAL, decision=outcome, approval=approval
            )

        # 3b. ALLOW: server-issued authorization, then the controlled executor.
        authorization = self.authorizations.issue(
            request_id, fingerprint, "ALLOW"
        )
        try:
            self.audit.append(
                "authorization_issued",
                {
                    "authorization_id": authorization.authorization_id,
                    "expires_at": authorization.expires_at,
                    "fingerprint": fingerprint,
                    "kind": "ALLOW",
                    "request_id": request_id,
                },
            )
        except AuditError as exc:
            self._persist(
                request_id=request_id,
                actor_id=actor_id,
                session_id=session_id,
                tool_name=tool_name,
                operation=operation,
                raw=raw,
                state=_AUDIT_FAILURE,
                outcome=outcome,
                authorization_id=authorization.authorization_id,
                detail=str(exc),
            )
            return self._response(
                request_id,
                _AUDIT_FAILURE,
                decision=outcome,
                reason_code="audit_unavailable",
                detail=str(exc),
            )
        return self._run(
            request=request,
            outcome=outcome,
            authorization=authorization,
            fingerprint=fingerprint,
            approval=None,
            actor_id=actor_id,
            session_id=session_id,
            raw=raw,
        )

    # -------------------------------------------------------------- execute approved
    def execute_approved(self, raw: Any, approval_id: str) -> dict[str, Any]:
        """Revalidate and consume an approval, then run through the executor."""
        request_id = _peek(raw, "request_id") or "req_" + uuid.uuid4().hex
        actor_id = _peek(raw, "actor_id", "-")
        session_id = _peek(raw, "session_id", "-")
        tool_name = _peek(raw, "tool_name", "-")
        operation = _peek(raw, "operation", "-")

        try:
            self.audit.append(
                "execution_requested",
                {"approval_id": approval_id, "request_id": request_id},
            )
        except AuditError as exc:
            return self._response(
                request_id,
                _NO_EXECUTION,
                reason_code="audit_unavailable",
                detail=str(exc),
            )

        validation = validate(raw)
        if not validation.ok:
            self._record_event("validation_failed", request_id, validation)
        outcome = self.policy.evaluate(
            validation.request if validation.ok else None, validation
        )
        self._record_decision(request_id, validation.request, outcome)
        if outcome.decision is Decision.DENY:
            self._persist(
                request_id=request_id,
                actor_id=actor_id,
                session_id=session_id,
                tool_name=tool_name,
                operation=operation,
                raw=raw,
                state=_NO_EXECUTION,
                outcome=outcome,
                approval_id=approval_id,
                detail="hard denial: approval cannot override policy",
            )
            return self._response(
                request_id,
                _NO_EXECUTION,
                decision=outcome,
                detail="hard denial: approval cannot override policy",
            )

        request = validation.request
        assert request is not None
        fingerprint = action_fingerprint(request, self.policy.policy_version)

        approval = self.approvals.get(approval_id)
        if approval is None:
            return self._refuse(
                request_id, approval_id, raw, outcome, "approval_not_found"
            )
        if approval.request_id != request_id:
            return self._refuse(
                request_id, approval_id, raw, outcome, "approval_request_mismatch"
            )
        if approval.fingerprint != fingerprint:
            self.audit.append(
                "approval_revalidation_failed",
                {
                    "approval_id": approval_id,
                    "expected_fingerprint": approval.fingerprint,
                    "reason_code": "approval_mutation",
                    "request_id": request_id,
                },
            )
            return self._refuse(
                request_id, approval_id, raw, outcome, "approval_mutation"
            )
        if approval.state != "APPROVED":
            reason = {
                "CONSUMED": "approval_already_consumed",
                "EXECUTED": "approval_already_consumed",
                "REJECTED": "approval_rejected",
                "REVALIDATED": "approval_already_consumed",
                "EXPIRED": "approval_expired",
            }.get(approval.state, "approval_not_approved")
            return self._refuse(request_id, approval_id, raw, outcome, reason)
        if self.approvals.is_expired(approval):
            self.approvals.db.execute(
                "UPDATE approvals SET state = 'EXPIRED' "
                "WHERE approval_id = ? AND state = 'APPROVED'",
                (approval_id,),
            )
            return self._refuse(
                request_id, approval_id, raw, outcome, "approval_expired"
            )

        # Revalidate the exact call, then consume it exactly once.
        if not self.approvals.revalidate(approval_id, fingerprint):
            return self._refuse(
                request_id, approval_id, raw, outcome, "approval_revalidation_conflict"
            )
        try:
            self.audit.append(
                "approval_revalidated",
                {"approval_id": approval_id, "request_id": request_id},
            )
        except AuditError as exc:
            return self._response(
                request_id,
                _NO_EXECUTION,
                reason_code="audit_unavailable",
                detail=str(exc),
            )
        if not self.approvals.consume(approval_id, fingerprint):
            return self._refuse(
                request_id, approval_id, raw, outcome, "approval_consumption_conflict"
            )
        try:
            self.audit.append(
                "approval_consumed",
                {"approval_id": approval_id, "request_id": request_id},
            )
        except AuditError as exc:
            return self._response(
                request_id,
                _NO_EXECUTION,
                reason_code="audit_unavailable",
                detail=str(exc),
            )

        authorization = self.authorizations.issue(request_id, fingerprint, "APPROVAL")
        try:
            self.audit.append(
                "authorization_issued",
                {
                    "authorization_id": authorization.authorization_id,
                    "expires_at": authorization.expires_at,
                    "fingerprint": fingerprint,
                    "kind": "APPROVAL",
                    "request_id": request_id,
                },
            )
        except AuditError as exc:
            return self._response(
                request_id,
                _AUDIT_FAILURE,
                decision=outcome,
                reason_code="audit_unavailable",
                detail=str(exc),
            )

        response = self._run(
            request=request,
            outcome=outcome,
            authorization=authorization,
            fingerprint=fingerprint,
            approval=approval,
            actor_id=actor_id,
            session_id=session_id,
            raw=raw,
        )
        if response["status"] == _EXECUTED:
            self.approvals.mark_executed(approval_id)
        return response

    # ------------------------------------------------------------------ internals
    def _run(
        self,
        request: ToolCallRequest,
        outcome: PolicyOutcome,
        authorization: Any,
        fingerprint: str,
        approval: ApprovalRecord | None,
        actor_id: str,
        session_id: str,
        raw: Any,
    ) -> dict[str, Any]:
        try:
            result: ExecutionResult = self.executor.execute(
                request, authorization, fingerprint
            )
        except ExecutionDenied as exc:
            self._persist(
                request_id=request.request_id,
                actor_id=actor_id,
                session_id=session_id,
                tool_name=request.tool_name,
                operation=request.operation,
                raw=raw,
                state=_NO_EXECUTION,
                outcome=outcome,
                approval_id=None if approval is None else approval.approval_id,
                authorization_id=authorization.authorization_id,
                detail=exc.detail,
                reason_code=exc.reason_code,
            )
            return self._response(
                request_id=request.request_id,
                status=_NO_EXECUTION,
                decision=outcome,
                reason_code=exc.reason_code,
                detail=exc.detail,
            )
        except AuditError as exc:
            self._persist(
                request_id=request.request_id,
                actor_id=actor_id,
                session_id=session_id,
                tool_name=request.tool_name,
                operation=request.operation,
                raw=raw,
                state=_AUDIT_FAILURE,
                outcome=outcome,
                approval_id=None if approval is None else approval.approval_id,
                authorization_id=authorization.authorization_id,
                detail=str(exc),
            )
            return self._response(
                request_id=request.request_id,
                status=_AUDIT_FAILURE,
                decision=outcome,
                reason_code="audit_unavailable",
                detail=str(exc),
            )

        state = _EXECUTED if result.outcome == "EXECUTED" else _FAILED
        self._persist(
            request_id=request.request_id,
            actor_id=actor_id,
            session_id=session_id,
            tool_name=request.tool_name,
            operation=request.operation,
            raw=raw,
            state=state,
            outcome=outcome,
            approval_id=None if approval is None else approval.approval_id,
            authorization_id=authorization.authorization_id,
            execution_id=result.execution_id,
            detail=result.error or result.summary,
            reason_code=result.error,
        )
        return self._response(
            request_id=request.request_id,
            status=state,
            decision=outcome,
            reason_code=result.error or outcome.reason_code,
            result=result,
            approval=approval,
            detail=result.summary,
        )

    def _refuse(
        self,
        request_id: str,
        approval_id: str,
        raw: Any,
        outcome: PolicyOutcome,
        reason_code: str,
    ) -> dict[str, Any]:
        try:
            self.audit.append(
                "approval_rejected",
                {
                    "approval_id": approval_id,
                    "reason_code": reason_code,
                    "request_id": request_id,
                },
            )
        except AuditError as exc:
            reason_code = "audit_unavailable"
            detail: str | None = str(exc)
        else:
            detail = f"no execution: {reason_code}"
        self._persist(
            request_id=request_id,
            actor_id=_peek(raw, "actor_id", "-"),
            session_id=_peek(raw, "session_id", "-"),
            tool_name=_peek(raw, "tool_name", "-"),
            operation=_peek(raw, "operation", "-"),
            raw=raw,
            state=_NO_EXECUTION,
            outcome=outcome,
            approval_id=approval_id,
            detail=detail,
            reason_code=reason_code,
        )
        return self._response(
            request_id, _NO_EXECUTION, decision=outcome,
            reason_code=reason_code, detail=detail,
        )

    def _record_event(
        self, event_type: str, request_id: str, validation: ValidationResult
    ) -> None:
        try:
            self.audit.append(
                event_type,
                {
                    "detail": validation.detail,
                    "reason_code": validation.reason_code,
                    "request_id": request_id,
                },
            )
        except AuditError:
            pass  # the caller still fails closed: no request reaches a tool

    def _record_decision(
        self,
        request_id: str,
        request: ToolCallRequest | None,
        outcome: PolicyOutcome,
    ) -> None:
        payload: dict[str, Any] = {
            "decision": outcome.decision.value,
            "explanation": outcome.explanation,
            "policy_version": outcome.policy_version,
            "reason_code": outcome.reason_code,
            "request_id": request_id,
            "rule_name": outcome.rule_name,
        }
        if request is not None:
            payload.update(
                {
                    "data_classification": request.data_classification.value,
                    "destination": request.destination,
                    "operation": request.operation,
                    "resource": request.resource,
                    "tool_name": request.tool_name,
                }
            )
        try:
            self.audit.append("policy_decision", payload)
        except AuditError:
            pass

    def _persist(
        self,
        *,
        request_id: str,
        actor_id: str,
        session_id: str,
        tool_name: str,
        operation: str,
        raw: Any,
        state: str,
        outcome: PolicyOutcome | None,
        approval_id: str | None = None,
        authorization_id: str | None = None,
        execution_id: str | None = None,
        detail: str | None = None,
        reason_code: str | None = None,
    ) -> None:
        payload: dict[str, Any] = {"request_id": request_id}
        if isinstance(raw, dict):
            payload = {
                "arguments": redact_arguments(raw.get("arguments") or {}),
                "actor_id": raw.get("actor_id", actor_id),
                "data_classification": raw.get("data_classification"),
                "destination": raw.get("destination"),
                "operation": raw.get("operation", operation),
                "request_id": raw.get("request_id", request_id),
                "resource": raw.get("resource"),
                "session_id": raw.get("session_id", session_id),
                "tool_name": raw.get("tool_name", tool_name),
            }
        now = float(self.clock())
        self.db.execute(
            "INSERT OR REPLACE INTO tool_calls "
            "(request_id, actor_id, session_id, tool_name, operation, payload_json, "
            " state, decision, reason_code, policy_version, approval_id, "
            " authorization_id, execution_id, detail, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            " COALESCE((SELECT created_at FROM tool_calls WHERE request_id = ?), ?), ?)",
            (
                request_id,
                actor_id,
                session_id,
                tool_name,
                operation,
                canonical_json(payload),
                state,
                None if outcome is None else outcome.decision.value,
                reason_code
                or (None if outcome is None else outcome.reason_code),
                None if outcome is None else outcome.policy_version,
                approval_id,
                authorization_id,
                execution_id,
                detail,
                request_id,
                now,
                now,
            ),
        )

    @staticmethod
    def _response(
        request_id: str,
        status: str,
        *,
        decision: PolicyOutcome | None = None,
        reason_code: str | None = None,
        approval: ApprovalRecord | None = None,
        result: ExecutionResult | None = None,
        detail: str | None = None,
    ) -> dict[str, Any]:
        response: dict[str, Any] = {
            "request_id": request_id,
            "status": status,
            "decision": None if decision is None else decision.decision.value,
            "reason_code": reason_code
            or (None if decision is None else decision.reason_code),
            "policy_version": POLICY_VERSION,
            "explanation": "" if decision is None else decision.explanation,
            "approval": None if approval is None else approval.to_dict(),
            "result": None if result is None else result.to_dict(),
            "detail": detail,
        }
        return response

    # ------------------------------------------------------------------ queries
    def get_status(self, request_id: str) -> dict[str, Any] | None:
        row = self.db.query_one(
            "SELECT * FROM tool_calls WHERE request_id = ?", (request_id,)
        )
        if row is None:
            return None
        status = {
            "request_id": str(row["request_id"]),
            "state": str(row["state"]),
            "decision": row["decision"],
            "reason_code": row["reason_code"],
            "policy_version": row["policy_version"],
            "approval_id": row["approval_id"],
            "authorization_id": row["authorization_id"],
            "execution_id": row["execution_id"],
            "detail": row["detail"],
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }
        ledger = self.db.query_one(
            "SELECT * FROM execution_ledger WHERE execution_id = ?",
            (row["execution_id"],),
        ) if row["execution_id"] else None
        if ledger is not None:
            status["execution"] = {
                "execution_id": str(ledger["execution_id"]),
                "outcome": str(ledger["outcome"]),
                "summary": str(ledger["summary"]),
                "error": ledger["detail"],
                "executed_at": float(ledger["executed_at"]),
            }
        if row["approval_id"]:
            approval = self.approvals.get(str(row["approval_id"]))
            status["approval"] = None if approval is None else approval.to_dict()
        return status

    def list_tool_calls(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT request_id, state, decision, reason_code, approval_id, "
            " execution_id, updated_at FROM tool_calls ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        )
        return [
            {
                "request_id": str(row["request_id"]),
                "state": str(row["state"]),
                "decision": row["decision"],
                "reason_code": row["reason_code"],
                "approval_id": row["approval_id"],
                "execution_id": row["execution_id"],
                "updated_at": float(row["updated_at"]),
            }
            for row in rows
        ]

    @staticmethod
    def registry() -> dict[str, dict[str, Any]]:
        return {
            name: {
                "description": spec.description,
                "operations": sorted(spec.operations),
                "required_args": {
                    op: list(args) for op, args in spec.required_args.items()
                },
            }
            for name, spec in TOOL_REGISTRY.items()
        }