"""The controlled executor: the only code path allowed to invoke a tool.

Before any side effect it independently re-checks the server-issued
authorization (HMAC validity, expiry, action fingerprint, single-use state),
consumes it atomically, and writes the pre-execution audit event. Any failure
raises :class:`ExecutionDenied` and **nothing executes** - the gateway treats a
policy verdict alone as insufficient proof of authorization.

Post-execution results are written to the execution ledger, which is what the
tests inspect as proof of a side effect (never a model's claim that it ran
something).
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditError, AuditLog
from .authorization import Authorization, AuthorizationError, AuthorizationService
from .db import Database
from .models import ToolCallRequest, action_fingerprint
from .tools import MockToolHost, ToolExecutionError


class ExecutionDenied(Exception):
    """The executor refused to run the action. No side effect occurred."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        super().__init__(detail or reason_code)
        self.reason_code = reason_code
        self.detail = detail or reason_code


@dataclass
class ExecutionResult:
    execution_id: str
    request_id: str
    authorization_id: str
    tool_name: str
    operation: str
    outcome: str
    summary: str
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "request_id": self.request_id,
            "authorization_id": self.authorization_id,
            "tool_name": self.tool_name,
            "operation": self.operation,
            "outcome": self.outcome,
            "summary": self.summary,
            "output": self.output,
            "error": self.error,
        }


class ControlledExecutor:
    """Verifies authorization, then runs exactly one registered mock tool."""

    def __init__(
        self,
        db: Database,
        tools: MockToolHost,
        authorizations: AuthorizationService,
        audit: AuditLog,
        clock: "callable" = time.time,
    ) -> None:
        self.db = db
        self.tools = tools
        self.authorizations = authorizations
        self.audit = audit
        self.clock = clock

    def execute(
        self, request: ToolCallRequest, authorization: Authorization, fingerprint: str
    ) -> ExecutionResult:
        execution_id = "exe_" + uuid.uuid4().hex

        if authorization.fingerprint != fingerprint:
            self._reject(
                execution_id, request, authorization, "authorization_mismatch",
                "authorization does not cover this action fingerprint",
            )
        try:
            self.authorizations.verify(authorization)
        except AuthorizationError as exc:
            self._reject(execution_id, request, authorization, exc.reason_code, exc.detail)
        if not self.authorizations.consume(authorization):
            self._reject(
                execution_id, request, authorization,
                "authorization_not_consumable", "authorization already used",
            )

        # Fail closed: if the pre-execution audit record cannot be written,
        # the action does not run.
        try:
            self.audit.append(
                "execution_started",
                {
                    "authorization_id": authorization.authorization_id,
                    "execution_id": execution_id,
                    "fingerprint": fingerprint,
                    "operation": request.operation,
                    "request_id": request.request_id,
                    "resource": request.resource,
                    "destination": request.destination,
                    "tool_name": request.tool_name,
                },
            )
        except AuditError as exc:
            raise ExecutionDenied("audit_unavailable", str(exc)) from exc

        try:
            result = self.tools.execute(request)
        except ToolExecutionError as exc:
            self._record(
                execution_id=execution_id,
                request=request,
                authorization=authorization,
                fingerprint=fingerprint,
                outcome="FAILED",
                summary=f"{request.tool_name}.{request.operation} refused",
                error=exc.reason_code,
            )
            return ExecutionResult(
                execution_id=execution_id,
                request_id=request.request_id,
                authorization_id=authorization.authorization_id,
                tool_name=request.tool_name,
                operation=request.operation,
                outcome="FAILED",
                summary=f"{request.tool_name}.{request.operation} refused",
                error=exc.reason_code,
            )
        except Exception as exc:  # noqa: BLE001 - unexpected tool fault
            self._record(
                execution_id=execution_id,
                request=request,
                authorization=authorization,
                fingerprint=fingerprint,
                outcome="FAILED",
                summary="tool raised an unexpected error",
                error=type(exc).__name__,
            )
            return ExecutionResult(
                execution_id=execution_id,
                request_id=request.request_id,
                authorization_id=authorization.authorization_id,
                tool_name=request.tool_name,
                operation=request.operation,
                outcome="FAILED",
                summary="tool raised an unexpected error",
                error=type(exc).__name__,
            )

        self._record(
            execution_id=execution_id,
            request=request,
            authorization=authorization,
            fingerprint=fingerprint,
            outcome="EXECUTED",
            summary=result.summary,
            error=None,
        )
        self.audit.append(
            "execution_completed",
            {
                "execution_id": execution_id,
                "fingerprint": fingerprint,
                "outcome": "EXECUTED",
                "request_id": request.request_id,
                "summary": result.summary,
                "tool_name": request.tool_name,
            },
        )
        return ExecutionResult(
            execution_id=execution_id,
            request_id=request.request_id,
            authorization_id=authorization.authorization_id,
            tool_name=request.tool_name,
            operation=request.operation,
            outcome="EXECUTED",
            summary=result.summary,
            output=result.output,
        )

    # -- helpers ------------------------------------------------------------
    def _reject(
        self,
        execution_id: str,
        request: ToolCallRequest,
        authorization: Authorization,
        reason_code: str,
        detail: str,
    ) -> None:
        """Audit a rejection. Audit failure here still never executes anything."""
        try:
            self.audit.append(
                "authorization_rejected",
                {
                    "authorization_id": authorization.authorization_id,
                    "detail": detail,
                    "execution_id": execution_id,
                    "reason_code": reason_code,
                    "request_id": request.request_id,
                },
            )
        except AuditError:
            pass
        raise ExecutionDenied(reason_code, detail)

    def _record(
        self,
        execution_id: str,
        request: ToolCallRequest,
        authorization: Authorization,
        fingerprint: str,
        outcome: str,
        summary: str,
        error: str | None,
    ) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO execution_ledger "
            "(execution_id, request_id, authorization_id, approval_id, actor_id, "
            " tool_name, operation, fingerprint, outcome, summary, detail, executed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                execution_id,
                request.request_id,
                authorization.authorization_id,
                None,
                request.actor_id,
                request.tool_name,
                request.operation,
                fingerprint,
                outcome,
                summary,
                error,
                float(self.clock()),
            ),
        )
        try:
            self.audit.append(
                "execution_failed" if outcome == "FAILED" else "execution_recorded",
                {
                    "execution_id": execution_id,
                    "outcome": outcome,
                    "reason_code": error,
                    "request_id": request.request_id,
                    "summary": summary,
                },
            )
        except AuditError as exc:
            raise AuditError(str(exc)) from exc
