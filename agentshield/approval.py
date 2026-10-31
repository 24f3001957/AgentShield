"""Exact-call approval workflow.

Lifecycle::

    PROPOSED -> PENDING_APPROVAL -> APPROVED -> REVALIDATED -> CONSUMED -> EXECUTED

``REJECTED`` and ``EXPIRED`` are terminal. An approval record binds to a
canonical SHA-256 fingerprint of the exact action (actor, session, tool,
operation, normalized arguments, resource, destination, classification, policy
and canonicalization versions), so mutating any authorization-relevant field,
letting it expire, or replaying a consumed approval all fail closed.

Consumption is a conditional single-row update executed inside a
``BEGIN IMMEDIATE`` transaction: of N concurrent attempts exactly one observes
the expected pre-state and wins.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from .db import Database
from .models import ToolCallRequest, action_binding, canonical_json, json

PENDING_STATE = "PENDING_APPROVAL"
TERMINAL_STATES = frozenset({"REJECTED", "EXPIRED", "CONSUMED", "EXECUTED"})


class ApprovalError(Exception):
    """Approval could not be used. Carries a machine-readable reason code."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        super().__init__(detail or reason_code)
        self.reason_code = reason_code
        self.detail = detail or reason_code


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    request_id: str
    fingerprint: str
    binding_json: str
    state: str
    requested_by: str
    approver: str | None
    created_at: float
    expires_at: float
    decided_at: float | None = None
    consumed_at: float | None = None
    executed_at: float | None = None

    @property
    def binding(self) -> dict[str, Any]:
        return json.loads(self.binding_json)

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "request_id": self.request_id,
            "fingerprint": self.fingerprint,
            "binding": self.binding,
            "state": self.state,
            "requested_by": self.requested_by,
            "approver": self.approver,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "decided_at": self.decided_at,
            "consumed_at": self.consumed_at,
            "executed_at": self.executed_at,
        }


def _record(row: Any) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=str(row["approval_id"]),
        request_id=str(row["request_id"]),
        fingerprint=str(row["fingerprint"]),
        binding_json=str(row["binding_json"]),
        state=str(row["state"]),
        requested_by=str(row["requested_by"]),
        approver=None if row["approver"] is None else str(row["approver"]),
        created_at=float(row["created_at"]),
        expires_at=float(row["expires_at"]),
        decided_at=None if row["decided_at"] is None else float(row["decided_at"]),
        consumed_at=None if row["consumed_at"] is None else float(row["consumed_at"]),
        executed_at=None if row["executed_at"] is None else float(row["executed_at"]),
    )


class ApprovalService:
    """Creates, decides, revalidates and atomically consumes approvals."""

    def __init__(self, db: Database, clock: "callable" = time.time, ttl_seconds: float = 300.0) -> None:
        self.db = db
        self.clock = clock
        self.ttl_seconds = ttl_seconds

    # -- creation -----------------------------------------------------------
    def create(
        self,
        request: ToolCallRequest,
        fingerprint: str,
        policy_version: str,
        requested_by: str | None = None,
    ) -> ApprovalRecord:
        """Register a pending approval bound to the exact action."""
        approval_id = "apr_" + uuid.uuid4().hex
        now = float(self.clock())
        expires_at = now + self.ttl_seconds
        binding_json = canonical_json(action_binding(request, policy_version))
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO approvals "
                "(approval_id, request_id, fingerprint, binding_json, state, "
                " requested_by, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, 'PROPOSED', ?, ?, ?)",
                (
                    approval_id,
                    request.request_id,
                    fingerprint,
                    binding_json,
                    requested_by or request.actor_id,
                    now,
                    expires_at,
                ),
            )
            conn.execute(
                "UPDATE approvals SET state = ? WHERE approval_id = ? AND state = 'PROPOSED'",
                (PENDING_STATE, approval_id),
            )
        record = self.get(approval_id)
        assert record is not None
        return record

    # -- reads --------------------------------------------------------------
    def get(self, approval_id: str) -> ApprovalRecord | None:
        row = self.db.query_one(
            "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
        )
        return None if row is None else _record(row)

    def list(self, state: str | None = None) -> list[ApprovalRecord]:
        if state:
            rows = self.db.query(
                "SELECT * FROM approvals WHERE state = ? ORDER BY created_at",
                (state,),
            )
        else:
            rows = self.db.query("SELECT * FROM approvals ORDER BY created_at")
        return [_record(row) for row in rows]

    def is_expired(self, record: ApprovalRecord) -> bool:
        return float(record.expires_at) <= float(self.clock())

    # -- decisions ----------------------------------------------------------
    def decide(self, approval_id: str, approver: str, approve: bool) -> ApprovalRecord:
        """Approve or reject a pending approval.

        Approval never executes anything - it only moves the record forward so
        the gateway may later revalidate and consume it.
        """
        record = self.get(approval_id)
        if record is None:
            raise ApprovalError("approval_not_found", approval_id)
        if record.state != PENDING_STATE:
            raise ApprovalError("approval_not_pending", record.state)
        if self.is_expired(record):
            self.db.execute(
                "UPDATE approvals SET state = 'EXPIRED' WHERE approval_id = ? "
                "AND state = ?",
                (approval_id, PENDING_STATE),
            )
            raise ApprovalError(
                "approval_expired", f"expired at {record.expires_at}"
            )

        now = float(self.clock())
        new_state = "APPROVED" if approve else "REJECTED"
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "UPDATE approvals SET state = ?, approver = ?, decided_at = ? "
                "WHERE approval_id = ? AND state = ?",
                (new_state, approver, now, approval_id, PENDING_STATE),
            )
            if cursor.rowcount != 1:
                raise ApprovalError("approval_not_pending", approval_id)
        updated = self.get(approval_id)
        assert updated is not None
        return updated

    # -- consumption --------------------------------------------------------
    def revalidate(self, approval_id: str, fingerprint: str) -> bool:
        """APPROVED -> REVALIDATED, only if the action is unchanged."""
        cursor = self.db.execute(
            "UPDATE approvals SET state = 'REVALIDATED' "
            "WHERE approval_id = ? AND state = 'APPROVED' AND fingerprint = ?",
            (approval_id, fingerprint),
        )
        return cursor.rowcount == 1

    def consume(self, approval_id: str, fingerprint: str) -> bool:
        """REVALIDATED -> CONSUMED. Atomic: exactly one caller can win."""
        cursor = self.db.execute(
            "UPDATE approvals SET state = 'CONSUMED', consumed_at = ? "
            "WHERE approval_id = ? AND state = 'REVALIDATED' AND fingerprint = ?",
            (float(self.clock()), approval_id, fingerprint),
        )
        return cursor.rowcount == 1

    def mark_executed(self, approval_id: str) -> None:
        self.db.execute(
            "UPDATE approvals SET state = 'EXECUTED', executed_at = ? "
            "WHERE approval_id = ? AND state = 'CONSUMED'",
            (float(self.clock()), approval_id),
        )

    def mark_executed_state(self, approval_id: str) -> str | None:
        row = self.db.query_one(
            "SELECT state FROM approvals WHERE approval_id = ?", (approval_id,)
        )
        return None if row is None else str(row["state"])

    # -- queries used by the API -------------------------------------------
    def pending(self) -> Iterable[ApprovalRecord]:
        return self.list(PENDING_STATE)
