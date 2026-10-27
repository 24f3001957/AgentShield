"""SHA-256 hash-chained audit trail.

Every event stores a canonical JSON payload, the previous event's hash and its
own hash, which is computed over ``{seq, event_type, payload, prev_hash,
timestamp}`` - the stored hash is deliberately excluded from its own input.

Verification recomputes each hash, checks sequence continuity and previous-hash
linkage, and can compare against a trusted event count and/or final chain head.

**Limits (documented, not marketing):** this chain is tamper-*evident*, not
tamper-proof. An attacker with write access to the whole store can rewrite
every event and recompute the hashes. The chain only detects modification when
the trusted head (or event count) is held elsewhere, and it cannot detect
deletion of a suffix of events when no external head is pinned.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .db import Database
from .models import GENESIS_HASH, canonical_json, sha256_hex


class AuditError(Exception):
    """The audit trail could not be written. Callers must fail closed."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass
class VerificationResult:
    valid: bool
    event_count: int
    head: str
    failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "event_count": self.event_count,
            "head": self.head,
            "failures": list(self.failures),
        }


def _event_body(
    seq: int,
    event_type: str,
    payload: dict[str, Any],
    prev_hash: str,
    timestamp: str,
) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "payload": payload,
        "prev_hash": prev_hash,
        "seq": seq,
        "timestamp": timestamp,
    }


class AuditLog:
    """Append-only structured event writer with an integrity verifier."""

    def __init__(self, db: Database, clock: "callable" = time.time) -> None:
        self.db = db
        self.clock = clock

    # -- writing ------------------------------------------------------------
    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Append one event. Raises :class:`AuditError` on any failure."""
        try:
            with self.db.transaction() as conn:
                row = conn.execute(
                    "SELECT seq, event_hash FROM audit_events "
                    "ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                seq = 1 if row is None else int(row["seq"]) + 1
                prev_hash = GENESIS_HASH if row is None else str(row["event_hash"])
                timestamp = datetime.fromtimestamp(
                    float(self.clock()), tz=timezone.utc
                ).isoformat()
                body = _event_body(seq, event_type, payload, prev_hash, timestamp)
                event_hash = sha256_hex(canonical_json(body))
                conn.execute(
                    "INSERT INTO audit_events "
                    "(seq, event_type, payload_json, prev_hash, event_hash, timestamp) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        seq,
                        event_type,
                        canonical_json(payload),
                        prev_hash,
                        event_hash,
                        timestamp,
                    ),
                )
        except AuditError:
            raise
        except Exception as exc:  # noqa: BLE001 - any write failure is fatal
            raise AuditError(f"failed to append audit event: {exc}") from exc

        return {
            "seq": seq,
            "event_type": event_type,
            "prev_hash": prev_hash,
            "event_hash": event_hash,
            "timestamp": timestamp,
        }

    def events(self, limit: int | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM audit_events ORDER BY seq"
        rows = self.db.query(sql)
        if limit is not None:
            rows = rows[-limit:]
        return [self._as_dict(row) for row in rows]

    @staticmethod
    def _as_dict(row: Any) -> dict[str, Any]:
        return {
            "seq": int(row["seq"]),
            "event_type": str(row["event_type"]),
            "payload": json.loads(str(row["payload_json"])),
            "prev_hash": str(row["prev_hash"]),
            "event_hash": str(row["event_hash"]),
            "timestamp": str(row["timestamp"]),
        }

    # -- verification -------------------------------------------------------
    def verify(
        self,
        expected_count: int | None = None,
        expected_head: str | None = None,
        record: bool = False,
    ) -> VerificationResult:
        """Check ordering, linkage and recomputed hashes.

        ``expected_count``/``expected_head`` are the trust anchors: without one
        of them a truncated-but-consistent chain still verifies, because the
        chain alone cannot prove it is complete.
        """
        rows = self.db.query("SELECT * FROM audit_events ORDER BY seq")
        failures: list[str] = []
        prev_hash = GENESIS_HASH
        expected_seq = 1

        for row in rows:
            seq = int(row["seq"])
            if seq != expected_seq:
                failures.append(f"sequence gap: expected {expected_seq}, found {seq}")
            if str(row["prev_hash"]) != prev_hash:
                failures.append(f"prev_hash mismatch at seq {seq}")
            body = _event_body(
                seq=seq,
                event_type=str(row["event_type"]),
                payload=json.loads(str(row["payload_json"])),
                prev_hash=str(row["prev_hash"]),
                timestamp=str(row["timestamp"]),
            )
            recomputed = sha256_hex(canonical_json(body))
            if recomputed != str(row["event_hash"]):
                failures.append(f"hash mismatch at seq {seq}")
            prev_hash = str(row["event_hash"])
            expected_seq += 1

        head = GENESIS_HASH if not rows else prev_hash
        if expected_count is not None and len(rows) != expected_count:
            failures.append(
                f"event count mismatch: expected {expected_count}, found {len(rows)}"
            )
        if expected_head is not None and head != expected_head:
            failures.append("chain head does not match the trusted head")

        result = VerificationResult(
            valid=not failures,
            event_count=len(rows),
            head=head,
            failures=failures,
        )
        if record:
            self.append(
                "audit_verification",
                {
                    "valid": result.valid,
                    "event_count": result.event_count,
                    "failures": result.failures[:5],
                },
            )
        return result

    def head(self) -> str:
        row = self.db.query_one(
            "SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        )
        return GENESIS_HASH if row is None else str(row["event_hash"])

    def count(self) -> int:
        return self.db.count("audit_events")

    def event_types(self) -> Iterable[str]:
        return [str(row["event_type"]) for row in self.db.query(
            "SELECT event_type FROM audit_events ORDER BY seq"
        )]
