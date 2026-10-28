"""Provenance records: explicit, server-side links from data access to later
outbound actions.

A provenance id is minted **only** by the trusted host, **only** after a read
has actually executed, and always carries the *ground-truth* classification
taken from ``sandbox_files`` - never the classification the client claimed in
the request.

Resolution is session-scoped: a reference only resolves inside the session that
produced it, so one session's evidence cannot be borrowed by another. Outbound
actions (``send``/ ``transfer``) that leave confidential sources of their
session unaccounted for fail closed in the policy engine.

This module owns no policy decisions; it only records, resolves and ranks.
Enforcement belongs to :mod:`agentshield.policy` and
:class:`agentshield.gateway.Gateway`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Sequence

from .db import Database
from .models import (
    CLASSIFICATION_SEVERITY,
    DataClassification,
    ToolCallRequest,
    canonical_json,
    sha256_hex,
)

#: Prefix so provenance ids are recognizable in logs and responses.
PROVENANCE_PREFIX = "prov_"

#: Operations whose data flow leaves the current host and therefore must
#: account for the confidential sources of their session.
OUTBOUND_OPERATIONS = frozenset({"send", "transfer"})


@dataclass(frozen=True)
class ProvenanceRecord:
    """One trusted observation: this session read this source, classified X."""

    prov_id: str
    source_path: str
    classification: str
    session_id: str
    actor_id: str
    request_id: str
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "prov_id": self.prov_id,
            "source_path": self.source_path,
            "classification": self.classification,
            "session_id": self.session_id,
            "actor_id": self.actor_id,
            "request_id": self.request_id,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class ProvenanceContext:
    """Resolution result handed to the policy engine for one request."""

    refs: tuple[ProvenanceRecord, ...] = ()
    #: Set when any declared reference failed to resolve. Fail closed.
    invalid_reason: str | None = None
    #: Confidential sources read in this session with no covering reference.
    unaccounted_sources: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return self.invalid_reason is None


def effective_classification(
    declared: DataClassification, refs: Sequence[ProvenanceRecord]
) -> DataClassification:
    """Most restrictive classification among the declared one and all refs.

    Provenance can only ever *raise* the classification policy applies - a
    client claiming ``public`` while carrying a ``confidential`` record is
    judged as confidential.
    """
    best = declared
    best_severity = CLASSIFICATION_SEVERITY[declared]
    for record in refs:
        try:
            cls = DataClassification(record.classification)
        except ValueError:  # pragma: no cover - store constrains the values
            return DataClassification.RESTRICTED
        severity = CLASSIFICATION_SEVERITY[cls]
        if severity > best_severity:
            best, best_severity = cls, severity
    return best


def _row_to_record(row: Any) -> ProvenanceRecord:
    return ProvenanceRecord(
        prov_id=str(row["prov_id"]),
        source_path=str(row["source_path"]),
        classification=str(row["classification"]),
        session_id=str(row["session_id"]),
        actor_id=str(row["actor_id"]),
        request_id=str(row["request_id"]),
        created_at=float(row["created_at"]),
    )


class ProvenanceService:
    """Mints provenance ids for executed reads and resolves them later."""

    def __init__(self, db: Database, clock: "callable" = time.time) -> None:
        self.db = db
        self.clock = clock

    # -- minting (trusted side only) ---------------------------------------
    def record_from_read(
        self, request: ToolCallRequest, output: dict[str, Any]
    ) -> ProvenanceRecord:
        """Persist provenance for one executed read.

        ``output['classification']`` is the ground truth the tool read from
        ``sandbox_files``. Callers must fail closed if this raises: content was
        read, so without a record the data-flow checks could not see it.
        """
        source_path = str(output.get("path") or request.resource or "")
        classification = str(output.get("classification") or "")
        if not source_path or not classification:
            raise ValueError("read output is missing provenance metadata")
        DataClassification(classification)  # fail closed on unknown values

        prov_id = PROVENANCE_PREFIX + sha256_hex(
            canonical_json(
                {
                    "path": source_path,
                    "request_id": request.request_id,
                    "session_id": request.session_id,
                }
            )
        )[:32]
        record = ProvenanceRecord(
            prov_id=prov_id,
            source_path=source_path,
            classification=classification,
            session_id=request.session_id,
            actor_id=request.actor_id,
            request_id=request.request_id,
            created_at=float(self.clock()),
        )
        self.db.execute(
            "INSERT OR REPLACE INTO provenance_records "
            "(prov_id, source_path, classification, session_id, actor_id, "
            " request_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                record.prov_id,
                record.source_path,
                record.classification,
                record.session_id,
                record.actor_id,
                record.request_id,
                record.created_at,
            ),
        )
        return record

    # -- resolution (request side) ------------------------------------------
    def context_for(self, request: ToolCallRequest) -> ProvenanceContext:
        """Resolve a request's declared references within its session.

        An unresolvable or foreign-session reference invalidates the whole
        context (fail closed). Confidential sources previously read in this
        session that no resolved reference covers are reported as unaccounted.
        """
        refs: list[ProvenanceRecord] = []
        invalid_reason: str | None = None

        for prov_id in request.provenance:
            row = self.db.query_one(
                "SELECT * FROM provenance_records WHERE prov_id = ? AND session_id = ?",
                (prov_id, request.session_id),
            )
            if row is None:
                invalid_reason = (
                    f"unknown provenance reference '{prov_id}' for session "
                    f"'{request.session_id}'"
                )
                refs = []
                break
            refs.append(_row_to_record(row))

        unaccounted: tuple[str, ...] = ()
        if request.operation in OUTBOUND_OPERATIONS and invalid_reason is None:
            covered = {record.source_path for record in refs}
            rows = self.db.query(
                "SELECT DISTINCT source_path FROM provenance_records "
                "WHERE session_id = ? AND classification = ?",
                (request.session_id, DataClassification.CONFIDENTIAL.value),
            )
            unaccounted = tuple(
                sorted(
                    str(row["source_path"])
                    for row in rows
                    if str(row["source_path"]) not in covered
                )
            )

        return ProvenanceContext(
            refs=tuple(refs),
            invalid_reason=invalid_reason,
            unaccounted_sources=unaccounted,
        )
