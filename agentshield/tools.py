"""Registered mock tools and the guarded host that owns their side effects.

Only :class:`MockToolHost.execute` is reached from the controlled executor.
The ``raw_*`` methods exist solely for the firewall-OFF baseline harness in
:mod:`agentshield.evaluation`; they touch the same isolated mock stores but
apply no policy, which is exactly the condition the evaluation measures.

No tool performs real I/O: reads come from ``sandbox_files``, messages are
written to ``mock_outbox`` and transfers to ``mock_transfers``, all in SQLite.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from .db import Database
from .models import DataClassification, ToolCallRequest, canonical_json, sha256_hex

#: E-mail domains treated as inside the organisation.
INTERNAL_DOMAINS: frozenset[str] = frozenset({"corp.example"})

#: Destinations explicitly approved to receive restricted data.
APPROVED_DESTINATIONS: frozenset[str] = frozenset({"vault.corp.example"})


def is_internal_destination(
    destination: str | None, internal_domains: Iterable[str] = INTERNAL_DOMAINS
) -> bool:
    """True when *destination* is an e-mail address in an internal domain."""
    if not destination or "@" not in destination:
        return False
    domain = destination.rsplit("@", 1)[1].strip().lower()
    return domain in {d.lower() for d in internal_domains}


def is_approved_destination(
    destination: str | None,
    internal_domains: Iterable[str] = INTERNAL_DOMAINS,
    approved_destinations: Iterable[str] = APPROVED_DESTINATIONS,
) -> bool:
    """True when *destination* may receive restricted data.

    Internal recipients are approved by definition; external destinations must
    appear explicitly in ``approved_destinations``.
    """
    if not destination:
        return False
    if is_internal_destination(destination, internal_domains):
        return True
    approved = {d.strip().lower() for d in approved_destinations}
    return destination.strip().lower() in approved


def is_safe_resource_path(path: str | None) -> bool:
    """Reject absolute-escape and traversal attempts before any lookup."""
    if not path or not isinstance(path, str):
        return False
    if not path.startswith("/"):
        return False
    return ".." not in path.split("/")


class ToolExecutionError(Exception):
    """A tool refused to run. Carries a machine-readable reason code."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        super().__init__(detail or reason_code)
        self.reason_code = reason_code
        self.detail = detail or reason_code


@dataclass(frozen=True)
class ToolSpec:
    """Declarative description of a registered tool."""

    name: str
    operations: frozenset[str]
    required_args: dict[str, tuple[str, ...]]
    description: str


TOOL_REGISTRY: dict[str, ToolSpec] = {
    "file_tool": ToolSpec(
        name="file_tool",
        operations=frozenset({"read"}),
        required_args={"read": ("path",)},
        description="Read a file from the mock agent sandbox.",
    ),
    "email_tool": ToolSpec(
        name="email_tool",
        operations=frozenset({"send"}),
        required_args={"send": ("recipient", "subject", "body")},
        description="Write a message to the mock outbox (no real e-mail is sent).",
    ),
    "transfer_tool": ToolSpec(
        name="transfer_tool",
        operations=frozenset({"transfer"}),
        required_args={"transfer": ("resource", "destination")},
        description="Copy a sandbox resource to a destination record.",
    ),
}


@dataclass
class ToolResult:
    """Outcome of a guarded tool invocation."""

    ok: bool
    summary: str
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class MockToolHost:
    """Owns the mock side-effect stores and the guarded execution entry point."""

    def __init__(
        self,
        db: Database,
        internal_domains: Iterable[str] = INTERNAL_DOMAINS,
        approved_destinations: Iterable[str] = APPROVED_DESTINATIONS,
    ) -> None:
        self.db = db
        self.internal_domains = tuple(internal_domains)
        self.approved_destinations = tuple(approved_destinations)

    # -- raw baseline primitives (firewall OFF only) ------------------------
    def raw_read(self, path: str) -> str | None:
        row = self.db.query_one(
            "SELECT content FROM sandbox_files WHERE path = ?", (path,)
        )
        return None if row is None else str(row["content"])

    def raw_send(
        self,
        recipient: str,
        subject: str,
        body: str,
        actor_id: str = "baseline",
        session_id: str = "baseline",
    ) -> str:
        message_id = "msg_" + sha256_hex(
            canonical_json(
                {
                    "actor_id": actor_id,
                    "body": body,
                    "recipient": recipient,
                    "session_id": session_id,
                    "subject": subject,
                }
            )
        )[:32]
        self.db.execute(
            "INSERT OR IGNORE INTO mock_outbox "
            "(message_id, recipient, subject, body, actor_id, session_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                message_id,
                recipient,
                subject,
                body,
                actor_id,
                session_id,
                _now(),
            ),
        )
        return message_id

    def raw_transfer(
        self,
        resource: str,
        destination: str,
        actor_id: str = "baseline",
        session_id: str = "baseline",
    ) -> str:
        row = self.db.query_one(
            "SELECT classification FROM sandbox_files WHERE path = ?", (resource,)
        )
        if row is None:
            raise ToolExecutionError("resource_not_found", resource)
        transfer_id = "trf_" + uuid.uuid4().hex
        self.db.execute(
            "INSERT INTO mock_transfers "
            "(transfer_id, resource, destination, classification, actor_id, session_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                transfer_id,
                resource,
                destination,
                str(row["classification"]),
                actor_id,
                session_id,
                _now(),
            ),
        )
        return transfer_id

    # -- guarded path (firewall ON) ----------------------------------------
    def execute(self, request: ToolCallRequest) -> ToolResult:
        """Invoke a registered tool. This is the only guarded entry point."""
        spec = TOOL_REGISTRY.get(request.tool_name)
        if spec is None:
            raise ToolExecutionError("unknown_tool", request.tool_name)
        if request.operation not in spec.operations:
            raise ToolExecutionError(
                "unsupported_operation",
                f"{request.tool_name} does not support {request.operation}",
            )
        required = spec.required_args.get(request.operation, ())
        for key in required:
            value = request.arguments.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ToolExecutionError("invalid_request", f"missing argument: {key}")

        if request.operation == "read":
            return self._read(request)
        if request.operation == "send":
            return self._send(request)
        if request.operation == "transfer":
            return self._transfer(request)
        raise ToolExecutionError("unsupported_operation", request.operation)

    def _read(self, request: ToolCallRequest) -> ToolResult:
        path = request.arguments["path"]
        if not is_safe_resource_path(path):
            raise ToolExecutionError("invalid_request", f"unsafe resource path: {path}")
        row = self.db.query_one(
            "SELECT content, classification FROM sandbox_files WHERE path = ?", (path,)
        )
        if row is None:
            raise ToolExecutionError("resource_not_found", path)
        content = str(row["content"])
        return ToolResult(
            ok=True,
            summary=f"read {len(content)} bytes from {path}",
            output={
                "path": path,
                "classification": str(row["classification"]),
                "content": content,
            },
        )

    def _send(self, request: ToolCallRequest) -> ToolResult:
        recipient = request.arguments["recipient"]
        subject = request.arguments["subject"]
        body = request.arguments["body"]
        # Defence in depth, mirroring _transfer: a protected classification may
        # only leave for an approved destination, even if a caller reached this
        # host without passing the gateway's provenance checks.
        if request.data_classification in (
            DataClassification.RESTRICTED,
            DataClassification.CONFIDENTIAL,
        ) and not is_approved_destination(
            recipient, self.internal_domains, self.approved_destinations
        ):
            raise ToolExecutionError(
                (
                    "restricted_data_transfer"
                    if request.data_classification is DataClassification.RESTRICTED
                    else "confidential_data_transfer"
                ),
                f"{request.data_classification.value} -> {recipient}",
            )
        message_id = self.raw_send(
            recipient=recipient,
            subject=subject,
            body=body,
            actor_id=request.actor_id,
            session_id=request.session_id,
        )
        return ToolResult(
            ok=True,
            summary=f"queued mock message {message_id} to {recipient}",
            output={"message_id": message_id, "recipient": recipient},
        )

    def _transfer(self, request: ToolCallRequest) -> ToolResult:
        resource = request.arguments["resource"]
        destination = request.arguments["destination"]
        row = self.db.query_one(
            "SELECT classification FROM sandbox_files WHERE path = ?", (resource,)
        )
        if row is None:
            raise ToolExecutionError("resource_not_found", resource)
        # Defence in depth: the tool re-checks the ground-truth classification
        # stored with the data, not the one the caller claimed.
        classification = str(row["classification"])
        if classification == "restricted" and not is_approved_destination(
            destination, self.internal_domains, self.approved_destinations
        ):
            raise ToolExecutionError(
                "restricted_data_transfer", f"{resource} -> {destination}"
            )
        transfer_id = self.raw_transfer(
            resource=resource,
            destination=destination,
            actor_id=request.actor_id,
            session_id=request.session_id,
        )
        return ToolResult(
            ok=True,
            summary=f"transferred {resource} to {destination}",
            output={
                "transfer_id": transfer_id,
                "resource": resource,
                "destination": destination,
                "classification": classification,
            },
        )


def _now() -> float:
    import time

    return time.time()
