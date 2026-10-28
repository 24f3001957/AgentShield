"""Validated tool-call schemas, structured decisions and canonicalization.

Deterministic canonical JSON is the foundation of every security binding in
AgentShield: approval fingerprints, audit hashes and authorization tokens all
serialize payloads through :func:`canonical_json`, which sorts keys and omits
whitespace so the same logical payload always produces the same bytes.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

#: Version of the canonicalization scheme used for fingerprints.
CANONICALIZATION_VERSION = "v1"

#: Version of the declarative policy set in :mod:`agentshield.policy`.
POLICY_VERSION = "2026-10-27-v1"

#: Previous-hash value of the first audit event.
GENESIS_HASH = "0" * 64


class Decision(str, Enum):
    """Structured policy outcome."""

    ALLOW = "ALLOW"
    APPROVAL = "APPROVAL"
    DENY = "DENY"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


#: Severity ordering used by data-flow decisions. A more severe classification
#: always wins when declared metadata and provenance records disagree.
CLASSIFICATION_SEVERITY: dict[DataClassification, int] = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.RESTRICTED: 3,
}


def canonical_json(payload: Any) -> str:
    """Serialize *payload* to deterministic JSON bytes-as-text."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_hex(text: str) -> str:
    """Return the lowercase hex SHA-256 digest of *text* (UTF-8)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_value(value: Any) -> Any:
    """Trim surrounding whitespace from strings, recursively."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return {key: normalize_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_value(item) for item in value]
    return value


def normalize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Normalize tool-call arguments before they are bound into a fingerprint."""
    return {str(key): normalize_value(value) for key, value in arguments.items()}


class ToolCallRequest(BaseModel):
    """A proposed tool call submitted by the agent/client.

    ``extra="forbid"`` makes unknown top-level fields a validation failure, so
    a client cannot smuggle an ``approved: true`` flag into the request.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    request_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=64)
    operation: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    resource: str | None = None
    destination: str | None = None
    data_classification: DataClassification = DataClassification.INTERNAL
    provenance: list[str] = Field(default_factory=list, max_length=32)
    policy_version: str = POLICY_VERSION

    @field_validator("provenance")
    @classmethod
    def _provenance_refs_must_be_non_empty_strings(
        cls, value: list[str]
    ) -> list[str]:
        cleaned: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("provenance references must be non-empty strings")
            cleaned.append(item.strip())
        return cleaned

    @field_validator("arguments")
    @classmethod
    def _arguments_must_be_json_serializable(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise ValueError("arguments must be JSON-serializable") from exc
        return value


class PolicyOutcome(BaseModel):
    """Structured verdict: decision, reason code, policy version, explanation."""

    decision: Decision
    reason_code: str
    policy_version: str = POLICY_VERSION
    rule_name: str | None = None
    explanation: str = ""


def action_binding(
    request: ToolCallRequest, policy_version: str = POLICY_VERSION
) -> dict[str, Any]:
    """Authorization-relevant fields of a request, in canonical form.

    Every field listed here is covered by the approval fingerprint: mutating any
    of them after approval invalidates the approval.
    """
    return {
        "actor_id": request.actor_id,
        "arguments": normalize_arguments(request.arguments),
        "canonicalization_version": CANONICALIZATION_VERSION,
        "data_classification": request.data_classification.value,
        "destination": request.destination,
        "operation": request.operation,
        "policy_version": policy_version,
        "provenance": sorted(set(request.provenance)),
        "resource": request.resource,
        "session_id": request.session_id,
        "tool_name": request.tool_name,
    }


def action_fingerprint(
    request: ToolCallRequest, policy_version: str = POLICY_VERSION
) -> str:
    """Stable SHA-256 fingerprint of the authorization-relevant action."""
    return sha256_hex(canonical_json(action_binding(request, policy_version)))


def parse_request(raw: Any) -> ToolCallRequest:
    """Validate raw input into a :class:`ToolCallRequest`.

    Raises ``pydantic.ValidationError`` for malformed payloads; callers map
    that to a ``DENY / invalid_request`` decision.
    """
    if not isinstance(raw, dict):
        raise ValidationError.from_exception_data(
            ToolCallRequest.__name__,
            [{"type": "model_attributes_type", "loc": (), "input": raw}],
        )
    return ToolCallRequest.model_validate(raw)
