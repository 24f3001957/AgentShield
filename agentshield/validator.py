"""Request validation: schema, tool registry, argument and resource checks.

Validation runs before policy evaluation. Failures are returned as a
``DENY``-shaped result carrying a reason code (``unknown_tool``,
``invalid_request``, ``unsupported_operation``) so malformed input never
reaches the policy engine as a half-formed action, and never reaches a tool.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from .models import ToolCallRequest, parse_request
from .tools import TOOL_REGISTRY, is_safe_resource_path


@dataclass
class ValidationResult:
    ok: bool
    reason_code: str | None = None
    detail: str | None = None
    request: ToolCallRequest | None = None


def validate(raw: Any) -> ValidationResult:
    """Validate raw client input into a normalized, registry-backed request."""
    try:
        request = parse_request(raw)
    except ValidationError as exc:
        return ValidationResult(
            ok=False,
            reason_code="invalid_request",
            detail=f"schema validation failed: {exc.errors()[0].get('loc', ())}",
        )

    spec = TOOL_REGISTRY.get(request.tool_name)
    if spec is None:
        return ValidationResult(
            ok=False,
            reason_code="unknown_tool",
            detail=f"tool '{request.tool_name}' is not registered",
        )

    if request.operation not in spec.operations:
        return ValidationResult(
            ok=False,
            reason_code="unsupported_operation",
            detail=f"{request.tool_name} does not support operation "
            f"'{request.operation}'",
        )

    required = spec.required_args.get(request.operation, ())
    for key in required:
        value = request.arguments.get(key)
        if not isinstance(value, str) or not value.strip():
            return ValidationResult(
                ok=False,
                reason_code="invalid_request",
                detail=f"missing or empty required argument '{key}'",
            )

    mismatch = _derive_context(request)
    if mismatch is not None:
        return ValidationResult(
            ok=False, reason_code="invalid_request", detail=mismatch
        )

    return ValidationResult(ok=True, request=request)


def _derive_context(request: ToolCallRequest) -> str | None:
    """Fill ``resource``/``destination`` from arguments, or reject mismatches.

    Deriving one source of truth keeps policy evaluation unambiguous: the
    resource the policy judges is always the resource the tool will act on.
    """
    args = request.arguments

    if request.operation == "read":
        path = args.get("path")
        if not is_safe_resource_path(path if isinstance(path, str) else None):
            return f"unsafe resource path: {path!r}"
        if request.resource is not None and request.resource != path:
            return "resource does not match arguments.path"
        request.resource = path
        return None

    if request.operation == "send":
        recipient = args["recipient"]
        if request.destination is not None and request.destination != recipient:
            return "destination does not match arguments.recipient"
        request.destination = recipient
        return None

    if request.operation == "transfer":
        resource = args["resource"]
        destination = args["destination"]
        if not is_safe_resource_path(resource):
            return f"unsafe resource path: {resource!r}"
        if request.resource is not None and request.resource != resource:
            return "resource does not match arguments.resource"
        if request.destination is not None and request.destination != destination:
            return "destination does not match arguments.destination"
        request.resource = resource
        request.destination = destination
        return None

    return f"unsupported operation '{request.operation}'"
