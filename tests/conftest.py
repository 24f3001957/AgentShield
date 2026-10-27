"""Shared fixtures: temp databases, an injectable clock, request builders."""

from __future__ import annotations

from typing import Any, Callable

import pytest

from agentshield.db import Database
from agentshield.gateway import Gateway


class FakeClock:
    """Deterministic clock so expiry tests never sleep."""

    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> float:
        self.t += seconds
        return self.t


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def db(tmp_path) -> Database:
    return Database(str(tmp_path / "test.db"))


@pytest.fixture
def gateway(db: Database, clock: FakeClock) -> Gateway:
    return Gateway(db, clock=clock, approval_ttl=300.0, authorization_ttl=300.0)


@pytest.fixture
def make_request() -> Callable[..., dict[str, Any]]:
    """Builder for valid tool-call payloads."""

    counter = {"n": 0}

    def build(**overrides: Any) -> dict[str, Any]:
        counter["n"] += 1
        payload: dict[str, Any] = {
            "request_id": f"req-{counter['n']}",
            "actor_id": "agent-1",
            "session_id": "sess-1",
            "tool_name": "file_tool",
            "operation": "read",
            "arguments": {"path": "/public/meeting.txt"},
            "data_classification": "public",
        }
        payload.update(overrides)
        return payload

    return build


def public_read(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "request_id": "req-public",
        "actor_id": "agent-1",
        "session_id": "sess-1",
        "tool_name": "file_tool",
        "operation": "read",
        "arguments": {"path": "/public/meeting.txt"},
        "data_classification": "public",
    }
    payload.update(overrides)
    return payload


def restricted_read(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "request_id": "req-secret",
        "actor_id": "agent-1",
        "session_id": "sess-1",
        "tool_name": "file_tool",
        "operation": "read",
        "arguments": {"path": "/secret/acquisition.txt"},
        "resource": "/secret/acquisition.txt",
        "data_classification": "restricted",
    }
    payload.update(overrides)
    return payload


def external_send(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "request_id": "req-external",
        "actor_id": "agent-1",
        "session_id": "sess-1",
        "tool_name": "email_tool",
        "operation": "send",
        "arguments": {
            "recipient": "partner@example.com",
            "subject": "Integration window",
            "body": "Live on Thursday.",
        },
        "destination": "partner@example.com",
        "data_classification": "internal",
    }
    payload.update(overrides)
    return payload


def internal_send(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "request_id": "req-internal",
        "actor_id": "agent-1",
        "session_id": "sess-1",
        "tool_name": "email_tool",
        "operation": "send",
        "arguments": {
            "recipient": "alice@corp.example",
            "subject": "Sprint review",
            "body": "Moved to 15:00.",
        },
        "destination": "alice@corp.example",
        "data_classification": "internal",
    }
    payload.update(overrides)
    return payload


def restricted_transfer(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "request_id": "req-transfer",
        "actor_id": "agent-1",
        "session_id": "sess-1",
        "tool_name": "transfer_tool",
        "operation": "transfer",
        "arguments": {
            "resource": "/secret/acquisition.txt",
            "destination": "cloud.external.example",
        },
        "resource": "/secret/acquisition.txt",
        "destination": "cloud.external.example",
        "data_classification": "restricted",
    }
    payload.update(overrides)
    return payload