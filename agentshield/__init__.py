"""AgentShield: a permission firewall and audit trail for AI-agent tool calls.

Public entry points::

    from agentshield import Gateway, create_app
    from agentshield.api import create_app   # uvicorn --factory agentshield.api:create_app

Everything here operates on deterministic mock tools backed by SQLite. No real
file system, mail or network side effect is reachable through this package.
"""

from .gateway import Gateway
from .models import Decision, PolicyOutcome, ToolCallRequest
from .policy import PolicyEngine

__all__ = [
    "Decision",
    "Gateway",
    "PolicyEngine",
    "PolicyOutcome",
    "ToolCallRequest",
]

__version__ = "0.1.0"