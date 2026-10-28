"""Deterministic, declarative, fail-closed policy engine.

Rules are ordered data evaluated first-match-wins, so the same request always
produces the same verdict. The engine only *decides*: nothing here executes a
tool. Enforcement belongs to :class:`agentshield.gateway.Gateway` and
:class:`agentshield.executor.ControlledExecutor`.

Deny rules are evaluated before any allow rule, so one action can never be
simultaneously eligible for ``DENY`` and ``APPROVAL``, and a hard denial can
never be reached by a later approval-granting rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .models import (
    CLASSIFICATION_SEVERITY,
    POLICY_VERSION,
    DataClassification,
    Decision,
    PolicyOutcome,
    ToolCallRequest,
)
from .provenance import (
    ProvenanceContext,
    effective_classification as derive_effective_classification,
)
from .tools import (
    APPROVED_DESTINATIONS,
    INTERNAL_DOMAINS,
    TOOL_REGISTRY,
    is_approved_destination,
    is_internal_destination,
)
from .validator import ValidationResult

#: Reason codes that human approval can never override.
HARD_DENY_REASON_CODES: frozenset[str] = frozenset(
    {
        "confidential_data_transfer",
        "destination_not_approved",
        "inconsistent_provenance",
        "invalid_provenance",
        "invalid_request",
        "missing_provenance",
        "no_matching_policy",
        "policy_version_mismatch",
        "resource_out_of_scope",
        "restricted_data_transfer",
        "restricted_resource",
        "unknown_tool",
        "unsupported_operation",
    }
)


@dataclass(frozen=True)
class PolicyConfig:
    """Reviewable policy parameters. All values are plain data."""

    internal_domains: tuple[str, ...] = tuple(sorted(INTERNAL_DOMAINS))
    approved_destinations: tuple[str, ...] = tuple(sorted(APPROVED_DESTINATIONS))
    public_roots: tuple[str, ...] = ("/public/",)
    internal_roots: tuple[str, ...] = ("/internal/",)
    restricted_roots: tuple[str, ...] = ("/secret/", "/private/")
    require_approval_for_external_send: bool = True

    @property
    def readable_roots(self) -> tuple[str, ...]:
        return self.public_roots + self.internal_roots


@dataclass
class EvalContext:
    """Everything a rule predicate may look at."""

    request: ToolCallRequest
    config: PolicyConfig
    validation: ValidationResult | None = None
    provenance: ProvenanceContext | None = None

    @property
    def operation(self) -> str:
        return self.request.operation

    @property
    def path(self) -> str:
        return self.request.resource or ""

    @property
    def destination(self) -> str | None:
        return self.request.destination

    @property
    def classification(self) -> DataClassification:
        return self.request.data_classification

    @property
    def is_restricted(self) -> bool:
        return self.classification is DataClassification.RESTRICTED

    @property
    def provenance_refs(self):
        return () if self.provenance is None else self.provenance.refs

    @property
    def effective_classification(self) -> DataClassification:
        """Declared classification raised by any carried provenance record."""
        return derive_effective_classification(
            self.classification, self.provenance_refs
        )

    @property
    def has_invalid_provenance(self) -> bool:
        return self.provenance is not None and not self.provenance.valid

    @property
    def has_unaccounted_confidential_sources(self) -> bool:
        return self.provenance is not None and bool(
            self.provenance.unaccounted_sources
        )


@dataclass(frozen=True)
class Rule:
    """A single declarative policy rule."""

    name: str
    decision: Decision
    reason_code: str
    explanation: str
    when: Callable[[EvalContext], bool]


def build_rules(config: PolicyConfig) -> list[Rule]:
    """Ordered rule set: every deny rule precedes every allow rule."""

    def denied_transfer(ctx: EvalContext) -> bool:
        return (
            ctx.operation in {"send", "transfer"}
            and ctx.is_restricted
            and not is_approved_destination(
                ctx.destination,
                config.internal_domains,
                config.approved_destinations,
            )
        )

    def unapproved_transfer(ctx: EvalContext) -> bool:
        return ctx.operation == "transfer" and not is_approved_destination(
            ctx.destination,
            config.internal_domains,
            config.approved_destinations,
        )

    def outbound(ctx: EvalContext) -> bool:
        return ctx.operation in {"send", "transfer"}

    def provenance_downgraded(ctx: EvalContext) -> bool:
        """Declared classification is milder than what the refs prove."""
        if ctx.provenance is None or not ctx.provenance.valid or not ctx.provenance_refs:
            return False
        ref_severity = max(
            CLASSIFICATION_SEVERITY[DataClassification(record.classification)]
            for record in ctx.provenance_refs
        )
        return (
            CLASSIFICATION_SEVERITY[ctx.classification] < ref_severity
        )

    def outbound_without_provenance(ctx: EvalContext) -> bool:
        """Outbound action carrying no provenance while claiming confidential,
        or leaving confidential sources of its session unaccounted for."""
        if not outbound(ctx) or ctx.provenance is None or not ctx.provenance.valid:
            return False
        if ctx.has_unaccounted_confidential_sources:
            return True
        return (
            ctx.effective_classification is DataClassification.CONFIDENTIAL
            and not ctx.provenance_refs
        )

    def confidential_flow_to_unapproved(ctx: EvalContext) -> bool:
        return (
            outbound(ctx)
            and ctx.effective_classification is DataClassification.CONFIDENTIAL
            and not is_approved_destination(
                ctx.destination,
                config.internal_domains,
                config.approved_destinations,
            )
        )

    def confidential_outbound(ctx: EvalContext) -> bool:
        return (
            outbound(ctx)
            and ctx.effective_classification is DataClassification.CONFIDENTIAL
        )

    return [
        # ---- hard denials -------------------------------------------------
        Rule(
            name="policy-version",
            decision=Decision.DENY,
            reason_code="policy_version_mismatch",
            explanation="Request was evaluated against a different policy version.",
            when=lambda ctx: ctx.request.policy_version != POLICY_VERSION,
        ),
        Rule(
            name="unknown-tool",
            decision=Decision.DENY,
            reason_code="unknown_tool",
            explanation="Tool is not in the registered tool registry.",
            when=lambda ctx: ctx.request.tool_name not in TOOL_REGISTRY,
        ),
        Rule(
            name="unsupported-operation",
            decision=Decision.DENY,
            reason_code="unsupported_operation",
            explanation="Operation is not declared by the registered tool.",
            when=lambda ctx: ctx.request.operation
            not in TOOL_REGISTRY[ctx.request.tool_name].operations,
        ),
        Rule(
            name="read-restricted-resource",
            decision=Decision.DENY,
            reason_code="restricted_resource",
            explanation="Reading restricted data is prohibited regardless of approver.",
            when=lambda ctx: ctx.operation == "read"
            and (
                ctx.is_restricted
                or ctx.path.startswith(config.restricted_roots)
            ),
        ),
        Rule(
            name="restricted-data-to-unapproved-destination",
            decision=Decision.DENY,
            reason_code="restricted_data_transfer",
            explanation="Restricted data may only go to an approved destination.",
            when=denied_transfer,
        ),
        Rule(
            name="transfer-to-unapproved-destination",
            decision=Decision.DENY,
            reason_code="destination_not_approved",
            explanation="Transfer destination is not on the approved list.",
            when=unapproved_transfer,
        ),
        Rule(
            name="read-out-of-scope",
            decision=Decision.DENY,
            reason_code="resource_out_of_scope",
            explanation="Resource lies outside the public and internal read scope.",
            when=lambda ctx: ctx.operation == "read"
            and not ctx.path.startswith(config.readable_roots),
        ),
        Rule(
            name="invalid-provenance",
            decision=Decision.DENY,
            reason_code="invalid_provenance",
            explanation=(
                "A declared provenance reference could not be resolved in this "
                "session; outbound data flow fails closed."
            ),
            when=lambda ctx: ctx.has_invalid_provenance,
        ),
        Rule(
            name="inconsistent-provenance",
            decision=Decision.DENY,
            reason_code="inconsistent_provenance",
            explanation=(
                "The declared classification is milder than the classification "
                "carried by the attached provenance records."
            ),
            when=provenance_downgraded,
        ),
        Rule(
            name="outbound-without-provenance",
            decision=Decision.DENY,
            reason_code="missing_provenance",
            explanation=(
                "A protected outbound action must carry provenance covering the "
                "confidential sources of its session."
            ),
            when=outbound_without_provenance,
        ),
        Rule(
            name="confidential-data-to-unapproved-destination",
            decision=Decision.DENY,
            reason_code="confidential_data_transfer",
            explanation=(
                "Confidential data may not flow to a destination that is not "
                "approved to receive it."
            ),
            when=confidential_flow_to_unapproved,
        ),
        # ---- approvals ----------------------------------------------------
        Rule(
            name="confidential-outbound",
            decision=Decision.APPROVAL,
            reason_code="confidential_transfer",
            explanation=(
                "Confidential data bound to an approved destination requires "
                "human approval."
            ),
            when=confidential_outbound,
        ),
        Rule(
            name="external-send",
            decision=(
                Decision.APPROVAL
                if config.require_approval_for_external_send
                else Decision.ALLOW
            ),
            reason_code="external_send",
            explanation=(
                "External recipients require a human approval."
                if config.require_approval_for_external_send
                else "External recipients are permitted by configuration."
            ),
            when=lambda ctx: ctx.operation == "send"
            and not is_internal_destination(ctx.destination, config.internal_domains),
        ),
        Rule(
            name="restricted-transfer-approved-destination",
            decision=Decision.APPROVAL,
            reason_code="restricted_transfer",
            explanation="Restricted data to an approved destination requires approval.",
            when=lambda ctx: ctx.operation == "transfer" and ctx.is_restricted,
        ),
        # ---- allows -------------------------------------------------------
        Rule(
            name="public-read",
            decision=Decision.ALLOW,
            reason_code="public_read",
            explanation="Public sandbox files may be read freely.",
            when=lambda ctx: ctx.operation == "read"
            and ctx.path.startswith(config.public_roots),
        ),
        Rule(
            name="confidential-read",
            decision=Decision.ALLOW,
            reason_code="confidential_read",
            explanation=(
                "Confidential files in readable roots may be read; their "
                "provenance then constrains every later outbound action of the "
                "session."
            ),
            when=lambda ctx: ctx.operation == "read"
            and ctx.effective_classification is DataClassification.CONFIDENTIAL,
        ),
        Rule(
            name="internal-read",
            decision=Decision.ALLOW,
            reason_code="internal_resource",
            explanation="Internal, non-restricted files may be read.",
            when=lambda ctx: ctx.operation == "read",
        ),
        Rule(
            name="internal-send",
            decision=Decision.ALLOW,
            reason_code="internal_recipient",
            explanation="Internal recipients are approved by policy.",
            when=lambda ctx: ctx.operation == "send"
            and is_internal_destination(ctx.destination, config.internal_domains),
        ),
        Rule(
            name="approved-destination-transfer",
            decision=Decision.ALLOW,
            reason_code="approved_destination",
            explanation="Non-restricted data may move to an approved destination.",
            when=lambda ctx: ctx.operation == "transfer",
        ),
    ]


@dataclass
class PolicyEngine:
    """Evaluates a validated request against the ordered rule set."""

    config: PolicyConfig = field(default_factory=PolicyConfig)
    policy_version: str = POLICY_VERSION

    def __post_init__(self) -> None:
        self.rules: list[Rule] = build_rules(self.config)

    def evaluate(
        self,
        request: ToolCallRequest | None,
        validation: ValidationResult | None = None,
        provenance: ProvenanceContext | None = None,
    ) -> PolicyOutcome:
        """Decide a request. ``request`` is ``None`` when validation failed,
        in which case the verdict is derived from the validation failure."""
        if validation is not None and not validation.ok:
            return PolicyOutcome(
                decision=Decision.DENY,
                reason_code=validation.reason_code or "invalid_request",
                policy_version=self.policy_version,
                rule_name="request-valid",
                explanation=validation.detail or "Request failed validation.",
            )

        if request is None:  # pragma: no cover - defensive
            return PolicyOutcome(
                decision=Decision.DENY,
                reason_code="invalid_request",
                policy_version=self.policy_version,
                rule_name="request-valid",
                explanation="Request failed validation.",
            )

        context = EvalContext(
            request=request,
            config=self.config,
            validation=validation,
            provenance=provenance,
        )
        for rule in self.rules:
            if rule.when(context):
                return PolicyOutcome(
                    decision=rule.decision,
                    reason_code=rule.reason_code,
                    policy_version=self.policy_version,
                    rule_name=rule.name,
                    explanation=rule.explanation,
                )

        # Fail closed: an action no rule matches is denied.
        return PolicyOutcome(
            decision=Decision.DENY,
            reason_code="no_matching_policy",
            policy_version=self.policy_version,
            rule_name="default-deny",
            explanation="No policy rule permits this action.",
        )


def is_hard_denial(outcome: PolicyOutcome) -> bool:
    """True when approval may never override this verdict."""
    return (
        outcome.decision is Decision.DENY
        and outcome.reason_code in HARD_DENY_REASON_CODES
    )
