"""Advisory classifier: predictions, abstention, metrics and its lack of authority."""

from __future__ import annotations

import pytest

from agentshield.classifier import (
    CONFIDENCE_THRESHOLD,
    MARGIN_THRESHOLD,
    PolicyClassifier,
    default_classifier,
    request_tokens,
)
from tests.conftest import public_read, restricted_read


@pytest.fixture(scope="module")
def classifier() -> PolicyClassifier:
    return PolicyClassifier()


def _payload(**overrides):
    base = {
        "tool_name": "email_tool",
        "operation": "send",
        "resource": None,
        "destination": "partner@example.com",
        "data_classification": "internal",
        "provenance": [],
    }
    base.update(overrides)
    return base


def test_fixture_metrics_are_internally_consistent(classifier):
    metrics = classifier.metrics()
    assert metrics["dataset_size"] == 120
    assert metrics["train_size"] + metrics["test_size"] == metrics["dataset_size"]
    assert metrics["test_size"] == sum(
        sum(row.values()) for row in metrics["confusion_matrix"].values()
    )
    assert 0.0 <= metrics["abstention_rate"] <= 1.0
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert metrics["false_positive"] >= 0
    assert metrics["false_negative"] >= 0
    # Guards a fixture/featurizer mismatch that made every sample abstain.
    assert metrics["abstention_rate"] < 0.5
    assert metrics["macro_f1"] is not None and metrics["macro_f1"] > 0.5
    assert metrics["per_class"]["allow"]["f1"] is not None
    assert metrics["policy_version"] == "2026-10-27-v1"
    assert metrics["evaluation_scope"].startswith("held-out split")


def test_classifier_is_deterministic(classifier):
    payload = _payload(destination="leak@external.example", data_classification="confidential")
    first = classifier.predict(payload)
    second = classifier.predict(payload)
    assert first.to_dict() == second.to_dict()
    fresh = PolicyClassifier()
    assert fresh.metrics() == classifier.metrics()


def test_known_safe_and_unsafe_requests(classifier):
    safe = classifier.predict(
        _payload(
            tool_name="file_tool",
            operation="read",
            resource="/public/meeting.txt",
            destination=None,
            data_classification="public",
        )
    )
    assert safe.abstained is False and safe.label == "allow"

    unsafe = classifier.predict(
        _payload(
            tool_name="file_tool",
            operation="read",
            resource="/secret/acquisition.txt",
            destination=None,
            data_classification="restricted",
        )
    )
    assert unsafe.abstained is False and unsafe.label == "deny"

    approval = classifier.predict(_payload())
    assert approval.label == "approval"


def test_unfamiliar_requests_abstain(classifier):
    prediction = classifier.predict(
        _payload(
            tool_name="quantum_tool",
            operation="entangle",
            destination="unknown",
            data_classification="internal",
        )
    )
    assert prediction.abstained is True
    assert prediction.decision_hint == "abstain"
    assert prediction.reason is not None


def test_thresholds_are_reported_with_the_prediction(classifier):
    prediction = classifier.predict(_payload()).to_dict()
    assert prediction["threshold"] == CONFIDENCE_THRESHOLD
    assert prediction["margin_threshold"] == MARGIN_THRESHOLD
    assert 0.0 <= prediction["confidence"] <= 1.0
    assert "advisory only" in prediction["authority"]
    assert set(prediction["probabilities"]) == {"allow", "approval", "ambiguous", "deny"}


def test_tokens_do_not_include_message_bodies():
    tokens = request_tokens(
        {
            "tool_name": "email_tool",
            "operation": "send",
            "destination": "partner@example.com",
            "data_classification": "internal",
            "arguments": {"body": "TOP-SECRET-CANARY", "subject": "hello"},
            "provenance": [],
        }
    )
    assert all("CANARY" not in token for token in tokens)


def test_advisory_is_audited_next_to_the_decision(gateway):
    response = gateway.submit(restricted_read())
    assert response["status"] == "DENIED"

    event = next(
        event
        for event in reversed(gateway.audit.events())
        if event["event_type"] == "policy_decision"
    )
    payload = event["payload"]
    assert payload["final_decision"] == "DENY"
    advisory = payload["classifier"]
    assert advisory["model_version"] == "policy-classifier-tfidf-lr-v1"
    assert advisory["policy_version"] == response["policy_version"]
    assert advisory["authority"].startswith("advisory only")


class _AllowEverything:
    """Hostile stub: the gateway must ignore it for authorization purposes."""

    def advisory(self, payload):  # noqa: ANN001 - test stub
        return {
            "model_version": "stub",
            "prediction": "allow",
            "decision_hint": "allow",
            "confidence": 1.0,
            "abstained": False,
        }

    def describe(self):
        return {}

    def metrics(self):
        return {}


def test_confident_allow_prediction_cannot_authorize(db, clock):
    from agentshield.gateway import Gateway

    gateway = Gateway(db, clock=clock, classifier=_AllowEverything())
    response = gateway.submit(restricted_read())
    assert response["status"] == "DENIED"
    assert response["reason_code"] == "restricted_resource"
    assert gateway.db.count("mock_outbox") == 0
    assert gateway.db.count("execution_ledger") == 0


def test_default_classifier_is_cached():
    assert default_classifier() is default_classifier()


def test_public_read_payload_shape_matches_gateway_request(gateway):
    """The advisory input uses the same field names the gateway persists."""
    payload = public_read()
    advisory = default_classifier().advisory(payload)
    assert advisory is not None
    assert advisory["prediction"] in {"allow", "approval", "ambiguous", "deny"}
