"""Provenance-aware data-flow regression tests (Phase 3 of the brief).

Covers: metadata carried through the workflow, unauthorized external flow
denied, no outbox side effect on denial, public workflows unaffected, missing /
invalid / inconsistent provenance failing closed, approval binding over
provenance, audit records carrying provenance, and chain verification.

Tests inspect mock stores and the execution ledger - never a textual claim.
"""

from __future__ import annotations

from agentshield.models import Decision

from conftest import acquisition_read, confidential_send, internal_send, public_read


def _read_confidential(gateway) -> tuple[dict, list[str]]:
    """Execute the confidential read and return (response, provenance ids)."""
    response = gateway.submit(acquisition_read())
    assert response["status"] == "EXECUTED", response
    provenance = response["result"]["output"].get("provenance")
    assert provenance, response
    return response, provenance


def _vault_send(request_id: str, provenance: list[str]) -> dict:
    """Confidential send whose recipient and destination both point at the
    approved vault, carrying the given provenance."""
    payload = confidential_send(
        request_id=request_id,
        destination="vault.corp.example",
        provenance=provenance,
    )
    payload["arguments"] = {
        "recipient": "vault.corp.example",
        "subject": "Acquisition report",
        "body": "For the vault.",
    }
    return payload


# -- 1. metadata preserved through the outbound workflow ---------------------
def test_confidential_read_records_provenance_metadata(gateway, db):
    response, provenance = _read_confidential(gateway)

    output = response["result"]["output"]
    assert output["classification"] == "confidential"
    assert output["path"] == "/internal/acquisition_report.pdf"

    row = db.query_one(
        "SELECT * FROM provenance_records WHERE prov_id = ?", (provenance[0],)
    )
    assert row is not None
    assert str(row["classification"]) == "confidential"
    assert str(row["source_path"]) == "/internal/acquisition_report.pdf"
    assert str(row["session_id"]) == "sess-dataflow"

    # The read's decision and provenance are auditable.
    events = gateway.audit.events()
    recorded = [e for e in events if e["event_type"] == "provenance_recorded"]
    assert recorded and recorded[-1]["payload"]["prov_id"] == provenance[0]
    read_decisions = [
        e
        for e in events
        if e["event_type"] == "policy_decision"
        and e["payload"].get("request_id") == "req-acquisition"
    ]
    assert read_decisions[-1]["payload"]["reason_code"] == "confidential_read"


# -- 2. unauthorized external flow denied ------------------------------------
def test_confidential_data_to_external_destination_is_denied(gateway, db):
    _, provenance = _read_confidential(gateway)
    before = db.count("mock_outbox")

    response = gateway.submit(confidential_send(provenance=provenance))

    assert response["status"] == "DENIED"
    assert response["decision"] == Decision.DENY.value
    assert response["reason_code"] == "confidential_data_transfer"
    assert response["result"] is None


# -- 3. denied action leaves no side effect ----------------------------------
def test_denied_confidential_send_has_no_outbox_side_effect(gateway, db):
    _, provenance = _read_confidential(gateway)
    before_outbox = db.count("mock_outbox")
    before_ledger = db.count("execution_ledger")

    gateway.submit(
        confidential_send(request_id="req-no-side-effect", provenance=provenance)
    )

    assert db.count("mock_outbox") == before_outbox
    assert db.count("execution_ledger") == before_ledger
    assert (
        db.query_one(
            "SELECT * FROM mock_outbox WHERE recipient = ?",
            ("leak@external.example",),
        )
        is None
    )


# -- 4. public data still completes a legitimate workflow --------------------
def test_public_workflow_still_completes(gateway, db):
    read = gateway.submit(
        public_read(request_id="req-pub-1", session_id="sess-dataflow")
    )
    assert read["status"] == "EXECUTED"

    send = gateway.submit(
        internal_send(
            request_id="req-pub-2",
            session_id="sess-dataflow",  # same session, no confidential taint
        )
    )
    assert send["status"] == "EXECUTED"
    assert send["reason_code"] == "internal_recipient"
    assert db.count("mock_outbox") == 1


# -- 5. missing provenance cannot bypass protected-action policy -------------
def test_omitting_provenance_cannot_bypass_data_flow_policy(gateway, db):
    """After a confidential read, dropping provenance no longer helps."""
    _read_confidential(gateway)

    # Claims public, attaches nothing: session still carries the secret.
    response = gateway.submit(
        confidential_send(
            request_id="req-omit",
            data_classification="public",
            provenance=[],
        )
    )

    assert response["status"] == "DENIED"
    assert response["reason_code"] == "missing_provenance"
    assert db.count("mock_outbox") == 0


def test_confidential_claim_without_provenance_fails_closed(gateway, db):
    """A fresh session claiming confidential but attaching nothing is refused."""
    response = gateway.submit(
        confidential_send(request_id="req-no-prov", provenance=[])
    )
    assert response["status"] == "DENIED"
    assert response["reason_code"] == "missing_provenance"
    assert db.count("mock_outbox") == 0


def test_unknown_provenance_reference_fails_closed(gateway, db):
    response = gateway.submit(
        confidential_send(
            request_id="req-bad-ref", provenance=["prov_00000000000000000000000000000000"]
        )
    )
    assert response["status"] == "DENIED"
    assert response["reason_code"] == "invalid_provenance"
    assert db.count("mock_outbox") == 0


def test_cross_session_provenance_reference_fails_closed(gateway, db):
    """Evidence minted in one session cannot be borrowed by another."""
    _, provenance = _read_confidential(gateway)
    response = gateway.submit(
        confidential_send(
            request_id="req-foreign",
            session_id="sess-attacker",
            provenance=provenance,
        )
    )
    assert response["status"] == "DENIED"
    assert response["reason_code"] == "invalid_provenance"
    assert db.count("mock_outbox") == 0


def test_downgraded_classification_fails_closed(gateway, db):
    """Declared public + confidential provenance is inconsistent: deny."""
    _, provenance = _read_confidential(gateway)
    response = gateway.submit(
        confidential_send(
            request_id="req-downgrade",
            data_classification="public",
            provenance=provenance,
        )
    )
    assert response["status"] == "DENIED"
    assert response["reason_code"] == "inconsistent_provenance"
    assert db.count("mock_outbox") == 0


def test_authorization_defence_in_depth_blocks_confidential_send(gateway, db):
    """Even a forged ALLOW path cannot push classified e-mail out of the tool
    host: the tool itself refuses an unapproved classified destination."""
    from agentshield.models import DataClassification, action_fingerprint
    from agentshield.validator import validate

    validation = validate(
        confidential_send(
            request_id="req-bypass",
            data_classification="public",
            provenance=[],
            session_id="sess-clean",
        )
    )
    assert validation.ok
    request = validation.request
    request.data_classification = DataClassification.CONFIDENTIAL
    fingerprint = action_fingerprint(request)
    authorization = gateway.authorizations.issue(
        request.request_id, fingerprint, "ALLOW"
    )

    result = gateway.executor.execute(request, authorization, fingerprint)

    assert result.outcome == "FAILED"
    assert result.error == "confidential_data_transfer"
    assert db.count("mock_outbox") == 0


# -- 6. approval binding, expiry, replay over provenance ---------------------
def test_provenance_is_bound_to_the_approval(gateway, db, clock):
    """An approval covers its provenance list: swapping it mutates the action."""
    _, provenance = _read_confidential(gateway)
    request = _vault_send("req-bound", provenance)
    response = gateway.submit(request)
    assert response["status"] == "AWAITING_APPROVAL"
    assert response["reason_code"] == "confidential_transfer"
    approval_id = response["approval"]["approval_id"]
    gateway.approvals.decide(approval_id, approver="sec-lead", approve=True)

    # A second, valid provenance reference (a public read in the same session)
    # changes only the bound provenance list - the approval must refuse it.
    public = gateway.submit(
        public_read(request_id="req-pub-for-binding", session_id="sess-dataflow")
    )
    extra_prov = public["result"]["output"]["provenance"]
    swapped = {**request, "provenance": provenance + extra_prov}
    refused = gateway.execute_approved(swapped, approval_id)
    assert refused["status"] == "NO_EXECUTION"
    assert refused["reason_code"] == "approval_mutation"
    assert db.count("mock_outbox") == 0

    # The exact approved action executes once.
    done = gateway.execute_approved(request, approval_id)
    assert done["status"] == "EXECUTED"
    assert db.count("mock_outbox") == 1

    # Replay of the consumed approval is refused.
    replay = gateway.execute_approved(request, approval_id)
    assert replay["status"] == "NO_EXECUTION"
    assert replay["reason_code"] == "approval_already_consumed"
    assert db.count("mock_outbox") == 1

    # Expiry still applies to a fresh provenance-bound approval.
    second = gateway.submit(_vault_send("req-bound-2", provenance))
    second_id = second["approval"]["approval_id"]
    gateway.approvals.decide(second_id, approver="sec-lead", approve=True)
    clock.advance(301)
    expired = gateway.execute_approved(
        _vault_send("req-bound-2", provenance), second_id
    )
    assert expired["status"] == "NO_EXECUTION"
    assert expired["reason_code"] == "approval_expired"
    assert db.count("mock_outbox") == 1


# -- 7. audit records include the decision and provenance --------------------
def test_audit_decision_carries_provenance_metadata(gateway):
    _, provenance = _read_confidential(gateway)
    gateway.submit(
        confidential_send(request_id="req-audit-df", provenance=provenance)
    )

    decisions = [
        e
        for e in gateway.audit.events()
        if e["event_type"] == "policy_decision"
        and e["payload"].get("request_id") == "req-audit-df"
    ]
    assert decisions, "no policy_decision event for the denied send"
    payload = decisions[-1]["payload"]
    assert payload["decision"] == "DENY"
    assert payload["reason_code"] == "confidential_data_transfer"
    assert payload["provenance"] == provenance
    assert payload["effective_classification"] == "confidential"
    assert payload["provenance_sources"] == ["/internal/acquisition_report.pdf"]
    # No message body leaks into the audit trail.
    assert "Indicative offer" not in str(decisions)


# -- evaluation: data-flow experiment ----------------------------------------
def test_evaluation_data_flow_metrics_match_raw_attempts(tmp_path):
    from agentshield.evaluation import EvaluationRunner

    results = EvaluationRunner(workdir=str(tmp_path / "df-eval")).run()
    experiment = results["experiments"]["data_flow"]

    block = results["metrics"]["unauthorized_disclosure_block_rate"]
    assert block["numerator"] == 2
    assert block["denominator"] == 2
    assert block["rate"] == 1.0
    # Raw rows must support the numerator: both attempts denied, no effects.
    assert len(experiment["attempts"]) == 2
    for attempt in experiment["attempts"]:
        assert attempt["actual_decision"] == "DENY"
        assert attempt["blocked"] is True
        assert attempt["no_side_effect"] is True

    benign = results["metrics"]["data_flow_benign_completion_rate"]
    assert benign["numerator"] == 1
    assert benign["denominator"] == 1
    assert experiment["benign"]["completed"] is True
    assert experiment["benign"]["actual_status"] == "EXECUTED"

    # The pre-existing fixture counts are untouched by the experiment.
    assert results["fixture_count"] == 11
    assert results["metrics"]["attack_success_rate"]["firewall_on"][
        "denominator"
    ] == 6


# -- 8. audit chain verification continues to work ---------------------------
def test_audit_chain_verifies_after_data_flow_workload(gateway):
    _, provenance = _read_confidential(gateway)
    gateway.submit(confidential_send(request_id="req-df-1", provenance=provenance))
    gateway.submit(
        confidential_send(request_id="req-df-2", data_classification="public")
    )
    gateway.submit(public_read(request_id="req-df-3"))

    expected = gateway.audit.count()
    result = gateway.audit.verify(expected_count=expected)
    assert result.valid, result.failures
    assert result.event_count == expected
