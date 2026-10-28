"""AgentShield demo: provenance-aware data-flow enforcement, end to end.

Run:  python demo.py

Sequence (deterministic, mock tools only, no network):
  1. Read the confidential acquisition report and inspect its provenance.
  2. Attempt to e-mail it to an unauthorized external destination -> DENY.
  3. Verify no e-mail side effect (mock outbox unchanged).
  4. Attempt the same disclosure with provenance omitted -> DENY.
  5. Inspect the audit record for the decision and its provenance.
  6. Run a legitimate covered action: approved destination -> approval ->
     execution.
  7. Verify the audit chain.

Exits non-zero if any expected outcome does not hold, so the demo doubles as a
smoke test. Uses a temporary database; nothing is persisted.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from agentshield.gateway import Gateway

FAILURES: list[str] = []


def step(title: str) -> None:
    print(f"\n=== {title} " + "=" * max(0, 60 - len(title)))


def check(label: str, condition: bool, detail: str = "") -> None:
    mark = "PASS" if condition else "FAIL"
    if not condition:
        FAILURES.append(f"{label}: {detail}")
    print(f"  [{mark}] {label}" + (f" - {detail}" if detail else ""))


def main() -> int:
    db_path = Path(tempfile.mkdtemp(prefix="agentshield-demo-")) / "demo.db"
    gateway = Gateway(str(db_path))
    session = {
        "actor_id": "agent-1",
        "session_id": "sess-demo",
    }

    # 1. Read the confidential file -----------------------------------------
    step("1. Read confidential file, inspect provenance")
    read = gateway.submit(
        {
            **session,
            "request_id": "demo-read",
            "tool_name": "file_tool",
            "operation": "read",
            "arguments": {"path": "/internal/acquisition_report.pdf"},
            "data_classification": "confidential",
        }
    )
    output = (read.get("result") or {}).get("output") or {}
    provenance = list(output.get("provenance") or [])
    print(f"  status      : {read['status']} ({read['reason_code']})")
    print(f"  classification: {output.get('classification')}")
    print(f"  source path   : {output.get('path')}")
    print(f"  provenance id : {provenance}")
    check(
        "confidential read executes with metadata",
        read["status"] == "EXECUTED"
        and output.get("classification") == "confidential"
        and len(provenance) == 1,
        str(read.get("reason_code")),
    )

    # 2. Unauthorized external e-mail carrying the provenance ---------------
    step("2. Attempt unauthorized external e-mail (with provenance) -> DENY")
    before = gateway.db.count("mock_outbox")
    leak = {
        **session,
        "request_id": "demo-leak",
        "tool_name": "email_tool",
        "operation": "send",
        "arguments": {
            "recipient": "leak@external.example",
            "subject": "Acquisition report",
            "body": "Indicative offer 4.2M USD.",
        },
        "destination": "leak@external.example",
        "data_classification": "confidential",
        "provenance": provenance,
    }
    leak_response = gateway.submit(leak)
    print(f"  status     : {leak_response['status']}")
    print(f"  decision   : {leak_response['decision']}")
    print(f"  reason     : {leak_response['reason_code']}")
    check(
        "external confidential send is denied",
        leak_response["status"] == "DENIED"
        and leak_response["reason_code"] == "confidential_data_transfer",
    )

    # 3. No side effect ------------------------------------------------------
    step("3. Verify no e-mail side effect")
    after = gateway.db.count("mock_outbox")
    print(f"  mock outbox rows: {before} -> {after}")
    check("outbox unchanged after denial", before == after)
    check(
        "no execution ledger row for the denied call",
        gateway.db.count("execution_ledger", "request_id = ?", ("demo-leak",)) == 0,
    )

    # 4. Omitting provenance does not bypass ---------------------------------
    step("4. Attempt same disclosure with provenance omitted -> DENY")
    omit = {
        **session,
        "request_id": "demo-omit",
        "tool_name": "email_tool",
        "operation": "send",
        "arguments": dict(leak["arguments"]),
        "destination": leak["destination"],
        "data_classification": "public",
    }
    omit_response = gateway.submit(omit)
    print(f"  status     : {omit_response['status']}")
    print(f"  reason     : {omit_response['reason_code']}")
    check(
        "dropping provenance still denied",
        omit_response["status"] == "DENIED"
        and omit_response["reason_code"] == "missing_provenance",
    )
    check("outbox still empty", gateway.db.count("mock_outbox") == before)

    # 5. Audit record --------------------------------------------------------
    step("5. Inspect the audit decision record")
    decision_events = [
        event
        for event in gateway.audit.events()
        if event["event_type"] == "policy_decision"
        and event["payload"].get("request_id") == "demo-leak"
    ]
    payload = decision_events[-1]["payload"] if decision_events else {}
    for key in (
        "decision",
        "reason_code",
        "data_classification",
        "effective_classification",
        "provenance",
        "provenance_sources",
        "destination",
    ):
        print(f"  {key:24s}: {payload.get(key)}")
    check(
        "audit carries decision + provenance",
        payload.get("decision") == "DENY"
        and payload.get("provenance") == provenance
        and payload.get("effective_classification") == "confidential",
    )
    check(
        "audit never stores the message body",
        "Indicative offer" not in str(decision_events),
    )

    # 6. Legitimate permitted action ----------------------------------------
    step("6. Legitimate action: covered send to the approved destination")
    vault = {
        **session,
        "request_id": "demo-vault",
        "tool_name": "email_tool",
        "operation": "send",
        "arguments": {
            "recipient": "vault.corp.example",
            "subject": "Acquisition report",
            "body": "Filed to the vault.",
        },
        "destination": "vault.corp.example",
        "data_classification": "confidential",
        "provenance": provenance,
    }
    vault_response = gateway.submit(vault)
    print(f"  submit     : {vault_response['status']} ({vault_response['reason_code']})")
    approval_id = (vault_response.get("approval") or {}).get("approval_id")
    check(
        "approved destination escalates to human approval",
        vault_response["status"] == "AWAITING_APPROVAL"
        and vault_response["reason_code"] == "confidential_transfer"
        and approval_id is not None,
    )
    if approval_id:
        gateway.approvals.decide(approval_id, approver="sec-lead", approve=True)
        done = gateway.execute_approved(vault, approval_id)
        print(f"  execute    : {done['status']} ({done['reason_code']})")
        check("approved action executes exactly once", done["status"] == "EXECUTED")
        replay = gateway.execute_approved(vault, approval_id)
        check(
            "replay refused",
            replay["status"] == "NO_EXECUTION"
            and replay["reason_code"] == "approval_already_consumed",
        )
    print(f"  mock outbox rows now: {gateway.db.count('mock_outbox')}")

    # 7. Audit chain ----------------------------------------------------------
    step("7. Verify audit chain integrity")
    result = gateway.audit.verify(expected_count=gateway.audit.count())
    print(f"  valid={result.valid}  events={result.event_count}  head={result.head[:16]}...")
    check("audit chain verifies", result.valid, "; ".join(result.failures))

    print("\n" + "=" * 70)
    if FAILURES:
        print(f"DEMO FAILED: {len(FAILURES)} check(s) did not hold")
        for failure in FAILURES:
            print(f"  - {failure}")
        return 1
    print("DEMO OK: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
