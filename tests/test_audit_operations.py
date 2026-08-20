"""
tests/test_audit_operations.py – Structured Logging & Auditability
===================================================================
Covers:
  * log_operation schema: every security-relevant event carries
    operator / engagement_id / target / module / action / timestamp /
    result / authorization_decision / scope_decision / evidence_ref
  * read_trail parses the JSONL audit log back
  * audit_operation helper: full-schema backends vs legacy log_action
    fallback vs None (no-op)
  * OperationGate emits structured events with engagement id,
    authorization + scope decisions (allow / deny / confirmation)
  * PipelineOrchestrator emits STAGE_RUN events with stage outcome,
    decisions and evidence reference
  * CleanupManager emits structured registration/cleanup events
"""

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.cleanup_manager import CleanupManager
from modules.engagement import Engagement
from modules.logging_config import AuditLogger, audit_operation
from modules.operation_control import OperationGate
from modules.orchestration import PipelineOrchestrator, StructuredError

REQUIRED_SCHEMA_FIELDS = {
    "operator", "engagement_id", "target", "module", "action",
    "timestamp", "result", "authorization_decision", "scope_decision",
    "evidence_ref",
}


@pytest.fixture()
def audit(tmp_path):
    """AuditLogger writing to a temp file, with handlers cleaned up."""
    log_file = str(tmp_path / "audit_ops.log")
    a = AuditLogger(audit_file=log_file)
    yield a, log_file
    for h in a.logger.handlers[:]:
        h.close()
        a.logger.removeHandler(h)


@pytest.fixture()
def engagement() -> Engagement:
    return Engagement(
        name="Audit Test",
        operator="operator@example.org",
        in_scope_targets=["example.com"],
    )


def _last_event(log_file: str) -> dict:
    lines = [ln for ln in Path(log_file).read_text(encoding="utf-8")
             .splitlines() if ln.strip()]
    return json.loads(lines[-1])


class TestStructuredSchema:
    def test_log_operation_carries_full_schema(self, audit):
        a, log_file = audit
        a.log_operation(
            operator="alice", action="STAGE_RUN", target="scanning",
            result="completed", engagement_id="eng-1", module="orchestration",
            authorization_decision="AUTHORIZED", scope_decision="in_scope",
            evidence_ref="vulnerabilities",
        )
        event = _last_event(log_file)
        assert REQUIRED_SCHEMA_FIELDS <= set(event)
        assert event["operator"] == "alice"
        assert event["engagement_id"] == "eng-1"
        assert event["module"] == "orchestration"
        assert event["authorization_decision"] == "AUTHORIZED"
        assert event["scope_decision"] == "in_scope"
        assert event["evidence_ref"] == "vulnerabilities"
        assert "T" in event["timestamp"]  # ISO-8601

    def test_log_operation_defaults(self, audit):
        a, log_file = audit
        a.log_operation(operator="bob", action="X", target="t",
                        result="ok")
        event = _last_event(log_file)
        assert event["engagement_id"] == ""
        assert event["module"] == "core"
        assert event["authorization_decision"] == ""
        assert event["scope_decision"] == ""

    def test_read_trail_parses_events(self, audit):
        a, log_file = audit
        a.log_operation(operator="u1", action="STAGE_RUN", target="a",
                        result="completed")
        a.log_operation(operator="u2", action="STAGE_RUN", target="b",
                        result="failed")
        a.log_action("u3", "OTHER", "c", "OK")
        trail = a.read_trail()
        assert len(trail) == 3
        assert trail[-1]["user"] == "u3"

    def test_read_trail_filters_and_limits(self, audit):
        a, log_file = audit
        for i in range(5):
            a.log_operation(operator=f"u{i}", action="STAGE_RUN",
                            target=f"t{i}", result="completed")
        only = a.read_trail(action="STAGE_RUN")
        assert len(only) == 5
        limited = a.read_trail(limit=2, action="STAGE_RUN")
        assert [e["operator"] for e in limited] == ["u3", "u4"]

    def test_read_trail_missing_file_returns_empty(self, tmp_path):
        a = AuditLogger(audit_file=str(tmp_path / "never_created.log"))
        assert a.read_trail() == []
        for h in a.logger.handlers[:]:
            h.close()
            a.logger.removeHandler(h)


class TestAuditOperationHelper:
    def test_none_audit_is_noop(self):
        audit_operation(None, operator="x", action="A", target="t",
                        result="ok")

    def test_full_schema_backend_gets_structured_call(self, audit):
        a, log_file = audit
        audit_operation(a, operator="carol", action="OP",
                        target="example.com", result="completed",
                        engagement_id="eng-9", module="test",
                        authorization_decision="AUTHORIZED",
                        scope_decision="in_scope", evidence_ref="e1")
        event = _last_event(log_file)
        assert event["operator"] == "carol"
        assert event["engagement_id"] == "eng-9"
        assert event["module"] == "test"

    def test_legacy_backend_falls_back_to_log_action(self):
        events = []

        class LegacyAudit:
            def log_action(self, user, action, target, status, details=""):
                events.append((user, action, target, status, details))

        audit_operation(LegacyAudit(), operator="dave", action="OP",
                        target="t", result="ok",
                        engagement_id="eng-1", module="m",
                        evidence_ref="e")
        user, action, target, status, details = events[-1]
        assert (user, action, target, status) == ("dave", "OP", "t", "ok")
        assert "eng-1" in details


class TestOperationGateAudit:
    def test_denied_out_of_scope_event(self, engagement, audit):
        a, log_file = audit
        gate = OperationGate(engagement=engagement, operator="tester",
                             audit=a)
        plan = gate.plan(action="a", rationale="r", target="evil.com")
        gate.authorize(plan)

        events = a.read_trail(action="OPERATION_DENIED")
        event = events[-1]
        assert event["operator"] == "tester"
        assert event["engagement_id"] == engagement.id
        assert event["module"] == "operation_control"
        assert event["authorization_decision"] == "DENIED"
        assert event["scope_decision"] == "blocked_by_scope"
        assert event["target"] == "evil.com"
        assert event["evidence_ref"] == plan.id

    def test_authorized_event(self, engagement, audit):
        a, log_file = audit
        gate = OperationGate(engagement=engagement, operator="tester",
                             audit=a)
        plan = gate.plan(action="a", rationale="r", target="example.com")
        gate.authorize(plan)

        event = a.read_trail(action="OPERATION_AUTHORIZED")[-1]
        assert event["authorization_decision"] == "AUTHORIZED"
        assert event["scope_decision"] == "in_scope"

    def test_confirmation_required_event(self, engagement, audit):
        a, log_file = audit
        gate = OperationGate(engagement=engagement, audit=a)
        plan = gate.plan(action="a", rationale="r", target="example.com",
                         requires_confirmation=True)
        gate.authorize(plan)

        event = a.read_trail(action="OPERATION_CONFIRMATION_REQUIRED")[-1]
        assert event["authorization_decision"] == "REQUIRES_AUTHORIZATION"

    def test_attempt_and_deny_are_both_recorded(self, engagement, audit):
        a, log_file = audit
        gate = OperationGate(engagement=engagement, audit=a)
        plan = gate.plan(action="a", rationale="r", target="evil.com")
        gate.authorize(plan)

        actions = [e["action"] for e in a.read_trail()]
        assert actions[-2:] == ["OPERATION_AUTHORIZE_ATTEMPT",
                                "OPERATION_DENIED"]

    def test_legacy_audit_backend_still_works(self, engagement):
        events = []

        class LegacyAudit:
            def log_action(self, user, action, target, status, details=""):
                events.append((action, status))

        gate = OperationGate(engagement=engagement, audit=LegacyAudit())
        plan = gate.plan(action="a", rationale="r", target="evil.com")
        gate.authorize(plan)
        assert ("OPERATION_DENIED", "DENIED") in events


class TestOrchestratorAudit:
    @pytest.mark.asyncio
    async def test_completed_stage_event(self, audit):
        a, log_file = audit
        orch = PipelineOrchestrator(engagement_id="eng-x", audit=a)

        async def runner():
            return {"urls": ["https://example.com"], "technologies": []}

        await orch.run_stage("discovery", runner)

        event = a.read_trail(action="STAGE_RUN")[-1]
        assert event["engagement_id"] == "eng-x"
        assert event["target"] == "discovery"
        assert event["result"] == "completed"
        assert event["module"] == "orchestration"
        assert event["authorization_decision"] == "AUTHORIZED"
        assert event["scope_decision"] == "in_scope"
        assert event["evidence_ref"] == "urls, technologies, ports"

    @pytest.mark.asyncio
    async def test_failed_stage_event(self, audit):
        a, log_file = audit
        orch = PipelineOrchestrator(engagement_id="eng-x", audit=a)

        async def runner():
            raise StructuredError("SCANNER_DOWN", "scanner crashed")

        await orch.run_stage("scanning", runner)

        event = a.read_trail(action="STAGE_RUN")[-1]
        assert event["result"] == "failed"
        assert event["evidence_ref"] == "SCANNER_DOWN"

    @pytest.mark.asyncio
    async def test_blocked_stage_event(self, audit):
        a, log_file = audit
        orch = PipelineOrchestrator(engagement_id="eng-x", audit=a)

        async def runner():
            raise AssertionError("must not run")

        await orch.run_stage("scanning", runner, in_scope=False)

        event = a.read_trail(action="STAGE_RUN")[-1]
        assert event["result"] == "blocked_by_scope"
        assert event["authorization_decision"] == "DENIED"
        assert event["scope_decision"] == "blocked_by_scope"
        assert event["evidence_ref"] == "BLOCKED_BY_SCOPE"

    @pytest.mark.asyncio
    async def test_pipeline_dependency_gate_is_audited(self, audit):
        a, log_file = audit
        orch = PipelineOrchestrator(engagement_id="eng-x", audit=a)
        await orch.run_pipeline({}, stages=["reporting"])

        event = a.read_trail(action="STAGE_RUN")[-1]
        assert event["result"] == "blocked_by_policy"
        assert event["evidence_ref"] == "MISSING_DEPENDENCY"


class TestCleanupAudit:
    def test_registration_event(self, audit, tmp_path):
        a, log_file = audit
        cleanup = CleanupManager(audit=a, engagement_id="eng-c")
        path = tmp_path / "artifact.tmp"
        cleanup.register(str(path))

        event = a.read_trail(action="ARTIFACT_REGISTERED")[-1]
        assert event["engagement_id"] == "eng-c"
        assert event["module"] == "cleanup_manager"
        assert event["result"] == "SUCCESS"
        assert event["evidence_ref"] == str(path)

    def test_cleanup_event(self, audit, tmp_path):
        a, log_file = audit
        cleanup = CleanupManager(audit=a, engagement_id="eng-c")
        path = tmp_path / "artifact.tmp"
        path.write_text("x", encoding="utf-8")
        cleanup.register(str(path))
        cleanup.cleanup()

        event = a.read_trail(action="ARTIFACT_CLEANUP")[-1]
        assert event["result"] == "VERIFIED"
        assert event["engagement_id"] == "eng-c"
        assert event["evidence_ref"] == str(path)
