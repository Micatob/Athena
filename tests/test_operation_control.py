"""
tests/test_operation_control.py – Operation Gate
=================================================
Covers:
  * preflight explanation content (WHAT / WHY / TARGET / IN SCOPE /
    EXPECTED EVIDENCE)
  * fail-closed authorization chain: no engagement → denied;
    out-of-scope → blocked_by_scope; restricted technique → blocked_by_policy
  * confirmation-required plans (requires_authorization → granted)
  * rate-limit denial
  * guarded execution: success / structured failure / timeout / cancel
  * cleanup registration on guarded execution
  * audit events for every gate decision
"""

import asyncio
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.engagement import Engagement
from modules.operation_control import OperationGate, OperationPlan


@pytest.fixture()
def engagement() -> Engagement:
    return Engagement(
        name="Gate Test",
        operator="operator@example.org",
        in_scope_targets=["example.com"],
        restricted_techniques=["persistence"],
    )


@pytest.fixture()
def gate(engagement) -> OperationGate:
    return OperationGate(engagement=engagement, operator="tester")


class TestOperationPlan:
    def test_explain_contains_required_sections(self):
        plan = OperationPlan(
            action="Enumerate SMB shares",
            rationale="Authorized assessment",
            target="example.com",
            expected_evidence=["shares", "versions"],
            technique="recon",
            requires_confirmation=True,
            in_scope=True,
            scope_reason="matches in-scope rule 'example.com'",
        )
        text = plan.explain()
        for section in (
            "WHAT:",
            "WHY:",
            "TARGET:",
            "TARGET IN SCOPE:",
            "EXPECTED EVIDENCE:",
            "CONFIRMATION:",
            "SCOPE REASON:",
            "TECHNIQUE:",
        ):
            assert section in text
        assert "YES (in scope)" in text

    def test_explain_unknown_scope(self):
        plan = OperationPlan(action="a", rationale="r", target="t")
        assert "UNVERIFIED" in plan.explain()


class TestAuthorizationChain:
    def test_plan_captures_scope(self, gate):
        plan = gate.plan(action="a", rationale="r", target="example.com")
        assert plan.in_scope is True

    def test_plan_marks_out_of_scope(self, gate):
        plan = gate.plan(action="a", rationale="r", target="evil.com")
        assert plan.in_scope is False
        assert "not covered" in plan.scope_reason

    def test_no_engagement_fails_closed(self):
        gate = OperationGate(engagement=None)
        plan = OperationPlan(
            action="a", rationale="r", target="example.com", in_scope=True
        )
        result = gate.authorize(plan)
        assert not result.allowed
        assert result.state.value == "blocked_by_policy"

    def test_inactive_engagement_denied(self, engagement):
        engagement.active = False
        gate = OperationGate(engagement=engagement)
        plan = gate.plan(action="a", rationale="r", target="example.com")
        assert not gate.authorize(plan).allowed

    def test_out_of_scope_target_denied(self, gate):
        plan = gate.plan(action="a", rationale="r", target="evil.com")
        result = gate.authorize(plan)
        assert not result.allowed
        assert result.state.value == "blocked_by_scope"

    def test_restricted_technique_denied(self, gate):
        plan = gate.plan(
            action="a", rationale="r", target="example.com",
            technique="persistence"
        )
        result = gate.authorize(plan)
        assert not result.allowed
        assert result.state.value == "blocked_by_policy"
        assert "restricted" in result.reason

    def test_authorized_without_confirmation(self, gate):
        plan = gate.plan(
            action="a", rationale="r", target="example.com", technique="recon"
        )
        result = gate.authorize(plan)
        assert result.allowed
        assert result.state.value == "running"

    def test_confirmation_required_until_granted(self, gate):
        plan = gate.plan(
            action="a", rationale="r", target="example.com",
            requires_confirmation=True
        )
        denied = gate.authorize(plan)
        assert not denied.allowed
        assert denied.state.value == "requires_authorization"

        granted = gate.authorize(plan, confirmation=True)
        assert granted.allowed

    def test_granted_plan_stays_authorized(self, gate):
        plan = gate.plan(
            action="a", rationale="r", target="example.com",
            requires_confirmation=True
        )
        gate.authorize(plan, confirmation=True)
        assert gate.authorize(plan).allowed


class TestRateLimit:
    def test_rate_limit_denies(self, engagement):
        class Limiter:
            def check(self, engagement_id, operator, action):
                return type("R", (), {"allowed": False, "reason": "limit"})()

        gate = OperationGate(engagement=engagement, rate_limiter=Limiter())
        plan = gate.plan(action="a", rationale="r", target="example.com")
        result = gate.authorize(plan)
        assert not result.allowed
        assert "limit" in result.reason


class TestGuardedExecution:
    pytestmark = pytest.mark.asyncio

    async def test_execute_success(self, gate):
        async def fn():
            return {"found": True}

        plan = gate.plan(action="a", rationale="r", target="example.com")
        outcome = await gate.execute(plan, fn)
        assert outcome["allowed"]
        assert outcome["state"] == "completed"
        assert outcome["output"] == {"found": True}

    async def test_execute_blocked_out_of_scope(self, gate):
        async def fn():
            raise AssertionError("must not run")

        plan = gate.plan(action="a", rationale="r", target="evil.com")
        outcome = await gate.execute(plan, fn)
        assert not outcome["allowed"]
        assert outcome["state"] == "blocked_by_scope"
        assert outcome["error"]["code"] == "OPERATION_BLOCKED"

    async def test_execute_confirmation_gate(self, gate):
        async def fn():
            return 1

        plan = gate.plan(
            action="a", rationale="r", target="example.com",
            requires_confirmation=True
        )
        outcome = await gate.execute(plan, fn)
        assert not outcome["allowed"]
        assert outcome["state"] == "requires_authorization"

        outcome = await gate.execute(plan, fn, confirmation=True)
        assert outcome["allowed"]
        assert outcome["state"] == "completed"

    async def test_execute_structured_failure(self, gate):
        from modules.orchestration import StructuredError

        async def fn():
            raise StructuredError("SCANNER_DOWN", "scanner crashed")

        plan = gate.plan(action="a", rationale="r", target="example.com")
        outcome = await gate.execute(plan, fn)
        assert not outcome["allowed"]
        assert outcome["state"] == "failed"
        assert outcome["error"]["code"] == "SCANNER_DOWN"

    async def test_execute_timeout(self, gate):
        async def fn():
            await asyncio.sleep(5)

        plan = gate.plan(action="a", rationale="r", target="example.com")
        outcome = await gate.execute(plan, fn, timeout_seconds=0.05)
        assert not outcome["allowed"]
        assert outcome["state"] == "timeout"
        assert outcome["error"]["code"] == "OPERATION_TIMEOUT"


class TestAuditIntegration:
    def test_audit_records_denial(self, engagement):
        events = []

        class Audit:
            def log_action(self, user, action, target, status, details=""):
                events.append((action, status))

        gate = OperationGate(engagement=engagement, audit=Audit())
        plan = gate.plan(action="a", rationale="r", target="evil.com")
        gate.authorize(plan)
        assert ("OPERATION_DENIED", "DENIED") in events


class TestCleanupHookup:
    pytestmark = pytest.mark.asyncio

    async def test_execute_registers_artifacts(self, gate):
        from modules.cleanup_manager import CleanupManager

        cleanup = CleanupManager()
        gate.cleanup = cleanup

        async def fn():
            return 1

        plan = gate.plan(action="a", rationale="r", target="example.com")
        await gate.execute(plan, fn, cleanup_registrations=["/tmp/atn_1"])
        assert os.path.normpath("/tmp/atn_1") in cleanup.registered
