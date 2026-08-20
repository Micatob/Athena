"""
tests/test_production_readiness.py - production hardening for the new subsystem
===============================================================================
Consolidated checklist tests covering the production-readiness items that are
specific to the orchestration / operator-control / cleanup / audit subsystem:

  * unknown stage keys are rejected (never silently executed)
  * pipeline isolation for unknown stages
  * failed stages recover on rerun (error recovery, not crash-and-die)
  * cleanup input validation (empty paths)
  * concurrent registration + stage execution are safe
  * audit trails never store raw secrets
"""

import sys
import threading
import asyncio
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.cleanup_manager import CleanupManager
from modules.logging_config import AuditLogger
from modules.orchestration import (
    PipelineOrchestrator,
    StageResult,
    StageState,
    StructuredError,
)


# -- unknown stage keys ------------------------------------------------------

class TestUnknownStageKeys:
    @pytest.mark.asyncio
    async def test_unknown_stage_rejected(self):
        orch = PipelineOrchestrator()

        async def runner():
            return {"ok": True}

        result = await orch.run_stage("not_a_stage", runner)
        assert result.state == StageState.FAILED
        assert result.error["code"] == "INVALID_STAGE_KEY"
        assert result.output is None

    @pytest.mark.asyncio
    async def test_unknown_stage_never_executes_runner(self):
        orch = PipelineOrchestrator()
        executed = []

        async def runner():
            executed.append(True)
            return {}

        await orch.run_stage("bogus", runner)
        assert executed == []

    @pytest.mark.asyncio
    async def test_unknown_stage_in_pipeline_fails_isolated(self):
        orch = PipelineOrchestrator()
        orch.artifacts["targets"] = {"hosts": ["10.0.0.1"]}

        async def enumeration():
            return {"services": ["http"]}

        results = await orch.run_pipeline(
            {"enumeration": enumeration},
            stages=["bogus", "enumeration", "nope"],
        )
        assert results["bogus"].state == StageState.FAILED
        assert results["bogus"].error["code"] == "INVALID_STAGE_KEY"
        assert results["nope"].state == StageState.FAILED
        assert results["enumeration"].state == StageState.COMPLETED
        assert "services" in orch.artifacts

    @pytest.mark.asyncio
    async def test_unknown_stage_audited(self, tmp_path):
        audit = AuditLogger(tmp_path / "audit.log")
        orch = PipelineOrchestrator(audit=audit)
        await orch.run_stage("bogus", lambda: _never())
        events = audit.read_trail(action="STAGE_RUN")
        assert events and events[-1]["result"] == "failed"
        assert events[-1]["evidence_ref"] == "INVALID_STAGE_KEY"


def _never():
    raise AssertionError("runner must not be called")


# -- recovery semantics ------------------------------------------------------

class TestRecovery:
    @pytest.mark.asyncio
    async def test_failed_stage_recovers_on_rerun(self):
        orch = PipelineOrchestrator()
        attempts = {"n": 0}

        async def flaky_runner():
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise StructuredError("SCANNER_DOWN", "scanner unavailable",
                                      transient=True)
            return {"vulnerabilities": ["CVE-x"]}

        first = await orch.run_stage("scanning", flaky_runner)
        assert first.state == StageState.FAILED
        assert first.error["code"] == "SCANNER_DOWN"

        second = await orch.run_stage("scanning", flaky_runner)
        assert second.state == StageState.COMPLETED
        assert second.output == {"vulnerabilities": ["CVE-x"]}

    @pytest.mark.asyncio
    async def test_pipeline_continues_after_failed_known_stage(self):
        orch = PipelineOrchestrator()
        orch.artifacts["targets"] = {"hosts": ["10.0.0.1"]}
        orch.artifacts["urls"] = ["http://10.0.0.1/"]
        orch.artifacts["technologies"] = ["nginx"]

        async def broken_scanning():
            raise StructuredError("SCANNER_DOWN", "down", transient=True)

        async def enumeration():
            return {"services": ["http"]}

        results = await orch.run_pipeline(
            {"scanning": broken_scanning, "enumeration": enumeration},
            stages=["enumeration", "scanning"],
        )
        assert results["scanning"].state == StageState.FAILED
        assert results["enumeration"].state == StageState.COMPLETED
        assert "services" in orch.artifacts

    @pytest.mark.asyncio
    async def test_gate_denial_is_recoverable(self):
        """An operator can re-plan and succeed after a denial."""
        from modules.engagement import Engagement
        from modules.operation_control import create_operation_gate

        engagement = Engagement(
            name="Readiness",
            operator="operator@example.org",
            in_scope_targets=["example.com"],
            restricted_techniques=["persistence"],
        )
        gate = create_operation_gate(engagement=engagement, operator="tester")

        denied = gate.plan(
            action="AUTH_ATTEMPT",
            rationale="Recovery check",
            target="example.com",
            technique="persistence",
        )
        decision = gate.authorize(denied)
        assert decision.allowed is False
        assert decision.state.value == "blocked_by_policy"

        authorized = gate.plan(
            action="AUTH_ATTEMPT",
            rationale="Recovery check",
            target="example.com",
            technique="controlled_validation",
        )
        assert gate.authorize(authorized).allowed is True
        outcome = await gate.execute(authorized, lambda: _ok())
        assert outcome["allowed"] is True
        assert outcome["state"] == "completed"
        assert outcome["output"] == "ok"


def _ok():
    async def inner():
        return "ok"
    return inner()


# -- cleanup input validation & concurrency ----------------------------------

class TestCleanupHardening:
    def test_empty_path_rejected(self):
        manager = CleanupManager()
        with pytest.raises(ValueError):
            manager.register("")
        with pytest.raises(ValueError):
            manager.register("   ")

    def test_concurrent_registration_and_cleanup(self, tmp_path):
        manager = CleanupManager()
        paths = [tmp_path / f"a{i}.tmp" for i in range(50)]
        for path in paths:
            path.write_text("data", encoding="utf-8")

        errors = []

        def worker(path):
            try:
                manager.register(str(path))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(p,)) for p in paths]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        assert len(manager.registered) == 50
        report = manager.cleanup()
        assert report["verified"] is True
        assert all(not p.exists() for p in paths)

    @pytest.mark.asyncio
    async def test_concurrent_stage_execution(self):
        orch = PipelineOrchestrator()
        seen = []

        async def stage_a():
            await asyncio.sleep(0.01)
            seen.append("a")
            return {"engagement": "e1"}

        async def stage_b():
            await asyncio.sleep(0.01)
            seen.append("b")
            return {"targets": ["10.0.0.1"]}

        a, b = await asyncio.gather(
            orch.run_stage("engagement", stage_a),
            orch.run_stage("recon", stage_b),
        )
        assert a.state == StageState.COMPLETED
        assert b.state == StageState.COMPLETED
        assert set(seen) == {"a", "b"}
        assert orch.artifacts["engagement"] == "e1"
        assert orch.artifacts["targets"] == ["10.0.0.1"]


# -- secrets in audit trails -------------------------------------------------

class TestAuditSecretHandling:
    def test_details_redacted_in_trail(self, tmp_path):
        audit = AuditLogger(tmp_path / "audit.log")
        audit.log_operation(
            operator="tester",
            action="TEST_OP",
            target="db",
            result="FAILED",
            details='login failed; password=supersecret123; token=abcd1234',
        )
        events = audit.read_trail(action="TEST_OP")
        assert len(events) == 1
        assert "supersecret123" not in events[0]["details"]
        assert "abcd1234" not in events[0]["details"]
        assert "[REDACTED:" in events[0]["details"]

    def test_clean_events_unchanged(self, tmp_path):
        audit = AuditLogger(tmp_path / "audit.log")
        audit.log_operation(
            operator="tester",
            action="TEST_OP",
            target="db",
            result="SUCCESS",
            details="no secrets here",
        )
        events = audit.read_trail(action="TEST_OP")
        assert events[0]["details"] == "no secrets here"

    @pytest.mark.asyncio
    async def test_failed_stage_error_leaks_no_secret(self, tmp_path):
        audit = AuditLogger(tmp_path / "audit.log")
        orch = PipelineOrchestrator(audit=audit)

        async def leaking_runner():
            raise StructuredError(
                "AUTH_DENIED",
                "credential password=hunter2 rejected by 10.0.0.1",
            )

        result = await orch.run_stage("validation", leaking_runner)
        assert result.state == StageState.FAILED
        raw = (tmp_path / "audit.log").read_text(encoding="utf-8")
        assert "hunter2" not in raw
        assert "AUTH_DENIED" in raw
