"""
tests/test_orchestration.py – Pipeline Orchestrator
====================================================
Covers:
  * stage registry (canonical order, 11 stages, artifact contracts)
  * structured errors (stable codes, serializable dicts)
  * single-stage execution: success / failure / timeout / cancel /
    out-of-scope / requires-authorization / non-independent
  * pipeline isolation (a failed stage never aborts other stages)
  * dependency gating (missing artifacts → blocked_by_policy)
  * artifact hand-off between stages
  * report shape and state counts
"""

import asyncio
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.orchestration import (
    PIPELINE_STAGES,
    PipelineOrchestrator,
    STAGE_BY_KEY,
    StageState,
    StructuredError,
    stage_list,
)


@pytest.fixture()
def orchestrator() -> PipelineOrchestrator:
    return PipelineOrchestrator(engagement_id="eng-test-1")


class TestStageRegistry:
    def test_canonical_order(self):
        keys = [s.key for s in PIPELINE_STAGES]
        assert keys == [
            "engagement",
            "recon",
            "enumeration",
            "discovery",
            "scanning",
            "validation",
            "initial_access",
            "post_exploitation_assessment",
            "attack_path_analysis",
            "impact_assessment",
            "reporting",
        ]

    def test_all_ten_states_are_defined(self):
        values = {s.value for s in StageState}
        assert values == {
            "queued",
            "running",
            "completed",
            "failed",
            "timeout",
            "cancelled",
            "blocked_by_scope",
            "blocked_by_policy",
            "requires_authorization",
            "partial",
        }

    def test_stage_artifact_contracts(self):
        discovery = STAGE_BY_KEY["discovery"]
        assert discovery.produces == ("urls", "technologies", "ports")
        assert discovery.requires == ("targets",)

    def test_stage_list_is_serializable(self):
        for spec in stage_list():
            assert set(spec) == {
                "key",
                "name",
                "description",
                "produces",
                "requires",
                "runnable_independently",
            }

    def test_reporting_depends_on_impact(self):
        assert "impact" in STAGE_BY_KEY["reporting"].requires


class TestStructuredError:
    def test_fields(self):
        err = StructuredError(
            "INTERNAL_ERROR", "boom", stage="scanning",
            details={"k": 1}, transient=True
        )
        assert err.code == "INTERNAL_ERROR"
        assert err.stage == "scanning"
        assert err.transient

    def test_to_dict_round_trip(self):
        err = StructuredError("E", "m")
        d = err.to_dict()
        assert d["code"] == "E"
        assert d["message"] == "m"
        assert d["transient"] is False


class TestSingleStageExecution:
    pytestmark = pytest.mark.asyncio

    async def test_success(self, orchestrator):
        async def runner():
            return {"ok": True}

        result = await orchestrator.run_stage("scanning", runner)
        assert result.state == StageState.COMPLETED
        assert result.output == {"ok": True}
        assert result.duration_seconds >= 0

    async def test_failure_is_captured_not_raised(self, orchestrator):
        async def runner():
            raise StructuredError("TEST_FAILURE", "nope")

        result = await orchestrator.run_stage("scanning", runner)
        assert result.state == StageState.FAILED
        assert result.error["code"] == "TEST_FAILURE"
        assert result.error["stage"] == "scanning"

    async def test_unexpected_exception_wraps(self, orchestrator):
        async def runner():
            raise RuntimeError("raw boom")

        result = await orchestrator.run_stage("scanning", runner)
        assert result.state == StageState.FAILED
        assert result.error["code"] == "INTERNAL_ERROR"

    async def test_timeout(self, orchestrator):
        async def runner():
            await asyncio.sleep(5)

        result = await orchestrator.run_stage(
            "scanning", runner, timeout_seconds=0.05)
        assert result.state == StageState.TIMEOUT
        assert result.error["transient"] is True

    async def test_default_timeout(self, orchestrator):
        orchestrator.default_timeout_seconds = 0.05

        async def runner():
            await asyncio.sleep(5)

        result = await orchestrator.run_stage("scanning", runner)
        assert result.state == StageState.TIMEOUT

    async def test_out_of_scope_blocks_without_running(self, orchestrator):
        async def runner():
            raise AssertionError("must not run")

        result = await orchestrator.run_stage(
            "scanning", runner, in_scope=False)
        assert result.state == StageState.BLOCKED_BY_SCOPE
        assert result.error["code"] == "BLOCKED_BY_SCOPE"

    async def test_requires_authorization_without_running(self, orchestrator):
        async def runner():
            raise AssertionError("must not run")

        result = await orchestrator.run_stage(
            "initial_access", runner, requires_authorization=True
        )
        assert result.state == StageState.REQUIRES_AUTHORIZATION
        assert result.error["code"] == "REQUIRES_AUTHORIZATION"

    async def test_cancel_skips_execution(self, orchestrator):
        async def runner():
            raise AssertionError("must not run")

        orchestrator.cancel("operator said stop")
        result = await orchestrator.run_stage("scanning", runner)
        assert result.state == StageState.CANCELLED

    async def test_non_independent_stage_blocked(self, orchestrator):
        async def runner():
            raise AssertionError("must not run")

        spec = STAGE_BY_KEY["reporting"]
        try:
            STAGE_BY_KEY["reporting"] = spec.__class__(
                key="reporting", name=spec.name, runnable_independently=False
            )
            result = await orchestrator.run_stage("reporting", runner)
            assert result.state == StageState.BLOCKED_BY_POLICY
            assert result.error["code"] == "STAGE_NOT_INDEPENDENT"
        finally:
            STAGE_BY_KEY["reporting"] = spec

    async def test_result_survives_repeated_runs(self, orchestrator):
        async def runner():
            return 1

        first = await orchestrator.run_stage("scanning", runner)
        second = await orchestrator.run_stage("scanning", runner)
        assert first.state == second.state == StageState.COMPLETED
        assert orchestrator.results["scanning"] is second


class TestPipelineExecution:
    pytestmark = pytest.mark.asyncio

    async def test_successful_pipeline_handoff(self, orchestrator):
        async def discovery_runner():
            return {"urls": ["https://example.com"], "technologies": ["nginx"]}

        async def scanning_runner():
            return {"vulns": ["CVE-2026-0001"]}

        results = await orchestrator.run_pipeline(
            {
                "discovery": discovery_runner,
                "scanning": scanning_runner,
            },
            stages=["discovery", "scanning"],
        )
        assert results["discovery"].state == StageState.COMPLETED
        assert results["scanning"].state == StageState.COMPLETED
        assert orchestrator.artifacts["urls"] == ["https://example.com"]

    async def test_failed_stage_does_not_abort_pipeline(self, orchestrator):
        async def discovery_runner():
            return {"urls": [], "technologies": []}

        async def bad_runner():
            raise StructuredError("SCANNER_DOWN", "scanner crashed")

        results = await orchestrator.run_pipeline(
            {
                "discovery": discovery_runner,
                "scanning": bad_runner,
            },
            stages=["discovery", "scanning"],
        )
        # the failed stage is captured without raising…
        assert results["scanning"].state == StageState.FAILED
        # …the successful stage's artifacts are still handed off
        assert orchestrator.artifacts.get("urls") == []
        assert "vulnerabilities" not in orchestrator.artifacts
        assert "scanning" in orchestrator.results

    async def test_missing_dependency_blocks_stage(self, orchestrator):
        results = await orchestrator.run_pipeline(
            {
                "reporting": lambda: _never(),
            },
            stages=["reporting"],
        )
        assert results["reporting"].state == StageState.BLOCKED_BY_POLICY
        assert results["reporting"].error["code"] == "MISSING_DEPENDENCY"

    async def test_missing_runner_is_failed(self, orchestrator):
        results = await orchestrator.run_pipeline({}, stages=["recon"])
        assert results["recon"].state == StageState.FAILED
        assert results["recon"].error["code"] == "NO_RUNNER"

    async def test_report_counts(self, orchestrator):
        async def ok():
            return {"urls": ["https://example.com"], "technologies": []}

        async def bad():
            raise StructuredError("X", "x")

        await orchestrator.run_pipeline(
            {
                "discovery": ok,
                "scanning": bad,
            },
            stages=["discovery", "scanning"],
        )
        report = orchestrator.report()
        assert report["state_counts"]["completed"] == 1
        assert report["state_counts"]["failed"] == 1
        assert "urls" in report["artifacts"]


async def _never():
    raise AssertionError("runner must not be invoked")
