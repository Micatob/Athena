"""Prompt A criterion 1: checkpoint save / crash / resume units.

Simulates a stage crash with mock counters: a resumed run must not re-run
completed stages, and its report inputs must match a no-crash baseline.
"""

import asyncio
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.checkpoint import CheckpointManager, target_key

TARGET = "http://resume.test.local"


def _manager(base, target=TARGET, **kwargs):
    return CheckpointManager(target, base_dir=str(base), **kwargs)


class TestCheckpointManager:
    def test_target_key_is_stable_and_distinct(self, tmp_path):
        assert target_key(TARGET) == target_key("  HTTP://RESUME.TEST.LOCAL ")
        assert target_key(TARGET) != target_key("http://other.test.local")
        assert len(target_key(TARGET)) == 16

    def test_save_and_load_stage_roundtrip(self, tmp_path):
        ckpt = _manager(tmp_path)
        payload = {"urls": [TARGET + "/"], "ports": [80, 443]}

        ckpt.save_stage("discovery", payload)

        assert ckpt.has("discovery") is True
        assert ckpt.load_stage("discovery") == payload
        assert "discovery" in ckpt.completed_stages()
        assert ckpt.load_stage("vuln") is None

    def test_stale_checkpoint_reports_stale(self, tmp_path):
        ckpt = _manager(tmp_path)
        ckpt.save_stage("discovery", {"urls": []})
        assert ckpt.is_stale() is False

        state_path = Path(ckpt.state_path)
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["updated_at"] = "2020-01-01T00:00:00+00:00"
        state_path.write_text(json.dumps(state), encoding="utf-8")

        aged = _manager(tmp_path)
        assert aged.is_stale() is True

    def test_vuln_progress_roundtrip_and_clear(self, tmp_path):
        ckpt = _manager(tmp_path)
        progress = {"completed": ["%s/%d" % (TARGET, i) for i in range(25)],
                    "remaining": ["%s/%d" % (TARGET, i) for i in range(25, 60)]}

        ckpt.save_progress(progress)
        assert ckpt.load_progress() == progress

        ckpt.clear_progress()
        assert ckpt.load_progress() is None

    def test_missing_checkpoint_is_not_present(self, tmp_path):
        ckpt = _manager(tmp_path)
        assert ckpt.has("discovery") is False
        assert ckpt.is_stale() is True


class TestCrashAndResume:
    pytestmark = pytest.mark.asyncio

    async def test_completed_stage_is_not_rerun(self, tmp_path):
        import athena

        ckpt = _manager(tmp_path)
        ckpt.save_stage("discovery", {"urls": [TARGET + "/"]})
        calls = {"discovery": 0, "vuln": 0}

        async def run_discovery():
            calls["discovery"] += 1
            return {"urls": []}

        async def run_vuln():
            calls["vuln"] += 1
            return [{"type": "X", "url": TARGET + "/"}]

        discovery, resumed_d = await athena._resumable_stage(
            ckpt, "discovery", run_discovery, resume=True)
        vulns, resumed_v = await athena._resumable_stage(
            ckpt, "vuln", run_vuln, resume=True)

        assert resumed_d is True
        assert calls["discovery"] == 0
        assert discovery == {"urls": [TARGET + "/"]}
        assert resumed_v is False
        assert calls["vuln"] == 1
        assert vulns == [{"type": "X", "url": TARGET + "/"}]

    async def test_crash_then_resume_matches_baseline(self, tmp_path):
        import athena

        # Baseline: uninterrupted run of both stages.
        baseline_dir = tmp_path / "baseline"
        base_ckpt = CheckpointManager(TARGET, base_dir=str(baseline_dir))
        first = await athena._resumable_stage(
            base_ckpt, "discovery",
            lambda: asyncio.sleep(0, result={"urls": [TARGET + "/"]}))
        second = await athena._resumable_stage(
            base_ckpt, "vuln",
            lambda: asyncio.sleep(0, result=[{"type": "X"}]))

        # Crashed run: discovery saved, vuln stage dies mid-flight.
        crash_dir = tmp_path / "crashed"
        crash_ckpt = CheckpointManager(TARGET, base_dir=str(crash_dir))
        await athena._resumable_stage(
            crash_ckpt, "discovery",
            lambda: asyncio.sleep(0, result={"urls": [TARGET + "/"]}))

        async def dying_vuln():
            raise RuntimeError("simulated stage crash")

        with pytest.raises(RuntimeError, match="simulated stage crash"):
            await athena._resumable_stage(
                crash_ckpt, "vuln", dying_vuln, resume=True)
        assert crash_ckpt.has("vuln") is False

        # Resumed run in a fresh manager over the same directory.
        resume_ckpt = CheckpointManager(TARGET, base_dir=str(crash_dir))
        calls = {"discovery": 0}

        async def must_not_rerun():
            calls["discovery"] += 1
            return {}

        resumed_first = await athena._resumable_stage(
            resume_ckpt, "discovery", must_not_rerun, resume=True)
        resumed_second = await athena._resumable_stage(
            resume_ckpt, "vuln",
            lambda: asyncio.sleep(0, result=[{"type": "X"}]), resume=True)

        assert calls["discovery"] == 0
        assert resumed_first[0] == first[0]
        assert resumed_second[0] == second[0]
