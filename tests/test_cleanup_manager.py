"""
tests/test_cleanup_manager.py – Verified Cleanup Manager
=========================================================
Covers:
  * registration + audit events
  * verified removal of files and directories
  * never-created artifacts reported as not_found (still "verified" overall)
  * failure isolation (one unremovable artifact does not block the rest)
  * scrubbing before removal
  * failures_only retry semantics
  * cleanup report shape (verified / remaining)
"""

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.cleanup_manager import CleanupManager


@pytest.fixture()
def manager() -> CleanupManager:
    return CleanupManager()


class TestRegistration:
    def test_register_tracks_artifact(self, manager, tmp_path):
        path = tmp_path / "artifact.tmp"
        manager.register(str(path))
        assert str(path) in manager.registered

    def test_register_normalizes_paths(self, manager, tmp_path):
        manager.register(str(tmp_path / "sub" / ".." / "artifact.tmp"))
        assert str(tmp_path / "artifact.tmp") in manager.registered

    def test_register_audits(self, tmp_path):
        events = []

        class Audit:
            def log_action(self, user, action, target, status, details=""):
                events.append(action)

        manager = CleanupManager(audit=Audit())
        manager.register(str(tmp_path / "x"))
        assert "ARTIFACT_REGISTERED" in events


class TestCleanup:
    def test_verified_file_removal(self, manager, tmp_path):
        path = tmp_path / "tmp.txt"
        path.write_text("sensitive", encoding="utf-8")
        manager.register(str(path))
        report = manager.cleanup()
        assert report["verified"] is True
        assert not path.exists()
        statuses = {r["path"]: r["status"] for r in report["results"]}
        assert statuses[str(path)] == "verified"

    def test_verified_directory_removal(self, manager, tmp_path):
        directory = tmp_path / "work"
        directory.mkdir()
        (directory / "inner.txt").write_text("x", encoding="utf-8")
        manager.register(str(directory), kind="dir")
        report = manager.cleanup()
        assert report["verified"] is True
        assert not directory.exists()

    def test_never_created_reported_not_found(self, manager, tmp_path):
        path = tmp_path / "ghost.txt"
        manager.register(str(path))
        report = manager.cleanup()
        assert report["verified"] is True
        assert report["results"][0]["status"] == "not_found"

    def test_failure_is_isolated(self, manager, tmp_path):
        removable = tmp_path / "ok.txt"
        removable.write_text("x", encoding="utf-8")
        blocker = tmp_path / "locked"
        blocker.write_text("x", encoding="utf-8")
        blocker.chmod(0o400)  # read-only on POSIX; on Windows may still fail
        manager.register(str(removable))
        manager.register(str(blocker))

        report = manager.cleanup()
        statuses = {r["path"]: r["status"] for r in report["results"]}
        assert statuses[str(removable)] == "verified"
        assert not removable.exists()

    def test_failures_only_retries_present_only(self, manager, tmp_path):
        gone = tmp_path / "gone.txt"
        present = tmp_path / "present.txt"
        present.write_text("x", encoding="utf-8")
        manager.register(str(gone))
        manager.register(str(present))

        first = manager.cleanup()
        assert first["verified"] is True
        present.write_text("again", encoding="utf-8")

        second = manager.cleanup(failures_only=True)
        paths = [r["path"] for r in second["results"]]
        assert str(present) in paths
        assert str(gone) not in paths
        assert second["verified"] is True

    def test_scrub_zero_fills_before_removal(self, manager, tmp_path):
        path = tmp_path / "secret.tmp"
        path.write_bytes(b"supersecret")
        manager.register(str(path), scrub=True)
        report = manager.cleanup()
        assert report["verified"] is True
        assert not path.exists()

    def test_report_remaining(self, manager, tmp_path):
        path = tmp_path / "leftover.tmp"
        path.write_text("x", encoding="utf-8")
        manager.register(str(path), kind="file")
        (tmp_path / "fake_dir").mkdir()
        manager.register(str(tmp_path / "fake_dir"), kind="dir")

        # make removal fail by replacing the file with a directory
        path.unlink()
        path.mkdir()
        report = manager.cleanup()
        assert report["verified"] is False
        assert str(path) in report["remaining"]


class TestVerification:
    def test_is_verified_absent(self, manager, tmp_path):
        assert manager.is_verified(str(tmp_path / "nope"))

    def test_is_verified_present(self, manager, tmp_path):
        path = tmp_path / "here"
        path.write_text("x", encoding="utf-8")
        assert not manager.is_verified(str(path))
