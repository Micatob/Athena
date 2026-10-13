"""Prompt C: SQLite history + durable queue units (tmp DB, no server)."""

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.scan_store import (
    ScanStore,
    default_db_path,
    export_scan,
)

FINDINGS = [
    {"type": "SQL Injection", "url": "http://t/a?id=1",
     "severity": "CRITICAL", "description": "sqli"},
    {"type": "XSS", "url": "http://t/b?q=1",
     "severity": "HIGH", "description": "xss"},
    "not-a-dict",
]


def _store(tmp_path):
    return ScanStore(str(tmp_path / "athena.db"))


class TestScanHistory:
    def test_record_and_read_back(self, tmp_path):
        store = _store(tmp_path)
        try:
            scan_id = store.record_scan(
                "http://t", "full", "complete",
                {"total": 2}, FINDINGS, "report_t.html")
            assert scan_id == 1
            scan = store.get_scan(1)
            assert scan["target"] == "http://t"
            assert scan["mode"] == "full"
            assert scan["report_path"] == "report_t.html"
            assert scan["summary"] == {"total": 2}
            assert scan["findings_stored"] == 2
            findings = store.findings_for(1)
            assert len(findings) == 2
            assert findings[0]["type"] == "SQL Injection"
        finally:
            store.close()

    def test_missing_scan_returns_none(self, tmp_path):
        store = _store(tmp_path)
        try:
            assert store.get_scan(999) is None
            assert store.findings_for(999) == []
            assert export_scan(store, 999) is None
        finally:
            store.close()

    def test_list_order_and_severity_counts(self, tmp_path):
        store = _store(tmp_path)
        try:
            store.record_scan("http://a", "full", "complete", {}, [])
            store.record_scan("http://b", "vuln", "partial",
                              {}, FINDINGS)
            rows = store.list_scans()
            assert [r["target"] for r in rows] == ["http://b", "http://a"]
            assert store.severity_counts(2) == {"CRITICAL": 1, "HIGH": 1}
        finally:
            store.close()

    def test_export_json_and_csv(self, tmp_path):
        store = _store(tmp_path)
        try:
            store.record_scan("http://t", "full", "complete",
                              {"total": 2}, FINDINGS)
            as_json = export_scan(store, 1, "json")
            blob = json.loads(as_json)
            assert blob["scan"]["target"] == "http://t"
            assert len(blob["findings"]) == 2
            as_csv = export_scan(store, 1, "csv")
            lines = as_csv.strip().splitlines()
            assert lines[0] == "severity,type,url,detail"
            assert len(lines) == 3
            assert "SQL Injection" in as_csv
        finally:
            store.close()

    def test_db_path_env_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATHENA_DB_PATH", str(tmp_path / "custom.db"))
        assert default_db_path() == str(tmp_path / "custom.db")


class TestDurableQueue:
    def test_enqueue_status_lifecycle(self, tmp_path):
        store = _store(tmp_path)
        try:
            jid = store.enqueue(["http://t"], "full", job_id="job-1")
            assert jid == "job-1"
            assert store.get_job("job-1")["status"] == "QUEUED"
            store.set_job_status("job-1", "RUNNING")
            assert store.get_job("job-1")["status"] == "RUNNING"
            store.set_job_status("job-1", "COMPLETE")
            job = store.get_job("job-1")
            assert job["status"] == "COMPLETE"
            assert job["finished_at"]
        finally:
            store.close()

    def test_stale_running_requeued(self, tmp_path):
        store = _store(tmp_path)
        try:
            store.enqueue(["http://t"], "full", job_id="job-9")
            store.set_job_status("job-9", "RUNNING")
            assert store.reset_stale_running() == 1
            assert store.get_job("job-9")["status"] == "QUEUED"
            assert store.reset_stale_running() == 0
        finally:
            store.close()

    def test_unknown_job_returns_none(self, tmp_path):
        store = _store(tmp_path)
        try:
            assert store.get_job("nope") is None
        finally:
            store.close()


class TestHistoryAPI:
    @staticmethod
    def _app(tmp_path, monkeypatch):
        monkeypatch.setenv("ATHENA_DB_PATH", str(tmp_path / "api.db"))
        monkeypatch.setenv("ATHENA_API_KEY", "history-test-key")
        monkeypatch.setenv("REQUIRE_API_KEY", "true")
        monkeypatch.setenv("RATE_LIMIT_SCAN", "1000 per minute")
        from athena import create_app
        app = create_app()
        app.config["TESTING"] = True
        return app

    @staticmethod
    def _headers():
        return {"X-API-KEY": "history-test-key"}

    def test_scans_endpoints(self, tmp_path, monkeypatch):
        from modules.scan_store import ScanStore
        store = ScanStore(str(tmp_path / "api.db"))
        try:
            store.record_scan("http://t", "full", "complete",
                              {"total": 1}, [FINDINGS[0]])
        finally:
            store.close()
        app = self._app(tmp_path, monkeypatch)
        client = app.test_client()

        resp = client.get("/scans", headers=self._headers())
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["total"] == 1
        assert body["scans"][0]["target"] == "http://t"

        resp = client.get("/scans/1", headers=self._headers())
        assert resp.status_code == 200
        assert resp.get_json()["severity_counts"] == {"CRITICAL": 1}

        resp = client.get("/scans/999", headers=self._headers())
        assert resp.status_code == 404

    def test_export_endpoint(self, tmp_path, monkeypatch):
        from modules.scan_store import ScanStore
        store = ScanStore(str(tmp_path / "api.db"))
        try:
            store.record_scan("http://t", "full", "complete", {}, FINDINGS)
        finally:
            store.close()
        app = self._app(tmp_path, monkeypatch)
        client = app.test_client()

        resp = client.get("/scans/1/export?format=csv",
                          headers=self._headers())
        assert resp.status_code == 200
        assert "SQL Injection" in resp.get_data(as_text=True)

        resp = client.get("/scans/1/export?format=json",
                          headers=self._headers())
        assert resp.status_code == 200
        assert resp.get_json()["scan"]["target"] == "http://t"

        resp = client.get("/scans/1/export?format=xml",
                          headers=self._headers())
        assert resp.status_code == 400

        resp = client.get("/scans/999/export", headers=self._headers())
        assert resp.status_code == 404

    def test_status_falls_back_to_store(self, tmp_path, monkeypatch):
        from modules.scan_store import ScanStore
        store = ScanStore(str(tmp_path / "api.db"))
        try:
            store.enqueue(["http://t"], "full", job_id="dur-1")
            store.set_job_status("dur-1", "COMPLETE")
        finally:
            store.close()
        app = self._app(tmp_path, monkeypatch)
        client = app.test_client()

        resp = client.get("/scan/status/dur-1", headers=self._headers())
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "COMPLETE"

        resp = client.get("/scan/status/nope", headers=self._headers())
        assert resp.status_code == 404


class TestHistoryCLI:
    def test_history_lists_scans(self, tmp_path, monkeypatch, capsys):
        import athena
        from modules.scan_store import ScanStore
        monkeypatch.setenv("ATHENA_DB_PATH", str(tmp_path / "cli.db"))
        store = ScanStore(str(tmp_path / "cli.db"))
        try:
            store.record_scan("http://t", "full", "complete", {}, FINDINGS)
        finally:
            store.close()
        athena._run_history_command(argparse.Namespace(
            history=True, export_history=None, export=None, output="json"))
        out = capsys.readouterr().out
        assert "http://t" in out

    def test_export_history_to_file(self, tmp_path, monkeypatch):
        import athena
        from modules.scan_store import ScanStore
        monkeypatch.setenv("ATHENA_DB_PATH", str(tmp_path / "cli.db"))
        store = ScanStore(str(tmp_path / "cli.db"))
        try:
            store.record_scan("http://t", "full", "complete", {}, FINDINGS)
        finally:
            store.close()
        dest = str(tmp_path / "hist")
        athena._run_history_command(argparse.Namespace(
            history=False, export_history="1", export=dest, output="csv"))
        text = (tmp_path / "hist.csv").read_text(encoding="utf-8")
        assert "SQL Injection" in text
