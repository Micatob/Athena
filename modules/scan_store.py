"""Durable scan history + queue (Prompt C - Operations).

The pipeline already checkpoints *in-progress* work (``modules/checkpoint``);
this module remembers *finished* work: every completed scan lands in a
local SQLite database (stdlib only, no new dependencies) with its summary
and findings, and API scan jobs are tracked durably so a server restart
loses neither history nor queued work.

Layout (``~/.athena/athena.db``, override with ``ATHENA_DB_PATH``)::

    scans     - one row per finished scan (target, mode, status, summary)
    findings  - one row per stored finding (severity, type, url, full JSON)
    jobs      - API queue mirror (QUEUED -> RUNNING -> COMPLETE | FAILED)

Secrets: summaries and findings are operator data - credentials are never
written here (auth summaries are already secret-free by construction).
Every public function degrades to a no-op / empty result on SQLite
failure; the store never breaks a scan or an API request.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("athena.store")

#: Hard cap on findings stored per scan (report caps itemization anyway).
MAX_STORED_FINDINGS = 2000

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'full',
    status TEXT NOT NULL DEFAULT 'complete',
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    summary_json TEXT NOT NULL DEFAULT '{}',
    report_path TEXT NOT NULL DEFAULT '',
    findings_stored INTEGER NOT NULL DEFAULT 0,
    findings_truncated INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    severity TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    finding_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(scan_id, severity);
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    targets_json TEXT NOT NULL DEFAULT '[]',
    mode TEXT NOT NULL DEFAULT 'full',
    status TEXT NOT NULL DEFAULT 'QUEUED',
    created_at TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT ''
);
"""


def default_db_path() -> str:
    """Database file, honouring the ``ATHENA_DB_PATH`` override (tests)."""
    override = (os.getenv("ATHENA_DB_PATH", "") or "").strip()
    if override:
        return override
    return os.path.join(os.path.expanduser("~"), ".athena", "athena.db")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanStore:
    """Thread-safe SQLite history + queue.  Open-per-instance, WAL mode."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or default_db_path()
        self._lock = threading.Lock()
        try:
            parent = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(parent, exist_ok=True)
        except OSError:
            pass
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.executescript(SCHEMA)
            self._db.commit()
        except sqlite3.Error as exc:
            logger.debug("scan store init failed (%s): %s", self.path, exc)

    def close(self) -> None:
        try:
            self._db.close()
        except Exception:
            pass

    # -- scans -----------------------------------------------------------

    def record_scan(self, target: str, mode: str = "full",
                    status: str = "complete",
                    summary: Optional[Dict[str, Any]] = None,
                    findings: Optional[List[Dict[str, Any]]] = None,
                    report_path: str = "",
                    started_at: str = "") -> int:
        """Persist one finished scan; returns the scan id (0 on failure)."""
        clean = [f for f in (findings or []) if isinstance(f, dict)]
        truncated = max(0, len(clean) - MAX_STORED_FINDINGS)
        kept = clean[:MAX_STORED_FINDINGS]
        now = _utcnow()
        try:
            with self._lock:
                cur = self._db.execute(
                    "INSERT INTO scans (target, mode, status, started_at,"
                    " finished_at, summary_json, report_path,"
                    " findings_stored, findings_truncated)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (str(target or ""), str(mode or "full"),
                     str(status or "complete"), started_at or now, now,
                     json.dumps(summary or {}, default=str),
                     str(report_path or ""), len(kept), truncated))
                scan_id = int(cur.lastrowid or 0)
                self._db.executemany(
                    "INSERT INTO findings (scan_id, severity, type, url,"
                    " finding_json) VALUES (?, ?, ?, ?, ?)",
                    [(scan_id, str(f.get("severity", "") or ""),
                      str(f.get("type", "") or ""), str(f.get("url", "") or ""),
                      json.dumps(f, default=str)) for f in kept])
                self._db.commit()
            return scan_id
        except sqlite3.Error as exc:
            logger.debug("record_scan failed: %s", exc)
            return 0

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        try:
            with self._lock:
                row = self._db.execute(
                    "SELECT id, target, mode, status, started_at,"
                    " finished_at, summary_json, report_path,"
                    " findings_stored, findings_truncated FROM scans"
                    " WHERE id = ?", (int(scan_id),)).fetchone()
        except (sqlite3.Error, TypeError, ValueError):
            return None
        if not row:
            return None
        try:
            summary = json.loads(row[6] or "{}")
        except ValueError:
            summary = {}
        return {"id": row[0], "target": row[1], "mode": row[2],
                "status": row[3], "started_at": row[4],
                "finished_at": row[5], "summary": summary,
                "report_path": row[7], "findings_stored": row[8],
                "findings_truncated": row[9]}

    def list_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        try:
            limit = max(1, min(100, int(limit or 20)))
        except (TypeError, ValueError):
            limit = 20
        try:
            with self._lock:
                rows = self._db.execute(
                    "SELECT id, target, mode, status, started_at,"
                    " finished_at, report_path, findings_stored FROM scans"
                    " ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        except sqlite3.Error:
            return []
        return [{"id": r[0], "target": r[1], "mode": r[2], "status": r[3],
                 "started_at": r[4], "finished_at": r[5],
                 "report_path": r[6], "findings_stored": r[7]} for r in rows]

    def findings_for(self, scan_id: int,
                     severity: str = "") -> List[Dict[str, Any]]:
        try:
            if severity:
                rows = self._db.execute(
                    "SELECT finding_json FROM findings WHERE scan_id = ?"
                    " AND severity = ? ORDER BY id",
                    (int(scan_id), str(severity))).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT finding_json FROM findings WHERE scan_id = ?"
                    " ORDER BY id", (int(scan_id),)).fetchall()
        except (sqlite3.Error, TypeError, ValueError):
            return []
        out = []
        for (blob,) in rows:
            try:
                data = json.loads(blob or "{}")
            except ValueError:
                continue
            if isinstance(data, dict):
                out.append(data)
        return out

    def severity_counts(self, scan_id: int) -> Dict[str, int]:
        try:
            with self._lock:
                rows = self._db.execute(
                    "SELECT severity, COUNT(*) FROM findings"
                    " WHERE scan_id = ? GROUP BY severity",
                    (int(scan_id),)).fetchall()
        except (sqlite3.Error, TypeError, ValueError):
            return {}
        return {str(sev or "unknown"): int(n) for sev, n in rows}

    # -- durable queue ---------------------------------------------------

    def enqueue(self, targets: List[str], mode: str = "full",
                job_id: str = "") -> str:
        """Queue an API scan; returns the job id ('' on failure)."""
        jid = job_id or uuid.uuid4().hex
        try:
            with self._lock:
                self._db.execute(
                    "INSERT OR REPLACE INTO jobs (id, targets_json, mode,"
                    " status, created_at) VALUES (?, ?, ?, 'QUEUED', ?)",
                    (jid, json.dumps([str(t) for t in (targets or [])]),
                     str(mode or "full"), _utcnow()))
                self._db.commit()
            return jid
        except sqlite3.Error as exc:
            logger.debug("enqueue failed: %s", exc)
            return ""

    def set_job_status(self, job_id: str, status: str,
                       error: str = "") -> None:
        stamp = _utcnow()
        started = finished = ""
        if status == "RUNNING":
            started = stamp
        if status in ("COMPLETE", "FAILED"):
            finished = stamp
        try:
            with self._lock:
                if started:
                    self._db.execute(
                        "UPDATE jobs SET status = ?, started_at = ?"
                        " WHERE id = ?", (status, started, job_id))
                elif finished:
                    self._db.execute(
                        "UPDATE jobs SET status = ?, finished_at = ?,"
                        " error = ? WHERE id = ?", (status, finished,
                                                    str(error or ""), job_id))
                else:
                    self._db.execute(
                        "UPDATE jobs SET status = ? WHERE id = ?",
                        (status, job_id))
                self._db.commit()
        except sqlite3.Error as exc:
            logger.debug("set_job_status failed: %s", exc)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        try:
            with self._lock:
                row = self._db.execute(
                    "SELECT id, targets_json, mode, status, created_at,"
                    " started_at, finished_at, error FROM jobs WHERE id = ?",
                    (str(job_id),)).fetchone()
        except sqlite3.Error:
            return None
        if not row:
            return None
        try:
            targets = json.loads(row[1] or "[]")
        except ValueError:
            targets = []
        return {"id": row[0], "targets": targets, "mode": row[2],
                "status": row[3], "created_at": row[4],
                "started_at": row[5] or None, "finished_at": row[6] or None,
                "error": row[7] or None, "results": None}

    def reset_stale_running(self) -> int:
        """Requeue jobs stuck RUNNING (server died mid-scan)."""
        try:
            with self._lock:
                cur = self._db.execute(
                    "UPDATE jobs SET status = 'QUEUED' WHERE status = 'RUNNING'")
                self._db.commit()
                return int(cur.rowcount or 0)
        except sqlite3.Error:
            return 0


def export_scan(store: ScanStore, scan_id: int,
                format: str = "json") -> Optional[Any]:
    """Re-emit a stored scan: JSON/CSV string, SARIF string, else None.

    History exports cover findings + summary.  Full HTML reports are only
    produced live (they need the discovery payload, which is not stored).
    SARIF uses the same rule ids as live reports (``reporting.build_sarif``)
    so IDE consumers see one stable contract.
    """
    scan = store.get_scan(scan_id)
    if not scan:
        return None
    findings = store.findings_for(scan_id)
    kind = str(format or "json").lower()
    if kind == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["severity", "type", "url", "detail"])
        for finding in findings:
            detail = finding.get("description") or finding.get("detail") or ""
            if isinstance(detail, dict):
                detail = json.dumps(detail, default=str)
            writer.writerow([finding.get("severity", ""),
                             finding.get("type", ""),
                             finding.get("url", ""), str(detail)[:500]])
        return buf.getvalue()
    if kind == "sarif":
        try:
            from modules.reporting import build_sarif
            return json.dumps(
                build_sarif(scan.get("target", "unknown"), findings),
                indent=2, default=str)
        except Exception as exc:
            logger.debug("sarif export failed: %s", exc)
            return None
    return json.dumps({"scan": scan, "findings": findings}, indent=2,
                      default=str)


def open_store(path: Optional[str] = None) -> Optional[ScanStore]:
    """Open the store, returning None (not raising) when unusable."""
    try:
        return ScanStore(path)
    except Exception as exc:  # pragma: no cover - never break callers
        logger.debug("open_store failed: %s", exc)
        return None
