"""Crash-resilient pipeline checkpoints.

A 45-minute scan must survive Ctrl+C, a dead laptop battery, or a traceback
in a late stage: every pipeline stage persists its result the moment it
finishes, and a resumed run reloads completed stages instead of re-running
them.  The long vulnerability-scan stage additionally checkpoints its URL
progress so a kill mid-stage resumes mid-list instead of from URL zero.

Layout per target::

    ~/.athena/checkpoints/<sha256(target)[:16]>/
        state.json          # stage completion map + scan metadata
        <stage>.json        # one payload file per completed stage
        vuln_progress.json  # URL progress for an *incomplete* vuln stage

Payloads are plain JSON (``default=str``) so a checkpoint is inspectable
with any text editor.  Non-JSON-native stage results (CVE dataclasses) are
converted by the caller before saving - see ``modules/cve_mapper.py``.

Staleness: a checkpoint older than ``STALE_AFTER_HOURS`` (24h) is ignored -
resuming yesterday's recon against a changed target would silently corrupt
the report.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("athena.checkpoint")

#: Checkpoints older than this are treated as absent.
STALE_AFTER_HOURS = 24.0

#: Stages in pipeline order. ``vuln_progress`` is a transient helper file,
#: not a completed stage.
STAGES = (
    "discovery",
    "vuln",
    "tools",
    "bruteforce",
    "enumeration",
    "cve",
    "ai",
    "exploitation",
)

PROGRESS_STAGE = "vuln_progress"


def default_base_dir() -> str:
    """Base directory for all checkpoints (``~/.athena/checkpoints``)."""
    return os.path.join(os.path.expanduser("~"), ".athena", "checkpoints")


def target_key(target: str) -> str:
    """Stable, filesystem-safe directory name for ``target``."""
    digest = hashlib.sha256((target or "").strip().lower().encode("utf-8"))
    return digest.hexdigest()[:16]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write_json(path: str, payload: Any) -> None:
    """Write JSON atomically so a kill mid-write never leaves a half file."""
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


class CheckpointManager:
    """Per-target stage checkpoint store."""

    def __init__(self, target: str, base_dir: Optional[str] = None,
                 stale_after_hours: float = STALE_AFTER_HOURS):
        self.target = target or ""
        base = base_dir or default_base_dir()
        self.dir = os.path.join(base, target_key(self.target))
        self.state_path = os.path.join(self.dir, "state.json")
        self.stale_after_hours = float(stale_after_hours or 0) or STALE_AFTER_HOURS
        self._state: Dict[str, Any] = self._read_state()

    # -- state -----------------------------------------------------------

    def _read_state(self) -> Dict[str, Any]:
        try:
            with open(self.state_path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
        return {}

    def _write_state(self) -> None:
        _atomic_write_json(self.state_path, self._state)

    def touch(self, extra: Optional[Dict[str, Any]] = None) -> None:
        """Refresh the timestamp (and optional metadata) without new data.

        Called on SIGINT so the checkpoint records exactly how far the
        interrupted run got.
        """
        self._state.setdefault("target", self.target)
        self._state["updated_at"] = _utcnow()
        if extra:
            for key, value in extra.items():
                if isinstance(value, (str, int, float, bool, list, dict)) \
                        or value is None:
                    self._state[key] = value
        self._write_state()

    # -- staleness ---------------------------------------------------------

    def _updated_at(self) -> Optional[datetime]:
        raw = self._state.get("updated_at") or self._state.get("started_at")
        if not raw:
            return None
        try:
            moment = datetime.fromisoformat(str(raw))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            return moment
        except ValueError:
            return None

    def is_stale(self) -> bool:
        """True when the checkpoint is missing, unreadable, or too old."""
        moment = self._updated_at()
        if moment is None:
            return True
        age_hours = (datetime.now(timezone.utc) - moment).total_seconds() / 3600.0
        return age_hours > self.stale_after_hours

    def completed_stages(self) -> List[str]:
        done = self._state.get("completed_stages") or {}
        if not isinstance(done, dict):
            return []
        return [s for s in STAGES if done.get(s)]

    # -- stages ------------------------------------------------------------

    def _stage_path(self, stage: str) -> str:
        safe = "".join(c if (c.isalnum() or c in ("-", "_")) else "_"
                       for c in stage)
        return os.path.join(self.dir, f"{safe}.json")

    def has(self, stage: str) -> bool:
        """True when ``stage`` has a saved, loadable payload."""
        done = self._state.get("completed_stages") or {}
        if not isinstance(done, dict) or not done.get(stage):
            return False
        return os.path.exists(self._stage_path(stage))

    def save_stage(self, stage: str, payload: Any,
                   meta: Optional[Dict[str, Any]] = None) -> str:
        """Persist ``payload`` for ``stage`` and mark it complete."""
        path = self._stage_path(stage)
        _atomic_write_json(path, payload if payload is not None else {})
        done = self._state.get("completed_stages")
        if not isinstance(done, dict):
            done = {}
            self._state["completed_stages"] = done
        entry: Dict[str, Any] = {"file": os.path.basename(path),
                                 "saved_at": _utcnow()}
        if isinstance(meta, dict):
            entry.update(meta)
        done[stage] = entry
        self._state.setdefault("target", self.target)
        self._state.setdefault("started_at", _utcnow())
        self._state["updated_at"] = _utcnow()
        self._write_state()
        logger.debug("checkpoint saved: %s/%s", self.target, stage)
        return path

    def load_stage(self, stage: str) -> Any:
        """Return the saved payload, or ``None`` when absent/unreadable."""
        if not self.has(stage):
            return None
        try:
            with open(self._stage_path(stage), encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError) as exc:
            logger.warning("checkpoint %s/%s unreadable: %s",
                           self.target, stage, exc)
            return None

    def drop_stage(self, stage: str) -> None:
        done = self._state.get("completed_stages")
        if isinstance(done, dict):
            done.pop(stage, None)
        try:
            os.remove(self._stage_path(stage))
        except OSError:
            pass
        self._write_state()

    # -- vuln URL progress ---------------------------------------------------

    def save_progress(self, payload: Dict[str, Any]) -> str:
        """Persist mid-stage progress (vuln URL list). Not a completion."""
        path = self._stage_path(PROGRESS_STAGE)
        _atomic_write_json(path, payload or {})
        self._state.setdefault("target", self.target)
        self._state["updated_at"] = _utcnow()
        self._write_state()
        return path

    def load_progress(self) -> Optional[Dict[str, Any]]:
        path = self._stage_path(PROGRESS_STAGE)
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    def clear_progress(self) -> None:
        try:
            os.remove(self._stage_path(PROGRESS_STAGE))
        except OSError:
            pass

    # -- lifecycle -----------------------------------------------------------

    def clear(self) -> None:
        """Delete the whole checkpoint (``--restart``)."""
        import shutil
        try:
            shutil.rmtree(self.dir, ignore_errors=True)
        finally:
            self._state = {}

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "dir": self.dir,
            "stale": self.is_stale(),
            "completed_stages": self.completed_stages(),
            "updated_at": self._state.get("updated_at"),
        }
