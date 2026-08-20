"""
Athena Verified Cleanup Manager
===============================
Tracks temporary artifacts created during an Athena run and removes them
afterwards with *verification*: removal is only reported as ``verified``
when a follow-up check confirms the artifact is gone (or was never created).

* every registration is written to the compliance audit log
* ``cleanup()`` returns a structured report with per-artifact status
* failures are isolated - one artifact that cannot be removed does not
  prevent the rest from being cleaned
* artifacts can be scrubbed (zero-fill) before removal when requested
"""

import logging
import os
import shutil
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .logging_config import audit_operation


@dataclass
class ArtifactRecord:
    path: str
    kind: str = "file"  # file | dir
    registered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    scrub: bool = False


@dataclass
class CleanupResult:
    """Structured outcome of one artifact removal attempt."""

    path: str
    status: str  # verified | not_found | failed | skipped
    detail: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {"path": self.path, "status": self.status,
                "detail": self.detail}


class CleanupManager:
    def __init__(self, audit=None, engagement_id: str = "",
                 logger: Optional[logging.Logger] = None):
        self.audit = audit
        self.engagement_id = engagement_id
        self.logger = logger or logging.getLogger("athena.cleanup")
        self._records: Dict[str, ArtifactRecord] = {}
        self._lock = threading.Lock()

    # -- registration --------------------------------------------------------

    def register(self, path: str, kind: str = "file",
                 scrub: bool = False) -> None:
        """Register a temporary artifact for later verified removal.

        Raises:
            ValueError: when ``path`` is empty or whitespace-only.
        """
        if not path or not path.strip():
            raise ValueError("artifact path must not be empty")
        normalized = os.path.normpath(path)
        with self._lock:
            self._records[normalized] = ArtifactRecord(
                path=normalized, kind=kind, scrub=scrub
            )
        try:
            audit_operation(
                self.audit,
                operator="athena",
                action="ARTIFACT_REGISTERED",
                target=normalized,
                result="SUCCESS",
                engagement_id=self.engagement_id,
                module="cleanup_manager",
                authorization_decision="AUTHORIZED",
                scope_decision="in_scope",
                evidence_ref=normalized,
                details=f"kind={kind} scrub={scrub}",
            )
        except Exception:
            # audit failures must never break artifact tracking
            pass  # nosec B110

    @property
    def registered(self) -> List[str]:
        with self._lock:
            return list(self._records)

    # -- removal ------------------------------------------------------------

    def _remove_one(self, record: ArtifactRecord) -> CleanupResult:
        path = record.path
        if not os.path.lexists(path):
            return CleanupResult(
                path, "not_found", "artifact never existed; nothing to remove"
            )

        try:
            if record.kind == "dir" and os.path.isdir(path):
                if record.scrub:
                    for root, dirs, files in os.walk(path, topdown=False):
                        for name in files:
                            self._scrub_file(os.path.join(root, name))
                shutil.rmtree(path)
            else:
                if record.scrub and os.path.isfile(path):
                    self._scrub_file(path)
                os.remove(path)
        except OSError as exc:
            return CleanupResult(path, "failed", str(exc))

        if os.path.lexists(path):
            return CleanupResult(path, "failed",
                                 "artifact still present after removal")
        return CleanupResult(path, "verified", "removed and verified")

    @staticmethod
    def _scrub_file(path: str, passes: int = 1) -> None:
        """Overwrite the file contents before deletion."""
        try:
            size = os.path.getsize(path)
            with open(path, "r+b") as handle:
                for _ in range(passes):
                    handle.seek(0)
                    handle.write(b"\x00" * size)
                    handle.flush()
                    os.fsync(handle.fileno())
        except OSError:
            pass  # best effort; deletion still proceeds

    # -- sweep ----------------------------------------------------------------

    def cleanup(self, failures_only: bool = False) -> Dict[str, object]:
        """Remove all registered artifacts; never raises.

        Returns a structured report:

        * ``results`` - per-artifact status
        * ``verified`` - fully cleaned? (False if anything failed)
        * ``remaining`` - artifacts still present
        """
        results: List[Dict[str, str]] = []
        with self._lock:
            records = list(self._records.values())
        for record in records:
            if failures_only and not os.path.lexists(record.path):
                continue  # only retry artifacts still present
            outcome = self._remove_one(record)
            try:
                audit_operation(
                    self.audit,
                    operator="athena",
                    action="ARTIFACT_CLEANUP",
                    target=record.path,
                    result=outcome.status.upper(),
                    engagement_id=self.engagement_id,
                    module="cleanup_manager",
                    authorization_decision="AUTHORIZED",
                    scope_decision="in_scope",
                    evidence_ref=record.path,
                    details=outcome.detail,
                )
            except Exception:
                # audit failures must never break the cleanup sweep
                pass  # nosec B110
            self.logger.info(
                "cleanup %s: %s (%s)",
                record.path,
                outcome.status,
                outcome.detail or "ok",
            )
            results.append(outcome.to_dict())

        with self._lock:
            remaining = [r.path for r in self._records.values()
                         if os.path.lexists(r.path)]
        return {
            "results": results,
            "verified": not remaining,
            "remaining": remaining,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

    def is_verified(self, path: str) -> bool:
        """True when an artifact is absent (verified removed or never made)."""
        return not os.path.lexists(os.path.normpath(path))
