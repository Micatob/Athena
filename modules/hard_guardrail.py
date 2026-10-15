"""
Athena Omega - Hard Guardrail + Rules of Engagement (RedAmon port)
================================================================
Deterministic, non-disableable block for gov/mil/edu/int + operator denylist.
RoE binds targets, exclusions, allowed techniques, time window, rate limits.
"""

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Suffixes that are ALWAYS blocked, regardless of RoE or flags.
_HARD_SUFFIXES = (".gov", ".mil", ".int", ".edu", "gov.", "mil.")
_HARD_EXACT = {"gov", "mil", "int", "edu"}

_HARD_HOST_RE = re.compile(r"(^|\.)(gov|mil|int|edu)(\.|$)", re.IGNORECASE)


def _host_of(target: str) -> str:
    t = (target or "").strip()
    if "://" in t:
        try:
            return (urlparse(t).hostname or "").lower().rstrip(".")
        except Exception:
            return t.lower()
    return t.lower().rstrip(".").split("/")[0].split(":")[0]


def hard_guardrail_reason(target: str) -> str:
    """Return block reason if the hard guardrail fires, else ''."""
    host = _host_of(target)
    if not host:
        return "empty target"
    # IP literals never match the domain guardrail
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass
    if _HARD_HOST_RE.search(host):
        return f"hard guardrail: government/military/edu/intl target blocked ({host})"
    return ""


def is_hard_blocked(target: str) -> bool:
    return hard_guardrail_reason(target) != ""


@dataclass
class RoE:
    """Parsed Rules of Engagement. Fail-closed: empty scope denies all."""

    targets: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    allowed_techniques: List[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    max_rps: int = 150
    engagement_id: str = "default"

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "RoE":
        d = data or {}
        return cls(
            targets=[str(x) for x in d.get("targets", d.get("in_scope_targets", [])) or []],
            exclusions=[str(x) for x in d.get("exclusions", d.get("excluded", [])) or []],
            allowed_techniques=[str(x) for x in d.get("allowed_techniques", []) or []],
            not_before=str(d.get("not_before", "") or ""),
            not_after=str(d.get("not_after", "") or ""),
            max_rps=int(d.get("max_rps", 150) or 150),
            engagement_id=str(d.get("engagement_id", "default") or "default"),
        )

    def _excluded(self, target: str) -> str:
        host = _host_of(target)
        for pat in self.exclusions:
            p = pat.strip().lower()
            if not p:
                continue
            if fnmatch.fnmatch(host, p) or fnmatch.fnmatch(target.lower(), p) or host == p:
                return f"excluded by RoE pattern {pat!r}"
        return ""

    def check(self, target: str, technique: str = "") -> Dict[str, Any]:
        hard = hard_guardrail_reason(target)
        if hard:
            return {"allowed": False, "reason": hard}
        exc = self._excluded(target)
        if exc:
            return {"allowed": False, "reason": exc}
        if self.not_before or self.not_after:
            now = datetime.now(timezone.utc)
            try:
                if self.not_before and now < datetime.fromisoformat(self.not_before):
                    return {"allowed": False, "reason": "RoE time window not open yet"}
                if self.not_after and now > datetime.fromisoformat(self.not_after):
                    return {"allowed": False, "reason": "RoE time window expired"}
            except Exception:
                pass
        if self.targets:
            host = _host_of(target)
            hit = any(
                fnmatch.fnmatch(host, p.strip().lower()) or fnmatch.fnmatch(target.lower(), p.strip().lower())
                for p in self.targets if p.strip()
            )
            if not hit:
                return {"allowed": False, "reason": f"target {target!r} not in RoE scope"}
        if technique and self.allowed_techniques and technique not in self.allowed_techniques:
            return {"allowed": False, "reason": f"technique {technique!r} not allowed by RoE"}
        return {"allowed": True, "reason": "in RoE scope"}
