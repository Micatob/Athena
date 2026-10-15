"""
Athena Omega - Settings Registry (RedAmon 500+ settings concept, Athena scale)
============================================================================
Single description of every tunable: key, type, default, bounds, stealth cap.
Derived lists (rate caps, timeouts) are queries over it, never hand-aligned.
Wraps FrameworkConfig so old ATHENA_*/AETHELRED_* env vars keep working.
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Setting:
    key: str
    type: str  # int | float | bool | str
    default: Any
    min: Optional[float] = None
    max: Optional[float] = None
    stealth_max: Optional[float] = None  # hard cap while STEALTH_MODE on
    help: str = ""
    env: str = ""


REGISTRY: List[Setting] = [
    Setting("HTTP_TIMEOUT", "int", 10, 2, 60, 15, "Per-request seconds", "HTTP_TIMEOUT"),
    Setting("HTTP_MAX_CONNECTIONS", "int", 60, 1, 200, 20, "Concurrent connections", "HTTP_MAX_CONNECTIONS"),
    Setting("SCANNING_THREADS", "int", 40, 1, 200, 20, "Scanner concurrency", "SCANNING_THREADS"),
    Setting("DISCOVERY_THREADS", "int", 25, 1, 100, 15, "Discovery concurrency", "DISCOVERY_THREADS"),
    Setting("BRUTEFORCE_THREADS", "int", 3, 1, 20, 3, "Bruteforce concurrency", "BRUTEFORCE_THREADS"),
    Setting("STEALTH_MIN_DELAY", "float", 0.1, 0.0, 5.0, None, "Min jitter s", "STEALTH_MIN_DELAY"),
    Setting("STEALTH_MAX_DELAY", "float", 0.5, 0.0, 10.0, 1.5, "Max jitter s", "STEALTH_MAX_DELAY"),
    Setting("RATE_LIMIT_RPS", "int", 150, 1, 1000, 50, "External engine req/s", "ATHENA_RATE_RPS"),
    Setting("NUCLEI_TIMEOUT", "int", 600, 60, 3600, None, "Nuclei wall clock s", "ATHENA_NUCLEI_TIMEOUT"),
    Setting("SQLMAP_TIMEOUT", "int", 300, 30, 1800, None, "sqlmap cap s", "ATHENA_SQLMAP_TIMEOUT"),
    Setting("DALFOX_TIMEOUT", "int", 300, 30, 1800, None, "dalfox per-URL cap s", "ATHENA_DALFOX_TIMEOUT"),
    Setting("TOOL_FINDINGS_CAP", "int", 100, 10, 1000, None, "Max findings per tool", "ATHENA_TOOL_CAP"),
    Setting("VHOST_WORDLIST_SIZE", "int", 2471, 100, 10000, None, "VHost candidates", "ATHENA_VHOST_SIZE"),
    Setting("JS_MAX_FILES", "int", 50, 5, 500, None, "JS files per host", "ATHENA_JS_MAX"),
    Setting("OOB_WAIT", "float", 60.0, 5.0, 600.0, None, "OOB callback wait s", "ATHENA_OOB_WAIT"),
    Setting("AGENT_MAX_STEPS", "int", 25, 1, 200, None, "Agent ReAct steps", "ATHENA_AGENT_STEPS"),
    Setting("FIRETEAM_MAX", "int", 5, 1, 12, None, "Fireteam members", "ATHENA_FIRETEAM_MAX"),
]

_BY_KEY = {s.key: s for s in REGISTRY}


def get(key: str, stealth: bool = False) -> Any:
    s = _BY_KEY.get(key)
    if s is None:
        raise KeyError(f"unknown setting {key!r}")
    raw = os.getenv(s.env or f"ATHENA_{key}", "")
    val: Any = s.default
    try:
        if raw != "":
            if s.type == "int":
                val = int(raw)
            elif s.type == "float":
                val = float(raw)
            elif s.type == "bool":
                val = str(raw).lower() in ("1", "true", "yes", "on")
            else:
                val = raw
    except Exception:
        val = s.default
    try:
        if isinstance(val, (int, float)):
            if s.min is not None:
                val = max(val, s.min)
            if s.max is not None:
                val = min(val, s.max)
            if stealth and s.stealth_max is not None:
                val = min(val, s.stealth_max)
    except Exception:
        pass
    return val


def as_dict(stealth: bool = False) -> Dict[str, Any]:
    return {s.key: get(s.key, stealth=stealth) for s in REGISTRY}


def describe() -> List[Dict[str, Any]]:
    return [
        {"key": s.key, "type": s.type, "default": s.default, "min": s.min,
         "max": s.max, "stealth_max": s.stealth_max, "help": s.help, "env": s.env}
        for s in REGISTRY
    ]
