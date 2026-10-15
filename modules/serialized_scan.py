"""
Athena Omega - Serialized-object passive detection (RedAmon concept)
Detects insecure-deserialization sinks WITHOUT deserializing.
Bomb-safe: base64-decode capped, recursion capped, never eval/pickle.loads.
Writes info + needs_agent_confirmation candidates. Never raises.
"""
import base64
import re
from typing import Any, Dict, List

PATTERNS = [
    (re.compile(r"rO0AB"), "java-serial", "native Java (rO0)"),
    (re.compile(r"aced0005", re.I), "java-serial-hex", "Java hex"),
    (re.compile(r"__VIEWSTATE.{0,20}[A-Za-z0-9+/=]{100,}", re.I), "viewstate", "ASP.NET ViewState"),
    (re.compile(r"O:\d+:\"[^\"]+\":\d+:\{"), "php-object", "PHP object injection sink"),
    (re.compile(r"a:\d+:\{"), "php-array", "PHP serialized array"),
    (re.compile(r"\.phar(?:[^A-Za-z0-9]|$)", re.I), "phar", "PHAR reference"),
    (re.compile(r"!\s*python/object"), "pyyaml", "Python YAML object"),
    (re.compile(r"pickle|__reduce__", re.I), "pickle-ref", "Pickle reference"),
    (re.compile(r"BinaryFormatter", re.I), "dotnet-bin", ".NET BinaryFormatter ref"),
    (re.compile(r"jackson.*polymorphic|@class|@type", re.I), "jackson-poly", "Jackson polymorphic"),
    (re.compile(r"Marshal\.load|_marshal", re.I), "ruby-marshal", "Ruby Marshal ref"),
    (re.compile(r"Hessian|hessian", re.I), "hessian", "Hessian ref"),
    (re.compile(r"<java[^>]*>|<string>.*</string>", re.I | re.S), "xstream", "XStream/XMLDecoder shape"),
]

COOKIE_SPLIT = re.compile(r"[;,]\s*")


def _safe_b64_sniff(value: str) -> str:
    """Decode short base64 blobs to reveal nested markers. Capped, never raises."""
    v = (value or "").strip()[:2000]
    if len(v) < 40 or len(v) > 1500:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9+/=_\-\s]+", v):
        return ""
    try:
        pad = "=" * (-len(v.strip()) % 4)
        raw = base64.b64decode(v.strip() + pad, validate=False)[:800]
        # keep printable
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
        return txt[:800]
    except Exception:
        return ""


def scan_values(values: List[str], where: str = "param") -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for val in values or []:
        v = str(val or "")
        if not v:
            continue
        hay = v + " || " + _safe_b64_sniff(v)
        for rx, fmt, desc in PATTERNS:
            try:
                if rx.search(hay):
                    findings.append({
                        "type": "serialized-candidate",
                        "format": fmt,
                        "severity": "info",
                        "where": where,
                        "needs_agent_confirmation": True,
                        "description": f"Possible insecure-deserialization sink ({desc}) - confirm with OOB/timing oracle, do not deserialize",
                        "evidence": v[:160],
                    })
                    break
            except Exception:
                continue
    return findings


def scan_response(headers: Dict[str, str], cookies: List[str], params: List[str]) -> Dict[str, Any]:
    out: List[Dict[str, Any]] = []
    try:
        hvals = [f"{k}: {v}" for k, v in (headers or {}).items()]
        out += scan_values(hvals, "header")
        out += scan_values(cookies or [], "cookie")
        out += scan_values(params or [], "param")
    except Exception:
        pass
    # dedup by format+where
    seen, uniq = set(), []
    for f in out:
        k = (f.get("format"), f.get("where"))
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return {"findings": uniq}
