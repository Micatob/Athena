"""
Athena Omega - VHost/SNI enumeration (Athena native dual-layer)
Curl-only logic ported to aiohttp: L7 Host-header overrides compared to
baseline. CDN catch-all guard via control names. Never raises.
"""
import difflib
from typing import Any, Dict, List
from urllib.parse import urlparse

import aiohttp

DEFAULT_WORDLIST = [
    "admin", "internal", "dev", "staging", "test", "api", "beta",
    "portal", "secure", "vpn", "mail", "owa", "intranet", "cms",
    "blog", "shop", "app", "mobile", "cdn", "static",
]

CDN_MARKERS = ("cloudflare", "akamai", "fastly", "incapsula", "sucuri",
               "attention required", "edge", "catch-all", "unknown host")

VOLATILE_RE = None  # normalized inline (avoid re import cost at module load)


def _normalize(body: str) -> str:
    import re
    body = re.sub(r"[0-9a-f]{8,}-[0-9a-f-]{4,}", "TOKEN", body)
    body = re.sub(r"ray-?id[^<]{0,40}", "RAY", body, flags=re.I)
    body = re.sub(r"\d{10,}", "EPOCH", body)
    return body


async def _fetch(session: aiohttp.ClientSession, url: str, host: str) -> Dict[str, Any]:
    try:
        async with session.get(url, headers={"Host": host}, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as r:
            body = await r.text()
            return {"status": r.status, "length": len(body), "body": _normalize(body[:8000])}
    except Exception as exc:
        return {"status": 0, "length": 0, "body": "", "error": str(exc)[:120]}


async def vhost_enum(target: str, wordlist: List[str] = None, limit: int = 40) -> Dict[str, Any]:
    words = (wordlist or DEFAULT_WORDLIST)[: max(1, limit)]
    base = target if target.startswith(("http://", "https://")) else f"https://{target}"
    try:
        host = urlparse(base).hostname or target
    except Exception:
        host = target
    findings: List[Dict[str, Any]] = []
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            baseline = await _fetch(session, base, host)
            # two made-up controls: if they match baseline, host is catch-all
            controls = []
            for ctrl in (f"no-such-vhost-xyz123.{host}", f"zzcontrol999.{host}"):
                controls.append(await _fetch(session, base, ctrl))
            catch_all = all(
                c.get("status") == baseline.get("status") and
                difflib.SequenceMatcher(None, c.get("body", ""), baseline.get("body", "")).ratio() > 0.92
                for c in controls if c.get("status")
            )
            if catch_all:
                return {"target": target, "baseline": baseline.get("status"),
                        "catch_all": True, "findings": [],
                        "note": "shared catch-all (CDN-style), candidates suppressed"}
            for w in words:
                cand = f"{w}.{host}" if "." in host else w
                resp = await _fetch(session, base, cand)
                if not resp.get("status"):
                    continue
                low = resp.get("body", "").lower()
                if any(m in low for m in CDN_MARKERS):
                    continue
                ratio = difflib.SequenceMatcher(None, resp.get("body", ""), baseline.get("body", "")).ratio()
                if resp.get("status") != baseline.get("status") or ratio < 0.85 or resp.get("length", 0) != baseline.get("length", 0) and ratio < 0.95:
                    sev = "medium" if resp.get("status", 0) in (200, 301, 302, 401, 403) else "low"
                    if "internal" in low or "admin" in low or "debug" in low:
                        sev = "high"
                    findings.append({"vhost": cand, "status": resp.get("status"),
                                     "length": resp.get("length"), "severity": sev,
                                     "type": "hidden-vhost", "confidence": round(1 - ratio, 2)})
    except Exception as exc:
        return {"target": target, "findings": [], "error": str(exc)[:200]}
    return {"target": target, "catch_all": False, "findings": findings,
            "probed": len(words)}
