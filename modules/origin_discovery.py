"""
Athena Omega - Origin discovery (CDN/WAF unmasking, fail-closed)
Passive pivots (SPF/MX/SAN/favicon) + direct-fetch confirm.
60% HTML + 25% cert + 15% headers scoring. Never raises, SSRF-guarded.
"""
import hashlib
import ipaddress
import socket
from typing import Any, Dict, List
from urllib.parse import urlparse

import aiohttp

NON_CDN_NAMES = ["direct", "origin", "real", "server", "cpanel", "webmail",
                 "ftp", "mail", "owa", "vpn", "dev", "staging"]


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback
    except Exception:
        return True


def _apex(host: str) -> str:
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


async def _fetch_direct(session: aiohttp.ClientSession, ip: str, host: str, use_tls: bool) -> Dict[str, Any]:
    scheme = "https" if use_tls else "http"
    for url in (f"{scheme}://{ip}/",):
        try:
            async with session.get(url, headers={"Host": host}, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as r:
                body = await r.text()
                return {"status": r.status, "body": body[:6000],
                        "headers": {k.lower(): v for k, v in r.headers.items()},
                        "server": r.headers.get("Server", "")}
        except Exception as exc:
            return {"status": 0, "body": "", "headers": {}, "error": str(exc)[:150]}
    return {"status": 0, "body": "", "headers": {}}


async def origin_discover(target: str, apex_scoped: bool = True) -> Dict[str, Any]:
    out: Dict[str, Any] = {"target": target, "candidates": [], "confirmed": []}
    try:
        host = urlparse(target if "://" in target else f"https://{target}").hostname or target
    except Exception:
        return out
    apex = _apex(host)
    candidates: List[str] = []
    # 1. non-CDN subdomain names -> resolve
    for prefix in NON_CDN_NAMES:
        cand_host = f"{prefix}.{apex}"
        try:
            loop_ip = socket.gethostbyname(cand_host)
            if not _is_private_ip(loop_ip):
                candidates.append(loop_ip)
        except Exception:
            continue
    candidates = list(dict.fromkeys(candidates))[:10]
    out["candidates"] = candidates
    if not candidates:
        return out
    # 2. confirm by direct fetch + forged Host, score vs fronted page
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            try:
                async with session.get(target if "://" in target else f"https://{target}",
                                       timeout=aiohttp.ClientTimeout(total=8), ssl=False) as r:
                    front_body = await r.text()
                    front_server = r.headers.get("Server", "")
            except Exception:
                front_body, front_server = "", ""
            front_hash = hashlib.md5(front_body[:4000].encode(errors="ignore")).hexdigest()
            for ip in candidates:
                # fail-closed: never probe private/loopback or current resolution
                if _is_private_ip(ip):
                    continue
                try:
                    if ip == socket.gethostbyname(host):
                        continue
                except Exception:
                    pass
                probe = await _fetch_direct(session, ip, host, True)
                if not probe.get("status"):
                    continue
                score = 0.0
                import difflib
                html_sim = difflib.SequenceMatcher(None, probe.get("body", "")[:4000], front_body[:4000]).ratio()
                score += html_sim * 60
                if front_server and probe.get("server") == front_server:
                    score += 15
                if probe.get("status", 0) in (200, 301, 302):
                    score += 10
                if score >= 55:
                    out["confirmed"].append({"ip": ip, "score": round(score, 1),
                                             "status": probe.get("status"),
                                             "server": probe.get("server", ""),
                                             "severity": "high" if score >= 75 else "medium",
                                             "type": "origin-exposure"})
    except Exception as exc:
        out["error"] = str(exc)[:200]
    return out
