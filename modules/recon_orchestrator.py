"""
Athena Omega - Recon Orchestrator (Athena native fan-out/fan-in)
=====================================================================
Runs independent recon tools concurrently, converges, merges into graph_lite.
Every tool: timeout + never-raise + structured status. Missing dep = skip line.

Usage:
    from modules.recon_orchestrator import omega_recon
    out = await omega_recon("https://example.com", discovery_results={...})
"""
import asyncio
import time
from typing import Any, Dict, List

TOOL_TIMEOUTS = {
    "tls": 20, "graphql": 40, "takeover": 60, "vhost": 90,
    "origin": 60, "js": 60, "serialized": 10, "supply_chain": 10,
}


async def _run_guarded(name: str, coro, timeout: float) -> Dict[str, Any]:
    t0 = time.monotonic()
    try:
        res = await asyncio.wait_for(coro, timeout=timeout)
        if not isinstance(res, dict):
            res = {"result": res}
        res.setdefault("tool", name)
        res.setdefault("status", "executed")
        res["duration_s"] = round(time.monotonic() - t0, 2)
        return res
    except asyncio.TimeoutError:
        return {"tool": name, "status": "timeout", "duration_s": round(time.monotonic() - t0, 2)}
    except Exception as exc:
        return {"tool": name, "status": "failed", "error": str(exc)[:200],
                "duration_s": round(time.monotonic() - t0, 2)}


async def omega_recon(target: str, discovery_results: Dict[str, Any] = None,
                      enabled: List[str] = None, wordlist: List[str] = None) -> Dict[str, Any]:
    """Run Omega recon pack. Returns {tools, findings, graph_stats, duration_s}."""
    from .hard_guardrail import hard_guardrail_reason
    disc = discovery_results or {}
    t0 = time.monotonic()
    hard = hard_guardrail_reason(target)
    if hard:
        return {"target": target, "blocked": True, "reason": hard, "tools": [], "findings": []}
    want = set(enabled or ["tls", "graphql", "takeover", "vhost", "origin", "js", "serialized", "supply_chain"])
    tasks = []

    if "tls" in want:
        from .tls_scan import tls_grab
        tasks.append(_run_guarded("tls", asyncio.to_thread(tls_grab, target), TOOL_TIMEOUTS["tls"]))
    if "graphql" in want:
        from .graphql_sec import graphql_audit
        tasks.append(_run_guarded("graphql", graphql_audit(target), TOOL_TIMEOUTS["graphql"]))
    if "takeover" in want:
        from .subdomain_takeover import takeover_check
        subs = [s if isinstance(s, str) else str(s.get("subdomain", s)) for s in disc.get("subdomains", []) or []]
        if subs:
            tasks.append(_run_guarded("takeover", takeover_check(subs), TOOL_TIMEOUTS["takeover"]))
    if "vhost" in want:
        from .vhost_sni import vhost_enum
        tasks.append(_run_guarded("vhost", vhost_enum(target, wordlist=wordlist), TOOL_TIMEOUTS["vhost"]))
    if "origin" in want:
        from .origin_discovery import origin_discover
        tasks.append(_run_guarded("origin", origin_discover(target), TOOL_TIMEOUTS["origin"]))
    if "js" in want:
        from .js_recon import js_recon
        js_urls = [u for u in (disc.get("urls", []) or []) if isinstance(u, str) and u.endswith(".js")]
        # also scan page bodies already harvested for import names is supply-chain's job
        if js_urls:
            tasks.append(_run_guarded("js", js_recon(js_urls), TOOL_TIMEOUTS["js"]))
    if "serialized" in want:
        async def _ser():
            from .serialized_scan import scan_response
            headers = {}
            cookies, params = [], []
            # cheap passive sweep over discovered URLs' query strings
            for u in (disc.get("urls", []) or [])[:50]:
                s = u if isinstance(u, str) else str(u.get("url", ""))
                if "?" in s or "=" in s:
                    params.append(s)
            return scan_response(headers, cookies, params)
        tasks.append(_run_guarded("serialized", _ser(), TOOL_TIMEOUTS["serialized"]))
    if "supply_chain" in want:
        async def _sc():
            from .supply_chain_recon import harvest_packages, verdict_packages
            pkgs = harvest_packages([], disc.get("technologies", []) or [])
            return verdict_packages(pkgs)
        tasks.append(_run_guarded("supply_chain", _sc(), TOOL_TIMEOUTS["supply_chain"]))

    results: List[Dict[str, Any]] = await asyncio.gather(*tasks) if tasks else []
    findings: List[Dict[str, Any]] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        for f in r.get("findings", []) or []:
            if isinstance(f, dict):
                f = dict(f)
                f.setdefault("omega_tool", r.get("tool", ""))
                findings.append(f)
        for f in r.get("confirmed", []) or []:
            if isinstance(f, dict):
                f = dict(f)
                f.setdefault("omega_tool", r.get("tool", ""))
                findings.append(f)
    # merge into graph_lite (best-effort, never breaks scan)
    graph_stats: Dict[str, Any] = {}
    try:
        from .graph_lite import GraphLite
        g = GraphLite(engagement_id="omega")
        g.ingest_discovery(disc, target)
        for f in findings[:500]:
            key = str(f.get("url", f.get("subdomain", f.get("package", f.get("vhost", f.get("ip", "finding"))))))
            g.add_node("Vuln", f"{f.get('type','finding')}:{key[:120]}", f)
            g.add_edge("Target", target, "HAS_FINDING", "Vuln", f"{f.get('type','finding')}:{key[:120]}")
        graph_stats = g.stats()
        g.close()
    except Exception:
        pass
    return {"target": target, "tools": results, "findings": findings,
            "graph_stats": graph_stats, "duration_s": round(time.monotonic() - t0, 2)}
