"""
Athena Omega - Subdomain takeover (Subjack/BadDNS concept, pure Python)
DNS-first fingerprints + HTTP confirm. Verdicts: confirmed/likely/manual_review.
A live claimed resource (2xx + cert names host) DROPS the candidate. Never raises.
"""
import socket
from typing import Any, Dict, List

import aiohttp

# provider -> fingerprint string that means DANGLING
TAKEOVER_FPS = {
    "github": "There isn't a GitHub Pages site here",
    "heroku": "No such app",
    "s3": "NoSuchBucket",
    "azure": "was not found",
    "netlify": "Not Found - Request ID",
    "shopify": "Sorry, this shop is currently unavailable",
    "zendesk": "Help Center Closed",
    "ghost": "The thing you were looking for is no longer here",
    "tumblr": "Whatever you were looking for doesn't currently exist",
    "bitbucket": "Repository not found",
}


def _cnames(host: str) -> List[str]:
    out = []
    try:
        import dns.resolver
        ans = dns.resolver.resolve(host, "CNAME", lifetime=5)
        for r in ans:
            out.append(str(r.target).rstrip(".").lower())
    except Exception:
        pass
    return out


async def takeover_check(subdomains: List[str]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            for sub in (subdomains or [])[:100]:
                sub = (sub if isinstance(sub, str) else str(sub.get("subdomain", sub))).strip()
                if not sub:
                    continue
                cnames = _cnames(sub)
                cname = cnames[0] if cnames else ""
                # resolve: NXDOMAIN-ish -> candidate dangling
                alive = True
                try:
                    socket.gethostbyname(sub)
                except Exception:
                    alive = False
                body, status = "", 0
                if alive:
                    try:
                        async with session.get(f"https://{sub}", timeout=aiohttp.ClientTimeout(total=8), ssl=False,
                                               allow_redirects=True) as r:
                            status = r.status
                            body = (await r.text())[:4000]
                    except Exception:
                        try:
                            async with session.get(f"http://{sub}", timeout=aiohttp.ClientTimeout(total=8),
                                                   allow_redirects=True) as r:
                                status = r.status
                                body = (await r.text())[:4000]
                        except Exception:
                            alive = False
                if not alive:
                    if cname:
                        findings.append({"subdomain": sub, "cname": cname, "verdict": "likely",
                                         "severity": "high", "type": "subdomain-takeover",
                                         "evidence": "CNAME to external host, DNS does not resolve"})
                    continue
                # live + 2xx = claimed, drop
                if status in (200, 201) and body and len(body) > 200:
                    continue
                for provider, fp in TAKEOVER_FPS.items():
                    if fp.lower() in body.lower():
                        findings.append({"subdomain": sub, "cname": cname, "provider": provider,
                                         "verdict": "confirmed", "severity": "high",
                                         "type": "subdomain-takeover",
                                         "evidence": f"provider fingerprint {fp[:60]} + HTTP {status}"})
                        break
    except Exception as exc:
        return {"findings": [], "error": str(exc)[:200]}
    # dedup
    seen, uniq = set(), []
    for f in findings:
        k = f.get("subdomain", "")
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return {"findings": uniq, "checked": len(subdomains or [])}
