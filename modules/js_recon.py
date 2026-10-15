"""
Athena Omega - JS recon (jsluice concept, pure Python, offline-safe)
Fetches JS, extracts endpoints/secrets/sinks. Severity downgrades built-in:
sink needs user-controlled source within 400 chars else low/info.
Never raises. Bounded: max files, max bytes.
"""
import re
from typing import Any, Dict, List

import aiohttp

SECRET_RES = [
    (re.compile(r"aws_access_key_id\s*[:=]\s*['\"]?(AKIA[0-9A-Z]{16})", re.I), "aws-key", "high"),
    (re.compile(r"aws_secret[^'\"]{0,20}['\"]([A-Za-z0-9/+=]{32,})", re.I), "aws-secret", "high"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}", re.I), "github-pat", "high"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}", re.I), "github-token", "high"),
    (re.compile(r"sk-live-[A-Za-z0-9]{16,}", re.I), "stripe-live", "high"),
    (re.compile(r"xox[bap]-[A-Za-z0-9-]{10,}", re.I), "slack-token", "high"),
    (re.compile(r"AIza[0-9A-Za-z_-]{30,}", re.I), "gcp-key", "medium"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private-key", "high"),
    (re.compile(r"password\s*[:=]\s*['\"][^'\"]{6,}['\"]", re.I), "password-assign", "medium"),
]

ENDPOINT_RE = re.compile(r"""(?:"|')(/(?:api|v\d|graphql|rest|auth|admin|debug|internal)[\w\-/{}.$?=&%]*)""", re.I)
GQL_RE = re.compile(r"(query|mutation|subscription)\s+[\w]+\s*[\(\{]", re.I)
WS_RE = re.compile(r"wss?://[\w.\-:/]+", re.I)

SINK_RES = [
    (re.compile(r"\.innerHTML\s*="), "innerHTML"),
    (re.compile(r"document\.write\s*\("), "document.write"),
    (re.compile(r"eval\s*\("), "eval"),
    (re.compile(r"new\s+Function\s*\("), "Function"),
    (re.compile(r"__proto__"), "__proto__"),
    (re.compile(r"setTimeout\s*\(\s*['\"]"), "setTimeout-string"),
]

SOURCE_RES = re.compile(r"(location\.hash|location\.search|document\.URL|postMessage|localStorage|window\.name|referrer)", re.I)
LIB_SKIP = re.compile(r"jquery(\.min|\.slim|\-migrate|\-ui)?\.js$", re.I)


def _is_lib(url: str) -> bool:
    return bool(LIB_SKIP.search(url or ""))


async def js_recon(urls: List[str], max_files: int = 20) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    endpoints: List[str] = []
    scanned = 0
    targets = [u for u in (urls or []) if isinstance(u, str) and u.endswith(".js")][: max(1, max_files)]
    # also probe common bundle paths is caller's job; here just scan given list
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as session:
            for js_url in targets:
                if _is_lib(js_url) and "plugin" not in js_url.lower():
                    continue  # skip jquery core only
                try:
                    async with session.get(js_url, ssl=False) as r:
                        if r.status != 200:
                            continue
                        ctype = r.headers.get("Content-Type", "")
                        if "javascript" not in ctype and "text/plain" not in ctype and "octet" not in ctype and ctype:
                            pass
                        body = (await r.text())[:400000]
                except Exception:
                    continue
                scanned += 1
                # secrets: must hold credential, drop UI labels/localhost
                for rx, name, sev in SECRET_RES:
                    for m in rx.finditer(body):
                        val = m.group(0)[:120]
                        low = val.lower()
                        if any(x in low for x in ("example", "placeholder", "your-", "xxx", "localhost", "127.0.0.1",
                                                  "staging", "internal", "test123")):
                            findings.append({"url": js_url, "type": f"js-dev-reference",
                                             "severity": "info", "evidence": val[:80]})
                            continue
                        if "localhost" in body[max(0, m.start()-40):m.start()].lower():
                            sev_use = "info"
                        else:
                            sev_use = sev
                        findings.append({"url": js_url, "type": f"js-secret-{name}",
                                         "severity": sev_use, "evidence": val[:80]})
                for m in ENDPOINT_RE.finditer(body):
                    endpoints.append(m.group(1)[:200])
                if GQL_RE.search(body):
                    findings.append({"url": js_url, "type": "js-graphql-ref", "severity": "info",
                                     "evidence": "GraphQL operation in JS"})
                for m in WS_RE.finditer(body):
                    endpoints.append(m.group(0)[:200])
                # sinks with source proximity
                for rx, sname in SINK_RES:
                    if sname == "__proto__" and '"__proto__"' not in body and "'__proto__'" not in body:
                        pass
                    for m in rx.finditer(body):
                        if sname == 'Function("return this")' or (sname == "Function" and "return this" in body[m.start():m.start()+60]):
                            continue
                        window = body[max(0, m.start()-400):m.start()]
                        has_source = bool(SOURCE_RES.search(window))
                        if has_source:
                            sev_use = "medium"
                        else:
                            sev_use = "low" if "plugin" not in js_url.lower() else "info"
                        # minified line: point at closest sink
                        findings.append({"url": js_url, "type": f"js-sink-{sname}",
                                         "severity": sev_use,
                                         "evidence": body[max(0, m.start()-80):m.start()+80][:160]})
                        break  # one per sink kind per file
    except Exception as exc:
        return {"findings": [], "endpoints": [], "error": str(exc)[:200]}
    # dedup
    seen, uniq = set(), []
    for f in findings:
        k = (f.get("url", ""), f.get("type", ""))
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return {"findings": uniq, "endpoints": sorted(set(endpoints))[:200], "scanned": scanned}
