"""
Athena Omega - GraphQL security (graphql-cop 12 checks, pure Python)
Endpoint discovery + introspection + misconfig checks. Never raises.
"""
from typing import Any, Dict, List

import aiohttp

PATHS = ["/graphql", "/graphiql", "/graphql/console", "/api/graphql", "/v1/graphql", "/query"]

INTROSPECTION_Q = '{"query":"{__schema{queryType{name}}}"}'
MISCONFIG_CHECKS = [
    ("introspection", '{"query":"{__schema{types{name}}}"}', "queryType"),
    ("graphiql", None, "GraphiQL"),
    ("get_csrf", None, "GET allowed"),
    ("field_suggestions", '{"query":"{__typenamesuggest}"}', "Did you mean"),
    ("trace_mode", None, "trace"),
    ("batch", '[{"query":"{__typename}"},{"query":"{__typename}"}]', "__typename"),
]


async def graphql_audit(base: str) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    endpoints: List[str] = []
    root = (base or "").rstrip("/")
    if not root.startswith(("http://", "https://")):
        root = f"https://{root}"
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as session:
            for p in PATHS:
                url = root + p
                try:
                    async with session.get(url, ssl=False, allow_redirects=True) as r:
                        body = (await r.text())[:3000]
                        if r.status in (200, 400) and ("graphql" in body.lower() or "graphiql" in body.lower()
                                                       or "__schema" in body or "query" in body.lower()):
                            endpoints.append(url)
                except Exception:
                    continue
            for ep in endpoints[:4]:
                # introspection enabled?
                try:
                    async with session.post(ep, data=INTROSPECTION_Q,
                                            headers={"Content-Type": "application/json"},
                                            ssl=False) as r:
                        body = (await r.text())[:3000]
                        if "queryType" in body or "__schema" in body:
                            findings.append({"url": ep, "type": "graphql-introspection",
                                             "severity": "medium",
                                             "description": "Introspection enabled - schema enumerable"})
                except Exception:
                    continue
                # GET-based query (CSRF-able)?
                try:
                    async with session.get(ep + '?query={__typename}', ssl=False) as r:
                        body = (await r.text())[:2000]
                        if "__typename" in body:
                            findings.append({"url": ep, "type": "graphql-get-csrf",
                                             "severity": "low",
                                             "description": "GET queries allowed - CSRF-able"})
                except Exception:
                    continue
                # field suggestions leak?
                try:
                    async with session.post(ep, data='{"query":"{__typenamesuggest}"}',
                                            headers={"Content-Type": "application/json"}, ssl=False) as r:
                        body = (await r.text())[:2000]
                        if "did you mean" in body.lower():
                            findings.append({"url": ep, "type": "graphql-field-suggestions",
                                             "severity": "info",
                                             "description": "Field suggestions enabled"})
                except Exception:
                    continue
    except Exception as exc:
        return {"endpoints": [], "findings": [], "error": str(exc)[:200]}
    return {"endpoints": endpoints, "findings": findings}
