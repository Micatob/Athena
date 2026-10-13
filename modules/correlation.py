"""Cross-tool finding correlation (native scanner + external engines).

Two scanners that agree on the same URL are stronger evidence than either
alone; two scanners that never agree are a warning.  This module merges
native Athena findings with external tool findings (nuclei, and any future
engine that emits the same shape) on ``(host + path, parameter, vuln
class)``:

* a native finding + a tool match on the same group merge into one finding
  with ``sources: [...]``, ``corroborated: True`` and bumped confidence;
* tool-only matches are kept but labelled ``tool_only: True`` so the
  executive summary can separate proven signal from single-source leads;
* native-only findings pass through untouched.

Deterministic - no LLM involved.  Native findings always win as the merge
base (they carry the richer evidence block).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl

logger = logging.getLogger("athena.correlation")

_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def _rank(conf: Any) -> int:
    return _CONF_RANK.get(str(conf or "").strip().lower(), 0)


def _unrank(rank: int) -> str:
    for name, value in _CONF_RANK.items():
        if value == rank:
            return name
    return "low"


def normalize_class(type_text: str = "", template: str = "") -> str:
    """Map a finding type / nuclei template id onto a vuln class key."""
    text = f"{type_text or ''} {template or ''}".lower()
    rules = (
        ("sqli", ("sql injection", "sqli", "sql-injection", "blind sqli",
                  "time-based", "union")),
        ("xss", ("cross-site scripting", "xss", "reflected xss",
                 "stored xss", "dom xss")),
        ("ssti", ("template injection", "ssti", "jinja", "twig",
                  "freemarker", "velocity", "erb", "smarty")),
        ("lfi", ("file inclusion", "lfi", "rfi", "path traversal",
                 "directory traversal", "traversal")),
        ("ssrf", ("ssrf", "server-side request forgery")),
        ("xxe", ("xxe", "xml external entity")),
        ("ldap", ("ldap injection", "ldap")),
        ("cmdi", ("command injection", "os command", "rce",
                  "remote code execution")),
        ("idor", ("idor", "insecure direct object")),
        ("auth", ("authentication bypass", "auth bypass", "broken auth",
                  "default credential", "weak credential")),
        ("headers", ("security header", "missing header", "clickjacking",
                     "x-frame", "hsts", "content-security-policy", "csp")),
        ("methods", ("http method", "trace method", "options method",
                     "dangerous method")),
        ("csrf", ("csrf", "cross-site request forgery")),
        ("redirect", ("open redirect", "unvalidated redirect")),
        ("info", ("disclosure", "exposure", "information", "fingerprint",
                  "version", "takeover", "dns", "ssl", "tls", "certificate")),
    )
    for key, markers in rules:
        if any(marker in text for marker in markers):
            return key
    return "other"


def normalize_path(url: str = "") -> str:
    """``scheme://host/path`` lowercased, no trailing slash, no query."""
    try:
        parsed = urlparse(str(url or "").strip())
    except Exception:
        return str(url or "").strip().lower()
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "/").rstrip("/") or "/"
    scheme = (parsed.scheme or "https").lower()
    if not host:
        return (parsed.path or "").lower().rstrip("/") or "/"
    return f"{scheme}://{host}{path.lower()}"


def url_params(url: str = "") -> List[str]:
    """Query parameter names in ``url`` (decoded, order-preserved)."""
    try:
        query = urlparse(str(url or "")).query
    except Exception:
        return []
    names: List[str] = []
    for name, _ in parse_qsl(query, keep_blank_values=True):
        if name and name not in names:
            names.append(name)
    return names


def extract_param(finding: Dict[str, Any]) -> Optional[str]:
    """Explicit parameter name, or None when the finding has none."""
    if not isinstance(finding, dict):
        return None
    for key in ("parameter", "param"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        for key in ("parameter", "param"):
            value = evidence.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def finding_template(finding: Dict[str, Any]) -> str:
    if not isinstance(finding, dict):
        return ""
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        template = evidence.get("template")
        if isinstance(template, str) and template.strip():
            return template.strip()
    return ""


def is_tool_finding(finding: Dict[str, Any]) -> bool:
    """True for nuclei findings (the cross-tool merge input).

    sqlmap/dalfox findings are *confirmations*, not independent detections -
    they ride along on the native side.
    """
    if not isinstance(finding, dict):
        return False
    if str(finding.get("source") or "").strip().lower() == "nuclei":
        return True
    evidence = finding.get("evidence")
    return (isinstance(evidence, dict)
            and str(evidence.get("tool") or "").strip().lower() == "nuclei")


def _params_match(native_param: Optional[str],
                  tool_finding: Dict[str, Any]) -> bool:
    """Parameter compatibility for a merge candidate pair."""
    if not native_param:
        # Param-less native finding (headers, methods, disclosure): a tool
        # match on the same path+class corroborates regardless of params.
        return True
    tool_param = extract_param(tool_finding)
    if tool_param:
        return tool_param.lower() == native_param.lower()
    # Tool match carries no explicit param: corroborate when the native
    # param appears in the matched URL's query string (or the URL has no
    # query at all, e.g. a header check on the bare path).
    params = url_params(tool_finding.get("url", ""))
    if not params:
        return True
    return native_param.lower() in [p.lower() for p in params]


def group_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    """``(path, vuln_class, param or '')`` grouping key."""
    return (normalize_path(finding.get("url", "")),
            normalize_class(str(finding.get("type", "")),
                            finding_template(finding)),
            (extract_param(finding) or "").lower())


@dataclass
class CorrelateResult:
    merged: List[Dict[str, Any]]
    corroborated: int = 0
    tool_only: int = 0
    native_only: int = 0
    groups: int = 0

    def summary(self) -> Dict[str, Any]:
        return {
            "total": len(self.merged),
            "corroborated": self.corroborated,
            "tool_only": self.tool_only,
            "native_only": self.native_only,
            "groups": self.groups,
        }


def _merge_pair(native: Dict[str, Any],
                tools: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Fold ``tools`` into a copy of ``native`` (native wins as base)."""
    merged = dict(native)
    sources = [str(native.get("source") or "athena-native")]
    corroborated_by: List[str] = list(merged.get("corroborated_by") or [])
    best = _rank(native.get("confidence"))
    notes: List[str] = []
    for tool in tools:
        template = finding_template(tool) or str(tool.get("id", "tool"))
        label = f"nuclei:{template}"
        if label not in sources:
            sources.append(label)
        if template not in corroborated_by:
            corroborated_by.append(template)
        best = max(best, _rank(tool.get("confidence")))
        matcher = ""
        evidence = tool.get("evidence")
        if isinstance(evidence, dict):
            matcher = str(evidence.get("matcher") or "")
        note = f"nuclei template {template} matched"
        if matcher:
            note += f" ({matcher})"
        notes.append(note)
    merged["sources"] = sources
    merged["corroborated"] = True
    merged["corroborated_by"] = corroborated_by
    merged["confidence"] = _unrank(best)
    if notes:
        merged["description"] = (
            f"{merged.get('description', '')} "
            f"[Corroborated: {'; '.join(notes)}]").strip()
    return merged


def correlate_tool_findings(
    native_findings: Optional[List[Dict[str, Any]]],
    tool_findings: Optional[List[Dict[str, Any]]],
) -> CorrelateResult:
    """Merge native + tool findings; return merged list and counts."""
    natives = [f for f in (native_findings or []) if isinstance(f, dict)]
    tools = [f for f in (tool_findings or []) if isinstance(f, dict)]

    # Index tool findings by (path, class) for candidate lookup.
    by_group: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for tool in tools:
        key = (normalize_path(tool.get("url", "")),
               normalize_class(str(tool.get("type", "")),
                               finding_template(tool)))
        by_group.setdefault(key, []).append(tool)

    used_tool_ids: set = set()
    merged: List[Dict[str, Any]] = []
    corroborated = 0
    native_only = 0

    for native in natives:
        path = normalize_path(native.get("url", ""))
        cls = normalize_class(str(native.get("type", "")),
                              finding_template(native))
        native_param = extract_param(native)
        matches = [t for t in by_group.get((path, cls), [])
                   if id(t) not in used_tool_ids
                   and _params_match(native_param, t)]
        if matches:
            for tool in matches:
                used_tool_ids.add(id(tool))
            merged.append(_merge_pair(native, matches))
            corroborated += 1
        else:
            merged.append(native)
            native_only += 1

    tool_only = 0
    for tool in tools:
        if id(tool) in used_tool_ids:
            continue
        leftover = dict(tool)
        leftover["tool_only"] = True
        sources = leftover.get("sources")
        if not isinstance(sources, list) or not sources:
            template = finding_template(tool)
            leftover["sources"] = (
                [f"nuclei:{template}"] if template else ["nuclei"])
        merged.append(leftover)
        tool_only += 1

    groups = len({group_key(f) for f in merged}) if merged else 0
    return CorrelateResult(merged=merged, corroborated=corroborated,
                           tool_only=tool_only, native_only=native_only,
                           groups=groups)
