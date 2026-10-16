"""
Athena Omega - Supply-chain recon (Athena native, offline)
Harvests npm package set from JS text (no new fetches), builds SBOM,
verdicts against local OSV cache if present. Passive + offline. Never raises.
"""
import json
import os
import re
from typing import Any, Dict, List

IMPORT_RE = re.compile(r"""(?:import\s+[^'"]*?from\s*['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\)|from\s*['"]([^'"]+)['"]\s+import)""")
PKG_RE = re.compile(r"node_modules/(@?[^/'\"]+(?:/[^/'\"]+)?)", re.I)
WAPPALY_RE = re.compile(r'"?(?:technology|name)"?\s*:\s*"([^"]+)"', re.I)


def harvest_packages(js_texts: List[str], technologies: List[str] = None) -> List[str]:
    pkgs: List[str] = []
    for body in js_texts or []:
        b = str(body or "")[:400000]
        for m in IMPORT_RE.finditer(b):
            name = m.group(1) or m.group(2) or m.group(3) or ""
            name = name.strip().split("/")[0] if not name.startswith("@") else "/".join(name.strip().split("/")[:2])
            if name and not name.startswith((".", "/", "http")):
                pkgs.append(name.lower())
        for m in PKG_RE.finditer(b):
            pkgs.append(m.group(1).lower())
    for t in technologies or []:
        ts = str(t).lower()
        if any(x in ts for x in ("react", "vue", "angular", "next", "jquery", "lodash", "express")):
            pkgs.append(ts.split()[0])
    # normalize + dedup, drop relative/built-ins
    skip = {"fs", "path", "http", "https", "crypto", "os", "util", "events", "react-dom"}
    uniq = sorted({p for p in pkgs if p and p not in skip and len(p) < 120})
    return uniq[:300]


def _load_osv_db(path: str = "") -> Dict[str, Any]:
    p = path or os.getenv("ATHENA_OSV_DB", os.path.join(os.path.expanduser("~"), ".athena", "osv.db.json"))
    try:
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as fh:
                d = json.load(fh)
                if isinstance(d, dict):
                    return d
    except Exception:
        pass
    return {}


def verdict_packages(packages: List[str], osv_db: Dict[str, Any] = None) -> Dict[str, Any]:
    db = osv_db if isinstance(osv_db, dict) else _load_osv_db()
    mal = set(str(db.get("malicious", []) or []))
    vuln = db.get("vulnerable", {}) if isinstance(db.get("vulnerable"), dict) else {}
    findings: List[Dict[str, Any]] = []
    sbom = {"bomFormat": "CycloneDX", "components": [{"name": p, "type": "library"} for p in packages or []]}
    for p in packages or []:
        pl = p.lower()
        if pl in {str(x).lower() for x in mal} or pl.startswith("mal-"):
            findings.append({"package": p, "type": "mal-package", "severity": "critical",
                             "description": f"Package {p} flagged MAL- (offline OSV)"})
        elif pl in {str(k).lower(): v for k, v in vuln.items()}:
            ids = vuln.get(p, vuln.get(pl, []))
            findings.append({"package": p, "type": "vuln-package", "severity": "high",
                             "description": f"Package {p} has known CVEs: {ids}"})
    return {"packages": packages, "sbom_components": len(sbom["components"]),
            "sbom": sbom if len(packages or []) <= 100 else {"bomFormat": "CycloneDX", "truncated": True},
            "findings": findings, "offline": True,
            "db_loaded": bool(db)}
