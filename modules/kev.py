"""
modules.kev.py — CISA Known Exploited Vulnerabilities (KEV) enrichment.
=======================================================================
The KEV catalog is the authoritative list of CVEs exploited in the wild.
Athena cross-references every mapped CVE against it so the report can say
"exploited in the wild — patch first" instead of treating a KEV like any
other CVE.

Contract (same as the tool bridge):

1. **Clean degradation.**  No network, stale cache, corrupt cache → an
   empty catalog and zero annotations, never a crash, never a traceback
   in the scan.
2. **Cached.**  The feed is fetched at most once per ``CACHE_TTL`` and
   stored next to the workspace; offline runs reuse the cache.
3. **Evidence only.**  A CVE is marked KEV only on an exact
   case-insensitive ``cveID`` match.  No fuzzy matching, no guessing.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

#: Canonical CISA feed (JSON).  Mirrored at github.com/cisagov/kev-data.
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

#: Local cache file (workspace-relative by default).
KEV_CACHE_FILE = '.athena_kev_cache.json'

#: Refresh at most once a day; the catalog updates on US business days.
CACHE_TTL_SECONDS = 24 * 3600


def _cache_path(explicit: Optional[str] = None) -> str:
    return explicit or os.path.join(os.getcwd(), KEV_CACHE_FILE)


def _read_cache(path: str, max_age: float) -> Optional[Dict[str, Dict[str, Any]]]:
    try:
        if not os.path.isfile(path):
            return None
        if max_age > 0 and (time.time() - os.path.getmtime(path)) > max_age:
            return None
        with open(path, 'r', encoding='utf-8') as fh:
            payload = json.load(fh)
        catalog = _index(payload)
        return catalog or None
    except Exception as exc:  # pragma: no cover - corrupt cache
        logger.debug('KEV cache unreadable (%s): %s', path, exc)
        return None


def _write_cache(path: str, payload: Dict[str, Any]) -> None:
    try:
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh)
        os.replace(tmp, path)
    except Exception as exc:  # pragma: no cover - read-only workspace
        logger.debug('KEV cache write failed (%s): %s', path, exc)


def _index(payload: Any) -> Dict[str, Dict[str, Any]]:
    """Index a KEV JSON document by upper-cased CVE id."""
    catalog: Dict[str, Dict[str, Any]] = {}
    vulns: Any = []
    if isinstance(payload, dict):
        vulns = payload.get('vulnerabilities', [])
    elif isinstance(payload, list):
        vulns = payload
    if not isinstance(vulns, list):
        return catalog
    for entry in vulns:
        if not isinstance(entry, dict):
            continue
        cve_id = str(entry.get('cveID') or entry.get('cve_id') or entry.get('id') or '').strip().upper()
        if not cve_id:
            continue
        catalog[cve_id] = {
            'cve_id': cve_id,
            'vendor': str(entry.get('vendorProject') or entry.get('vendor') or ''),
            'product': str(entry.get('product') or ''),
            'name': str(entry.get('vulnerabilityName') or entry.get('name') or ''),
            'date_added': str(entry.get('dateAdded') or ''),
            'due_date': str(entry.get('dueDate') or ''),
            'description': str(entry.get('shortDescription') or entry.get('description') or '')[:500],
            'action': str(entry.get('requiredAction') or '')[:500],
            'ransomware_use': str(entry.get('knownRansomwareCampaignUse') or ''),
        }
    return catalog


def fetch_kev_feed(url: str = KEV_URL, timeout: int = 15) -> Optional[Dict[str, Any]]:
    """Download the KEV JSON feed.  Returns None on any failure."""
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Athena-Security-Suite/3.0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.getcode() != 200:
                return None
            return json.loads(resp.read().decode('utf-8'))
    except Exception as exc:
        logger.debug('KEV feed fetch failed: %s', exc)
        return None


def load_kev_catalog(cache_path: Optional[str] = None,
                     max_age: float = CACHE_TTL_SECONDS,
                     refresh: bool = True,
                     url: str = KEV_URL) -> Dict[str, Dict[str, Any]]:
    """Load the KEV catalog (cached, optionally refreshed).  Never raises."""
    try:
        path = _cache_path(cache_path)
        cached = _read_cache(path, max_age)
        if cached is not None and not refresh:
            return cached
        if cached is not None and refresh:
            # Fresh enough and refresh best-effort: serve cache, try update.
            try:
                payload = fetch_kev_feed(url)
            except Exception:
                payload = None
            if payload:
                indexed = _index(payload)
                if indexed:
                    _write_cache(path, payload)
                    return indexed
            return cached
        if refresh:
            payload = fetch_kev_feed(url)
            if payload:
                indexed = _index(payload)
                if indexed:
                    _write_cache(path, payload)
                    return indexed
        return cached or {}
    except Exception:  # pragma: no cover - never break the scan
        return {}


def is_kev(cve_id: str, catalog: Dict[str, Dict[str, Any]]) -> bool:
    """Exact (case-insensitive) KEV membership test."""
    if not cve_id or not catalog:
        return False
    return str(cve_id).strip().upper() in catalog


def kev_entry(cve_id: str, catalog: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return the KEV entry for ``cve_id`` or None."""
    if not cve_id or not catalog:
        return None
    return catalog.get(str(cve_id).strip().upper())


def annotate_cve_results(version_results: List[Any],
                         catalog: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Flag KEV-listed CVEs in-place on ``VersionCVEResult`` objects.

    Sets ``kev=True`` plus ``kev_due_date``/``kev_name`` on matching
    ``CVEResult`` items (attributes are created dynamically so older
    pickles/constructors keep working).  Returns a summary dict for the
    report: ``kev_count``, ``kev_ids`` and ``catalog_size``.
    """
    summary: Dict[str, Any] = {'kev_count': 0, 'kev_ids': [], 'catalog_size': len(catalog or {})}
    if not version_results or not catalog:
        return summary
    hits: List[str] = []
    for entry in version_results:
        for cve in (getattr(entry, 'cves', None) or []):
            cve_id = getattr(cve, 'cve_id', '')
            kev = kev_entry(str(cve_id or ''), catalog)
            if kev:
                try:
                    setattr(cve, 'kev', True)
                    setattr(cve, 'kev_due_date', kev.get('due_date', ''))
                    setattr(cve, 'kev_name', kev.get('name', ''))
                except Exception:
                    pass
                hits.append(str(cve_id).strip().upper())
            else:
                try:
                    if not hasattr(cve, 'kev'):
                        setattr(cve, 'kev', False)
                except Exception:
                    pass
    summary['kev_count'] = len(hits)
    summary['kev_ids'] = sorted(set(hits))
    return summary


def cve_dict_kev_fields(cve: Any) -> Dict[str, Any]:
    """Extract KEV annotation fields for report serialization."""
    return {
        'kev': bool(getattr(cve, 'kev', False)),
        'kev_due_date': getattr(cve, 'kev_due_date', '') or '',
        'kev_name': getattr(cve, 'kev_name', '') or '',
    }
