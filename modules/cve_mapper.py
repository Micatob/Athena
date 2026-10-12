import asyncio
import json
import logging
import re
import sqlite3
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field


@dataclass
class CVEResult:
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    exploit_available: bool = False
    exploit_source: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class VersionCVEResult:
    technology: str
    version: str
    confidence: int
    cves: List[CVEResult] = field(default_factory=list)
    max_cvss: Optional[float] = None


CURATED_DB: Dict[str, Dict[str, List[Tuple[str, str, float, bool]]]] = {
    'apache': {
        '2.4.49': [('CVE-2021-41773', 'Path Traversal & RCE in Apache 2.4.49', 7.5, True)],
        '2.4.50': [('CVE-2021-42013', 'RCE bypass for CVE-2021-41773', 9.8, True)],
        '2.4.48': [('CVE-2021-44790', 'mod_lua RCE in Apache <= 2.4.48', 9.8, True)],
        '2.4.46': [('CVE-2021-40438', 'SSRF in mod_proxy (affects 2.4.30-2.4.46)', 7.5, False)],
        '2.4.43': [('CVE-2021-33193', 'HTTP/2 request splitting', 7.5, False)],
        '2.4.39': [('CVE-2019-10081', 'HTTP/2 push request memory corruption', 5.0, False)],
        '2.4.38': [('CVE-2019-0211', 'Privilege escalation via shared memory', 9.8, True)],
        '2.4.37': [('CVE-2019-0215', 'mod_ssl access control bypass', 9.1, False)],
        '2.4.35': [('CVE-2018-11763', 'mod_http2 denial of service', 7.5, False)],
        '2.4.34': [('CVE-2018-8011', 'mod_md denial of service', 5.0, False)],
        '2.4.33': [('CVE-2018-1303', 'mod_cache_sm problem', 5.0, False)],
        '2.2.32': [('CVE-2017-15710', 'mod_auth_digest out-of-bounds write', 7.5, False)],
    },
    'nginx': {
        '1.22.0': [('CVE-2022-41741', 'Memory disclosure in ngx_http_mp4_module', 7.5, False)],
        '1.21.0': [('CVE-2021-3618', 'ALPACA TLS triple handshake attack', 5.9, False)],
        '1.20.0': [('CVE-2021-23017', 'DNS Spoofing via resolver', 7.5, False)],
        '1.18.0': [('CVE-2020-11724', 'HTTP/2 HPACK table DoS', 7.5, False)],
        '1.16.1': [('CVE-2019-20372', 'Directory traversal in error_page', 7.5, False)],
        '1.14.0': [('CVE-2018-16845', 'Memory disclosure in MP4 module', 7.5, False)],
        '1.13.0': [('CVE-2017-7529', 'Integer overflow in range filter', 7.5, True)],
        '1.4.0': [('CVE-2013-2028', 'Stack buffer overflow in chunked encoding', 7.5, True)],
    },
    'php': {
        '8.1.0': [('CVE-2021-21703', 'Local privilege escalation in PHP-FPM', 7.8, True)],
        '8.0.0': [('CVE-2021-21703', 'Local privilege escalation in PHP-FPM', 7.8, True)],
        '7.4.30': [('CVE-2022-31631', 'SQL injection via PDO', 9.8, True)],
        '7.4.28': [('CVE-2022-2405', 'XSS in FPM status page', 6.1, True)],
        '7.4.0': [('CVE-2019-11048', 'HTTP header injection via LDAP', 7.5, False)],
        '7.3.0': [('CVE-2018-17082', 'URL heap corruption in EXIF parser', 7.5, False)],
        '7.1.0': [('CVE-2017-16642', 'Invalid pointer in FILTER_VALIDATE_EMAIL', 5.0, False)],
        '5.6.30': [('CVE-2016-10397', 'Memory corruption in WDDX decoder', 7.5, True)],
        '5.6.0': [('CVE-2018-19518', 'IMAP extension RCE', 9.8, True)],
        '5.4.0': [('CVE-2013-1643', 'SOAP client XXE injection', 7.5, True)],
    },
    'wordpress': {
        '6.4.0': [('CVE-2023-6896', 'XSS via shortcode in post content', 6.1, True)],
        '6.3.0': [('CVE-2023-39999', 'Open redirect via wp_validate_redirect', 6.1, False)],
        '6.2.0': [('CVE-2023-2854', 'Stored XSS via block attributes', 6.1, True)],
        '6.1.0': [('CVE-2022-3590', 'Stored XSS via Custom CSS', 6.1, True)],
        '5.9.0': [('CVE-2022-21661', 'SQL injection via WP_Term_Query', 9.8, True)],
        '5.8.0': [('CVE-2021-39200', 'Information disclosure via REST API', 4.3, False)],
        '5.7.0': [('CVE-2021-29504', 'Stored XSS via post meta', 6.1, True)],
        '5.0.0': [('CVE-2018-20148', 'PHP object injection via PHAR deserialization', 9.8, True)],
        '4.7.0': [('CVE-2016-10033', 'RCE via PHPMailer', 9.8, True)],
    },
    'drupal': {
        '9.2.0': [('CVE-2021-32780', 'SSRF in Drupal 9.2', 7.5, True)],
        '9.0.0': [('CVE-2020-13671', 'XSS via RSS feed aggregation', 6.1, True)],
        '8.6.0': [('CVE-2019-6339', 'RCE via Phar deserialization', 9.8, True)],
        '7.58': [('CVE-2018-7600', 'Drupalgeddon RCE (SA-CORE-2018-002)', 9.8, True)],
        '7.0.0': [('CVE-2018-7602', 'Drupalgeddon2 RCE', 9.8, True)],
    },
    'joomla': {
        '4.2.0': [('CVE-2023-23752', 'Unauthenticated REST API info disclosure', 7.5, True)],
        '3.7.0': [('CVE-2017-8917', 'SQL injection in Joomla 3.7.0', 9.8, True)],
        '3.4.0': [('CVE-2015-8562', 'RCE via sessions', 9.8, True)],
    },
    'laravel': {
        '10.0.0': [('CVE-2023-24209', 'Mass assignment in Eloquent', 7.5, False)],
        '9.0.0': [('CVE-2022-31279', 'SQL injection via DB::raw()', 9.8, True)],
        '8.0.0': [('CVE-2021-3129', 'Ignition RCE (debug mode)', 9.8, True)],
        '7.0.0': [('CVE-2020-19347', 'PDO truncation SQL injection', 7.5, True)],
        '6.0.0': [('CVE-2020-11022', 'XSS in Blade templating', 6.1, True)],
    },
    'tomcat': {
        '9.0.0': [('CVE-2018-8037', 'Open redirection via /..;param', 5.0, False)],
        '8.5.0': [('CVE-2020-1938', 'Ghostcat: AJP file read/RCE', 9.8, True)],
        '7.0.0': [('CVE-2017-12617', 'RCE via PUT method', 9.8, True)],
    },
    'iis': {
        '7.5': [('CVE-2015-1635', 'MS15-034: HTTP.sys RCE via Range header', 9.8, True)],
        '6.0': [('CVE-2010-2730', 'Buffer overflow in FastCGI', 7.5, True)],
    },
    'openssh': {
        '9.3': [('CVE-2023-38408', 'RCE via forwarding of PKCS#11 tokens', 9.8, True)],
        '8.9': [('CVE-2023-28531', 'Privilege escalation via ssh-agent', 7.8, True)],
        '8.0': [('CVE-2019-6111', 'Information disclosure via SCP', 5.3, False)],
        '7.7': [('CVE-2018-20685', 'Username enumeration via scp', 5.3, False)],
        '7.2': [('CVE-2016-6210', 'Username enumeration via SSHD', 5.3, False)],
        '7.0': [('CVE-2015-6564', 'Privilege escalation via sshd PAM', 7.8, True)],
    },
    'mysql': {
        '8.0.25': [('CVE-2022-21292', 'DoS via subquery optimization', 5.0, False)],
        '8.0.0': [('CVE-2018-2767', 'DoS via optimizer', 5.0, False)],
        '5.7.0': [('CVE-2017-3313', 'RCE via yaSSL', 9.8, True)],
        '5.6.0': [('CVE-2016-6662', 'RCE via crafted my.cnf', 9.8, True)],
    },
    'postgresql': {
        '15.0': [('CVE-2023-2454', 'Mitigation bypass in pgcrypto', 5.0, False)],
        '14.0': [('CVE-2022-21724', 'DoS via btree', 5.0, False)],
        '13.0': [('CVE-2020-25694', 'Account misidentification via SSCM', 5.3, False)],
        '12.0': [('CVE-2020-1720', 'ALTER .. DEPENDS ON EXTENSION misuse', 7.5, False)],
        '11.0': [('CVE-2018-16850', 'SQL injection via CREATE TRIGGER', 9.8, True)],
    },
    'openssl': {
        '1.1.1': [('CVE-2023-3446', 'DoS via DH key generation', 5.0, False)],
        '1.0.2': [('CVE-2016-2107', 'Padding oracle in AES-CBC (Lucky13)', 5.9, True)],
        '1.0.1': [('CVE-2014-0160', 'Heartbleed: memory disclosure via heartbeat', 7.5, True)],
    },
    'python': {
        '3.11.0': [('CVE-2023-24329', 'URL parser bypass for blocklist', 5.3, False)],
        '3.10.0': [('CVE-2021-3737', 'Infinite loop in HTTP client', 7.5, False)],
        '3.9.0': [('CVE-2021-29921', 'IPv4 address spoofing via ipaddress module', 5.3, False)],
        '3.8.0': [('CVE-2019-9740', 'CRLF injection via urllib', 7.5, True)],
        '3.7.0': [('CVE-2018-1000802', 'Directory traversal in urllib', 7.5, True)],
        '2.7.0': [('CVE-2019-9948', 'File disclosure via urllib CRLF injection', 7.5, True)],
    },
    'node.js': {
        '18.0.0': [('CVE-2022-35256', 'DoS via HTTP request smuggling', 7.5, False)],
        '16.0.0': [('CVE-2021-22931', 'Improper proxy handling', 5.3, False)],
        '14.0.0': [('CVE-2020-8252', 'RCE via buffer overflow in realpath', 7.5, True)],
        '12.0.0': [('CVE-2019-15604', 'DoS via HTTP/2 memory exhaustion', 7.5, False)],
    },
    'redis': {
        '6.2.0': [('CVE-2022-35951', 'Lua sandbox escape', 9.8, True)],
        '6.0.0': [('CVE-2020-14147', 'Integer overflow in Lua scripts', 5.0, False)],
        '5.0.0': [('CVE-2019-10193', 'LUA sandbox bypass via Redis', 9.8, True)],
        '3.2.0': [('CVE-2016-8339', 'Buffer overflow in cluster process', 7.5, True)],
    },
    'mongodb': {
        '6.0.0': [('CVE-2022-45169', 'Stored XSS via MongoDB shell', 5.0, False)],
        '5.0.0': [('CVE-2021-32039', 'DoS via crafted queries', 5.0, False)],
        '4.4.0': [('CVE-2020-7921', 'DoS via crafted LDAP query', 5.0, False)],
        '3.6.0': [('CVE-2017-17427', 'Memory disclosure via crafted request', 5.0, True)],
    },
    'docker': {
        '20.10.0': [('CVE-2021-41091', 'Moby information disclosure', 7.5, True)],
        '19.03.0': [('CVE-2020-13401', 'IPv6 address spoofing via networks', 5.3, False)],
        '18.09.0': [('CVE-2019-13139', 'Command injection via docker build', 9.8, True)],
        '17.12.0': [('CVE-2018-15664', 'Symlink swap attack during container build', 7.5, True)],
    },
    'kubernetes': {
        '1.27.0': [('CVE-2023-2431', 'Privilege escalation via subpath', 8.8, True)],
        '1.24.0': [('CVE-2022-3172', 'Privilege escalation via Aggregated API', 8.8, True)],
        '1.22.0': [('CVE-2021-25741', 'Symlink traversal via subpath', 8.8, True)],
        '1.20.0': [('CVE-2020-8554', 'MITM via ExternalName services', 7.5, True)],
    },
    'gitlab': {
        '15.0.0': [('CVE-2022-1946', 'XSS via RDoc documentation', 6.1, True)],
        '14.0.0': [('CVE-2021-22205', 'Unauthenticated RCE via ExifTool', 9.9, True)],
        '13.0.0': [('CVE-2020-13258', 'SSRF via CI job token', 6.5, False)],
    },
    'jenkins': {
        '2.300': [('CVE-2022-45387', 'RCE via crafted config file', 9.9, True)],
        '2.200': [('CVE-2021-21690', 'RCE via Agent-to-Controller', 9.0, True)],
        '2.100': [('CVE-2020-2099', 'XSS via build log output', 6.1, True)],
        '2.0': [('CVE-2018-1000861', 'RCE via crafted URL', 9.8, True)],
    },
    'grafana': {
        '9.0.0': [('CVE-2022-21707', 'XSS via alerting settings', 6.1, True)],
        '8.0.0': [('CVE-2021-28146', 'SSRF via data source proxy', 7.5, False)],
        '7.0.0': [('CVE-2020-13379', 'SSRF via avatar URL processing', 7.5, True)],
    },
}

SEVERITY_THRESHOLDS = {
    'CRITICAL': 9.0,
    'HIGH': 7.0,
    'MEDIUM': 4.0,
    'LOW': 0.0,
}

#: NVD CPE ``virtualMatchString`` mapping (vendor, product).  A CPE match is
#: authoritative for "this version is affected"; keyword search only proves
#: the version is *mentioned* (often in "fixed in" text), so CPE wins.
CPE_MAP: Dict[str, Tuple[str, str]] = {
    'php': ('php', 'php'),
    'exim': ('exim', 'exim'),
    'dovecot': ('dovecot', 'dovecot'),
    'apache': ('apache', 'http_server'),
    'nginx': ('nginx', 'nginx'),
    'openssh': ('openbsd', 'openssh'),
    'mysql': ('mysql', 'mysql'),
    'postgresql': ('postgresql', 'postgresql'),
    'openssl': ('openssl', 'openssl'),
    'tomcat': ('apache', 'tomcat'),
    'iis': ('microsoft', 'iis'),
    'redis': ('redislabs', 'redis'),
    'wordpress': ('wordpress', 'wordpress'),
    'drupal': ('drupal', 'drupal'),
    'joomla': ('joomla', 'joomla'),
    'python': ('python', 'python'),
    'node.js': ('nodejs', 'node'),
    'nodejs': ('nodejs', 'node'),
    'gitlab': ('gitlab', 'gitlab'),
    'jenkins': ('jenkins', 'jenkins'),
    'grafana': ('grafana', 'grafana'),
    'mongodb': ('mongodb', 'mongodb'),
    'docker': ('docker', 'docker'),
    'kubernetes': ('kubernetes', 'kubernetes'),
}

_NAME_VERSION_RE = re.compile(r'^(.*?)[\s/:]+(v?\d+(?:\.\d+)*(?:[a-z]\d+)?)$',
                              re.IGNORECASE)


def split_name_version(name: str, version: str = '') -> Tuple[str, str]:
    """Return ``(product, version)`` from a technology entry.

    Tech lists often carry the version inline ('PHP 8.0.30') with no
    separate ``version`` key — that mismatch silently disabled every lookup
    before (0 CVEs reported even though NVD works).  Handles both shapes.
    """
    version = (version or '').strip().lstrip('vV')
    if version:
        return name.strip(), version
    name = (name or '').strip()
    m = _NAME_VERSION_RE.match(name)
    if m:
        base = re.sub(r'\(.*?\)$', '', m.group(1)).strip()   # drop '(suspected)'
        ver = m.group(2).lstrip('vV')
        if base and ver and not base.lower().startswith('v'):
            return base, ver
    return name, ''


class CVEMapper:
    def __init__(self, db_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self._cache: Dict[str, List[CVEResult]] = {}
        self._cache_ttl: Dict[str, float] = {}
        self._cache_duration = 3600
        self.db_path = db_path
        #: NVD rate-limit gate: unauthenticated = 5 req/30s (6.2s spacing);
        #: with NVD_API_KEY env set = 50 req/30s (0.6s spacing).
        self._nvd_last = 0.0

    def _get_cvss_severity(self, score: float) -> str:
        for severity, threshold in sorted(SEVERITY_THRESHOLDS.items(), key=lambda x: -x[1]):
            if score >= threshold:
                return severity
        return 'LOW'

    def _lookup_curated(self, name_lower: str, version: str) -> List[CVEResult]:
        results = []
        tech_db = CURATED_DB.get(name_lower, {})
        direct = tech_db.get(version)
        if direct:
            for cve_id, desc, score, has_exploit in direct:
                results.append(CVEResult(
                    cve_id=cve_id, description=desc, cvss_score=score,
                    exploit_available=has_exploit,
                    remediation=f'Update {name_lower} to latest version'
                ))
        parts = version.split('.')
        if len(parts) >= 2:
            major_minor = '.'.join(parts[:2])
            if major_minor != version:
                mm_result = tech_db.get(major_minor)
                if mm_result:
                    for cve_id, desc, score, has_exploit in mm_result:
                        results.append(CVEResult(
                            cve_id=cve_id, description=desc, cvss_score=score,
                            exploit_available=has_exploit,
                            remediation=f'Update {name_lower} to latest version'
                        ))
        return results

    async def _nvd_get(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """One rate-limited, retried NVD API 2.0 request.  Never raises."""
        import urllib.request, urllib.parse
        api_key = os.environ.get('NVD_API_KEY', '').strip()
        if api_key:
            params = {**params, 'apiKey': api_key}
        url = ('https://services.nvd.nist.gov/rest/json/cves/2.0?'
               + urllib.parse.urlencode(params))
        gap = 0.6 if api_key else 6.2
        wait = self._nvd_last + gap - time.time()
        if wait > 0:
            await asyncio.sleep(wait)
        for attempt in (1, 2):
            try:
                req = urllib.request.Request(
                    url, headers={'User-Agent': 'Athena-Security-Suite/3.0'})
                loop = asyncio.get_event_loop()
                resp = await loop.run_in_executor(
                    None, lambda: urllib.request.urlopen(req, timeout=20))
                self._nvd_last = time.time()
                if resp.getcode() == 200:
                    return json.loads(resp.read().decode('utf-8'))
                return None
            except Exception as e:
                self._nvd_last = time.time()
                self.logger.debug('NVD request failed (attempt %d): %s', attempt, e)
                if attempt == 1:
                    await asyncio.sleep(3.0)   # transient 503/timeout: one retry
        return None

    @staticmethod
    def _parse_nvd_items(data: Optional[Dict[str, Any]]) -> List[CVEResult]:
        results: List[CVEResult] = []
        for item in (data or {}).get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id', '')
            if not cve_id:
                continue
            descriptions = cve.get('descriptions', [])
            desc = next((d.get('value', '') for d in descriptions
                         if d.get('lang') == 'en'), '')
            score = None
            metrics = cve.get('metrics', {})
            for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                entries = metrics.get(key)
                if entries:
                    score = (entries[0].get('cvssData', {}) or {}).get('baseScore')
                    if score is not None:
                        break
            results.append(CVEResult(cve_id=cve_id, description=desc[:300],
                                     cvss_score=score))
        return results

    @staticmethod
    def _already_fixed(description: str, version: str) -> bool:
        """True when a CVE description says it was fixed *at* the version the
        target runs — 'Exim before 4.100.1' does not affect Exim 4.100.1, so
        matching it would be a false CVE claim in the report."""
        d = (description or '').lower()
        v = (version or '').lower()
        if not d or not v:
            return False
        return any(p in d for p in (f'before {v}', f'fixed in {v}',
                                    f'prior to {v}', f'earlier than {v}'))

    async def _lookup_live(self, name_lower: str, name: str,
                           version: str) -> List[CVEResult]:
        """Live NVD lookup.  CPE ``virtualMatchString`` first (authoritative
        'affects this version'), then keyword search as fallback.

        CPE versions escalate: exact ('4.100.1') -> drop patch ('4.100') when
        the exact CPE does not exist; matches found via a shortened variant
        are then filtered for 'fixed in <full version>' text so an already-
        patched target never gets a false CVE row.  Keyword only runs when
        CPE found nothing (or product has no CPE), which keeps us inside the
        5-req/30s anonymous rate limit.
        """
        if not version:
            return []
        cache_key = f'live:{name_lower}:{version}'
        now = time.time()
        if cache_key in self._cache and now - self._cache_ttl.get(cache_key, 0) < self._cache_duration:
            return self._cache[cache_key]
        cves: List[CVEResult] = []
        product = CPE_MAP.get(name_lower)
        if product:
            vendor, prod = product
            variants = [version]
            parts = version.split('.')
            if len(parts) > 2:
                variants.append('.'.join(parts[:2]))   # 4.100.1 -> 4.100
            for ver_variant in variants:
                data = await self._nvd_get({
                    'virtualMatchString':
                        f'cpe:2.3:a:{vendor}:{prod}:{ver_variant}:*:*:*:*:*:*:*',
                        'resultsPerPage': 20})
                found = self._parse_nvd_items(data)
                if found:
                    seen = set()
                    for c in found:
                        if c.cve_id in seen:
                            continue
                        seen.add(c.cve_id)
                        if self._already_fixed(c.description, version):
                            continue      # patched at target's version
                        cves.append(c)
                    break
        if not cves:
            data = await self._nvd_get({'keywordSearch': f'{name} {version}',
                                        'resultsPerPage': 10})
            cves = [c for c in self._parse_nvd_items(data)
                    if not self._already_fixed(c.description, version)]
        if cves:
            self._cache[cache_key] = cves
            self._cache_ttl[cache_key] = now
        return cves

    async def query_nvd_api(self, keyword: str) -> Optional[List[CVEResult]]:
        """Keyword search against live NVD (kept for callers/back-compat)."""
        now = time.time()
        cache_key = f"nvd:{keyword}"
        if cache_key in self._cache and now - self._cache_ttl.get(cache_key, 0) < self._cache_duration:
            return self._cache[cache_key]
        data = await self._nvd_get({'keywordSearch': keyword,
                                    'resultsPerPage': 10})
        results = self._parse_nvd_items(data)
        if results:
            self._cache[cache_key] = results
            self._cache_ttl[cache_key] = now
            return results
        return None

    async def check_exploit_db(self, cve_id: str) -> Tuple[bool, Optional[str]]:
        try:
            import urllib.request
            url = f"https://www.exploit-db.com/search?cve={cve_id}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = await asyncio.get_event_loop().run_in_executor(None, lambda: urllib.request.urlopen(req, timeout=5))
            if resp.getcode() == 200:
                body = resp.read().decode('utf-8', errors='ignore')
                if 'exploit' in body.lower() and 'no results' not in body.lower():
                    return True, url
        except Exception:
            search_url = f"https://www.exploit-db.com/search?cve={cve_id}"
            return False, search_url
        return False, None

    async def map_versions(self, technologies: List[Dict[str, Any]]) -> List[VersionCVEResult]:
        results = []
        seen = set()
        for tech in technologies:
            raw_name = tech.get('technology', '')
            name, version = split_name_version(raw_name, tech.get('version', ''))
            confidence = tech.get('confidence', 3)
            if not version:
                continue          # nothing versioned to map; name alone is noise
            dedupe_key = f'{name.lower()}:{version}'
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            name_lower = name.strip().lower()
            cves = self._lookup_curated(name_lower, version)
            try:
                live = await self._lookup_live(name_lower, name.strip(), version)
            except Exception as e:       # offline? rate-limited? scan continues
                self.logger.debug('live NVD lookup failed for %s %s: %s',
                                  name, version, e)
                live = []
            existing_ids = {c.cve_id for c in cves}
            for cve in live:
                if cve.cve_id not in existing_ids:
                    cves.append(cve)
            max_cvss = max((c.cvss_score for c in cves if c.cvss_score), default=None)
            results.append(VersionCVEResult(
                technology=name, version=version, confidence=confidence,
                cves=cves, max_cvss=max_cvss
            ))
        return results

    def get_remediation(self, cve: CVEResult, tech: str) -> str:
        if cve.remediation:
            return cve.remediation
        return f"Update {tech} to a patched version. See {cve.cve_id} for details."
