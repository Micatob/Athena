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
    # --- SPA / Frontend frameworks ---
    'jquery': {
        '3.4.0': [('CVE-2020-11022', 'XSS in jQuery.html() with HTML strings', 6.1, True),
                   ('CVE-2020-11023', 'XSS in jQuery.html() with <option> elements', 6.1, True)],
        '3.3.0': [('CVE-2019-11358', 'Prototype pollution in jQuery.extend()', 6.1, True)],
        '2.1.0': [('CVE-2015-9251', 'XSS via cross-domain AJAX requests', 6.1, True)],
        '1.12.0': [('CVE-2015-9251', 'XSS via cross-domain AJAX requests', 6.1, True)],
    },
    'bootstrap': {
        '4.3.0': [('CVE-2019-8331', 'XSS in tooltip and popover data-template attribute', 6.1, True)],
        '3.3.0': [('CVE-2019-8331', 'XSS in tooltip and popover data-template attribute', 6.1, True)],
        '3.4.0': [('CVE-2019-8331', 'XSS in tooltip and popover data-template attribute', 6.1, True)],
    },
    'react': {
        '16.0.0': [('CVE-2020-8203', 'SSRF via resource hints with user-controlled URLs', 6.1, False),
                    ('CVE-2020-15366', 'Prototype pollution via __proto__ in jsx-runtime', 5.6, True)],
        '17.0.0': [('CVE-2020-15366', 'Prototype pollution in JSX runtime (affects < 17.0.2)', 5.6, True)],
    },
    'angular': {
        '13.0.0': [('CVE-2022-25869', 'XSS via unsafe style bindings', 5.4, False)],
        '12.0.0': [('CVE-2022-25869', 'XSS via unsafe style bindings (affects < 12.2.14)', 5.4, False)],
        '11.0.0': [('CVE-2021-42342', 'Server-side template injection via expressions', 9.8, True)],
        '9.0.0': [('CVE-2020-7676', 'XSS in template compilation with attacker-controlled input', 6.1, True)],
    },
    'vue.js': {
        '2.6.0': [('CVE-2024-22365', 'XSS via v-html directive with untrusted content', 6.1, False)],
        '2.5.0': [('CVE-2021-23343', 'ReDoS in template compiler with malicious template', 5.3, False)],
        '3.0.0': [('CVE-2024-22365', 'Sandbox escape via crafted template (affects Vue 2/3)', 6.1, False)],
    },
    'firebase sdk': {
        '9.0.0': [('CVE-2022-27198', 'Firebase Auth - account enumeration via reset password', 5.3, False),
                   ('CVE-2021-37646', 'Firebase Hosting - access to non-public files via misconfigured rules', 7.5, False)],
        '8.0.0': [('CVE-2021-37646', 'Firebase Hosting - access to non-public files via misconfigured rules', 7.5, False)],
    },
    'firebase hosting': {
        '1.0.0': [('CVE-2021-37646', 'Access to non-public files via misconfigured security rules', 7.5, False)],
    },
}

SEVERITY_THRESHOLDS = {
    'CRITICAL': 9.0,
    'HIGH': 7.0,
    'MEDIUM': 4.0,
    'LOW': 0.0,
}


class CVEMapper:
    def __init__(self, db_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self._cache: Dict[str, List[CVEResult]] = {}
        self._cache_ttl: Dict[str, float] = {}
        self._cache_duration = 3600
        self.db_path = db_path

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

    async def query_nvd_api(self, keyword: str) -> Optional[List[CVEResult]]:
        now = time.time()
        cache_key = f"nvd:{keyword}"
        if cache_key in self._cache and now - self._cache_ttl.get(cache_key, 0) < self._cache_duration:
            return self._cache[cache_key]
        try:
            import urllib.request, urllib.error
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=10"
            req = urllib.request.Request(url, headers={'User-Agent': 'Athena-Security-Suite/3.0'})
            resp = await asyncio.get_event_loop().run_in_executor(None, lambda: urllib.request.urlopen(req, timeout=10))
            if resp.getcode() == 200:
                data = json.loads(resp.read().decode('utf-8'))
                results = []
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', '')
                    descriptions = cve.get('descriptions', [])
                    desc = next((d.get('value', '')[:200] for d in descriptions if d.get('lang') == 'en'), '')
                    metrics = cve.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}) if metrics.get('cvssMetricV31') else {}
                    score = cvss_v3.get('baseScore')
                    results.append(CVEResult(cve_id=cve_id, description=desc, cvss_score=score))
                if results:
                    self._cache[cache_key] = results
                    self._cache_ttl[cache_key] = now
                    return results
        except Exception as e:
            self.logger.debug(f"NVD API query failed for '{keyword}': {e}")
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
        for tech in technologies:
            name = tech.get('technology', '')
            version = tech.get('version', '')
            confidence = tech.get('confidence', 3)
            if not version:
                continue
            name_lower = name.strip().lower()
            cves = self._lookup_curated(name_lower, version)
            nvd_results = await self.query_nvd_api(f"{name} {version}")
            if nvd_results:
                existing_ids = {c.cve_id for c in cves}
                for cve in nvd_results:
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
