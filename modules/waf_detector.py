"""Native WAF detection — runs FIRST, needs no binary.

wafw00f is still used when installed (richer fingerprint), but Athena must
not depend on it: this module fingerprints the WAF from plain HTTP
responses so the rest of the pipeline (rate, payloads, stealth) can be
tuned before a single injection is sent.

Detection signals (all deterministic, no guessing):
  1. Well-known WAF headers / cookies / server banners.
  2. Response to a deliberately malicious probe (SQLi-ish path). A WAF
     answers 403/406/501/419/429 with a vendor page; an unprotected app
     answers 200/404 with its own content.
  3. Behavioural: normal page = 200, attack page = block -> WAF confirmed.
     Both blocked -> hard block / ModSecurity default-deny.
     Neither blocked -> no WAF (or transparent).
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

WAF_SIGNATURES = [
    (r'cloudflare', 'Cloudflare', ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-mitigated', 'server: cloudflare']),
    (r'mod_?security|modsec|owasp', 'ModSecurity', ['mod_security', 'modsecurity']),
    (r'sucuri', 'Sucuri', ['x-sucuri-id', 'x-sucuri-cache']),
    (r'incapsula|imperva', 'Imperva Incapsula', ['x-iinfo', 'incap_ses']),
    (r'akamai', 'Akamai', ['akamai', 'x-akamai']),
    (r'aws.?waf|awselb|awselastic', 'AWS WAF/ELB', ['x-amzn-requestid', 'x-amz-cf-id']),
    (r'barracuda', 'Barracuda', ['barra_counter_session']),
    (r'f5-big-?ip|big-?ip\b|x-waf-event', 'F5 BIG-IP ASM', ['x-waf-event', 'bigip']),
    (r'fortiweb|fortinet', 'FortiWeb', ['fortiwafsid']),
    (r'wordfence|wfvt_', 'Wordfence', ['wordfence']),
    (r'siteground|sg-optimizer', 'SiteGround', []),
    (r'stackpath', 'StackPath', ['x-sp-ip']),
    (r'blazingfast', 'BlazingFast', []),
    (r'cachewall', 'CacheWall', []),
    (r'denyall|360.?waf|wangsu', '360/Wangsu', ['x-360']),
    (r'edgecast|verizon', 'Edgecast/Verizon', []),
    (r'expression.?engine|expressionengine', 'ExpressionEngine', []),
    (r'cpanel|whm', 'cPanel/ModSecurity', ['cpanel']),
]

BLOCK_STATUSES = {400, 401, 403, 406, 407, 409, 419, 421, 429, 501, 503}
BLOCK_MARKERS = [
    'mod_security', 'modsecurity', 'not acceptable', 'forbidden',
    'request blocked', 'access denied', 'waf', 'blocked by',
    'cloudflare', 'sucuri', 'incapsula', 'imperva', 'akamai',
    'attention required', 'security check', 'ray id', 'error 1015',
    'error 1020', 'web application firewall',
]

ATTACK_PROBES = [
    "/?id=' OR '1'='1",
    "/?id=<script>alert(1)</script>",
]


async def _fetch(session: aiohttp.ClientSession, url: str,
                 headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    try:
        async with session.get(url, ssl=False, headers=headers or {},
                               timeout=aiohttp.ClientTimeout(total=10),
                               allow_redirects=False) as resp:
            body = await resp.text()
            return {
                'status': resp.status,
                'headers': dict(resp.headers),
                'body': body[:8000],
                'elapsed': 0.0,
            }
    except Exception as exc:
        return {'status': None, 'headers': {}, 'body': '', 'error': str(exc)[:200]}


def _match_signatures(headers: Dict[str, str], body: str,
                      server: str = '') -> List[Dict[str, str]]:
    blob = ' '.join([
        *[f'{k}: {v}' for k, v in (headers or {}).items()],
        body[:4000],
        server,
    ]).lower()
    hits: List[Dict[str, str]] = []
    for pattern, name, keys in WAF_SIGNATURES:
        matched_on = ''
        try:
            if re.search(pattern, blob):
                matched_on = 'banner/body/header pattern'
        except re.error:
            continue
        else:
            for k in keys:
                kl = k.lower().rstrip(': ')
                for hk, hv in (headers or {}).items():
                    if kl in hk.lower() or kl in str(hv).lower():
                        matched_on = f'header {hk}'
                        break
                if matched_on:
                    break
                if kl in blob:
                    matched_on = 'response marker'
                    break
        if matched_on:
            hits.append({'waf': name, 'matched_on': matched_on})
    return hits


def _is_block_page(status: Optional[int], body: str) -> bool:
    if status in BLOCK_STATUSES:
        low = (body or '').lower()
        if any(m in low for m in BLOCK_MARKERS):
            return True
        # 403/406 with empty/generic body on an attack probe is still a
        # block signal (ModSecurity default-deny has no vendor string).
        if status in (403, 406) and len(body or '') < 5000:
            return True
    return False


async def detect_waf(target: str,
                     session: Optional[aiohttp.ClientSession] = None) -> Dict[str, Any]:
    """Fingerprint the WAF in front of *target*. Never raises."""
    started = time.monotonic()
    if not target.startswith(('http://', 'https://')):
        target = f'https://{target}'
    target = target.rstrip('/')
    parsed = urlparse(target)
    base = f'{parsed.scheme}://{parsed.netloc}'

    close_here = False
    if session is None:
        conn = aiohttp.TCPConnector(ssl=False)
        session = aiohttp.ClientSession(
            connector=conn,
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36'},
        )
        close_here = True
    try:
        return await _detect_inner(target, session, started)
    except Exception as exc:
        return {
            'target': target, 'verdict': 'unknown', 'waf': '',
            'signatures': [], 'confidence': 'low',
            'baseline_status': None, 'probes_blocked': 0, 'probes_total': 0,
            'tuning': f'WAF gate error ({exc}); continuing with normal rate.',
            'rate_hint': 'normal', 'payload_hint': 'standard payloads',
            'duration_s': round(time.monotonic() - started, 1),
            'error': str(exc)[:200],
        }
    finally:
        if close_here:
            try:
                await session.close()
            except Exception:
                pass


async def _detect_inner(target: str, session: aiohttp.ClientSession,
                        started: float) -> Dict[str, Any]:
    parsed = urlparse(target)
    base = f'{parsed.scheme}://{parsed.netloc}'
    try:
        baseline = await _fetch(session, base + '/')
        probe_results = []
        for probe in ATTACK_PROBES:
            probe_results.append(await _fetch(session, base + probe))

        sig_hits = _match_signatures(
            baseline.get('headers') or {},
            baseline.get('body') or '',
            (baseline.get('headers') or {}).get('Server', ''),
        )
        for pr in probe_results:
            _h = pr.get('headers') or {}
            sig_hits.extend(_match_signatures(_h, pr.get('body') or '',
                                              _h.get('Server', '')))

        # Dedupe by WAF name
        seen = set()
        uniq_hits = []
        for h in sig_hits:
            if h['waf'] not in seen:
                seen.add(h['waf'])
                uniq_hits.append(h)

        blocked = sum(1 for pr in probe_results if _is_block_page(pr.get('status'), pr.get('body', '')))
        baseline_blocked = _is_block_page(baseline.get('status'), baseline.get('body', ''))
        baseline_ok = baseline.get('status') == 200

        if uniq_hits and blocked:
            verdict = 'confirmed'
            confidence = 'high'
        elif uniq_hits:
            verdict = 'likely'
            confidence = 'medium'
        elif blocked >= 1 and baseline_ok:
            verdict = 'likely'
            confidence = 'medium'
            uniq_hits.append({'waf': 'Unknown WAF/ModSecurity (behavioural block)', 'matched_on': f'{blocked}/{len(probe_results)} attack probes blocked, baseline 200'})
        elif baseline_blocked:
            verdict = 'hard-block'
            confidence = 'medium'
            uniq_hits.append({'waf': 'Hard block / default-deny (baseline also blocked)', 'matched_on': f"baseline HTTP {baseline.get('status')}"})
        else:
            verdict = 'none'
            confidence = 'high'

        waf_name = uniq_hits[0]['waf'] if uniq_hits else ''
        if verdict in ('confirmed', 'likely'):
            tuning = ('WAF in front — Athena switches to low-rate + WAF-bypass '
                      'payloads; expect 403/406 on naive probes, use encoded variants.')
            rate_hint = 'low (<=50 rps, stealth delays on)'
            payload_hint = 'use WAF-bypass/encoded payloads first'
        elif verdict == 'hard-block':
            tuning = ('Target hard-blocks even the baseline — crawler forms will be '
                      'empty; rely on admin-panel probes, directory enum and manual review.')
            rate_hint = 'minimal (single-threaded probes)'
            payload_hint = 'manual review; automated injection unreliable'
        else:
            tuning = 'No WAF detected — normal scan rate applies.'
            rate_hint = 'normal'
            payload_hint = 'standard payloads'

        return {
            'target': base,
            'verdict': verdict,            # confirmed | likely | none | hard-block
            'waf': waf_name,
            'signatures': uniq_hits,
            'confidence': confidence,
            'baseline_status': baseline.get('status'),
            'probes_blocked': blocked,
            'probes_total': len(probe_results),
            'tuning': tuning,
            'rate_hint': rate_hint,
            'payload_hint': payload_hint,
            'duration_s': round(time.monotonic() - started, 1),
        }
    except Exception:
        raise


def waf_notice(result: Optional[Dict[str, Any]]) -> str:
    if not result:
        return ''
    v = str(result.get('verdict', ''))
    if v == 'confirmed':
        return (f"  [+] WAF gate: {result.get('waf','WAF')} CONFIRMED "
                f"({result.get('probes_blocked')}/{result.get('probes_total')} probes blocked) — "
                f"{result.get('tuning','')}")
    if v == 'likely':
        return (f"  [!] WAF gate: {result.get('waf','possible WAF')} LIKELY "
                f"({result.get('probes_blocked')}/{result.get('probes_total')} blocked) — "
                f"{result.get('tuning','')}")
    if v == 'hard-block':
        return (f"  [!] WAF gate: HARD BLOCK (baseline HTTP {result.get('baseline_status')}) — "
                f"{result.get('tuning','')}")
    return '  [*] WAF gate: no WAF detected — normal scan rate'
