"""
tests/test_false_positive_hardening.py – evidence required, not hope
====================================================================
Regression cover for the false positives produced by a live scan:

  * Timing: a slow response alone must never confirm SQLi / command
    injection / NoSQL - the delay has to survive a stable baseline and
    scale with the requested sleep (the scanned host answered anything
    in 1-25s, so "7.5s" was the host, not MySQL).
  * Error pages (406/403/5xx) are not content: reflection checks against
    them compare an error document, not the resource.
  * HTTP method and cache-poisoning detectors need real evidence (an
    executed request, an ``Allow`` header, a distinctive marker) instead
    of "the server answered" / "the page contains the word http".
  * SSTI must see an *evaluated* expression, never a reflected payload.
  * Exploitation attempts carry an explainable ``detail`` and the HTML
    report renders the Automated Exploitation section.
"""

import asyncio
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import athena
import modules.vulnerability_scanner as vs
from modules.reporting import ReportGenerator
from modules.timing_probe import (format_delay_evidence, measure_baseline,
                                  verify_sleep_delay, verify_with_baseline)
from modules.vulnerability_scanner import VulnerabilityScanner

IN_SCOPE = 'http://fp.test.local'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def seq(values):
    """Async sample function returning each value in turn."""
    it = iter(list(values))

    async def _sample(*args, **kwargs):
        return next(it)

    return _sample


def const(value):
    async def _sample(*args, **kwargs):
        return value
    return _sample


class _Resp:
    def __init__(self, status=200, body='', headers=None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    async def text(self):
        return self._body

    async def read(self):
        return self._body.encode()

    def __await__(self):
        # Scanner code does `resp = await self._request(...)` while some
        # detectors `async with` it - one object does double duty.
        async def _self():
            return self
        return _self().__await__()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    """Stand-in for aiohttp.ClientSession (request/get -> async CM)."""

    def __init__(self, responder):
        self._responder = responder

    def request(self, method, url, **kwargs):
        return _Resp(**self._responder(method, url, kwargs))

    def get(self, url, **kwargs):
        return _Resp(**self._responder('GET', url, kwargs))


def make_scanner() -> VulnerabilityScanner:
    return VulnerabilityScanner(stealth_mode=False)


# ---------------------------------------------------------------------------
# modules/timing_probe
# ---------------------------------------------------------------------------


class TestTimingProbe:
    pytestmark = pytest.mark.asyncio

    async def test_noisy_baseline_is_not_measurable(self):
        """The live host: 2.5s / 4.4s / 14.7s for the same benign URL."""
        assert await measure_baseline(seq([2.48, 4.36, 14.69]),
                                      max_spread=1.0) is None

    async def test_failed_baseline_sample_is_not_measurable(self):
        assert await measure_baseline(seq([0.5, None]), max_spread=1.0) is None

    async def test_stable_baseline_is_measured(self):
        median, spread = await measure_baseline(seq([1.0, 1.2]), max_spread=1.0)
        assert median == pytest.approx(1.1)
        assert spread == pytest.approx(0.2)

    async def test_scaling_delay_is_evidence(self):
        async def payload(sleep):
            return {2.0: 3.0, 5.0: 6.0}[sleep]

        evidence = await verify_with_baseline(payload, (1.0, 0.1))
        assert evidence is not None
        assert evidence['requested_s'] == [2.0, 5.0]
        assert evidence['measured_s'] == [3.0, 6.0]

    async def test_delay_that_does_not_scale_is_rejected(self):
        """12s for both sleeps is a slow host, not an injected one."""
        async def payload(sleep):
            return {2.0: 12.0, 5.0: 12.5}[sleep]

        assert await verify_with_baseline(payload, (1.0, 0.1)) is None

    async def test_delay_below_baseline_margin_is_rejected(self):
        async def payload(sleep):
            return {2.0: 1.5, 5.0: 5.0}[sleep]

        assert await verify_with_baseline(payload, (1.0, 0.1)) is None

    async def test_verify_sleep_delay_measures_its_own_baseline(self):
        async def payload(sleep):
            return 0.5 + sleep * 0.9

        evidence = await verify_sleep_delay(payload, seq([0.5, 0.6]))
        assert evidence is not None
        assert evidence['baseline_s'] == pytest.approx(0.55, abs=0.11)

    async def test_format_delay_evidence_is_readable(self):
        text = format_delay_evidence({'baseline_s': 1.0, 'baseline_spread_s': 0.1,
                                      'requested_s': [2, 5],
                                      'measured_s': [3.0, 6.0]})
        assert 'baseline 1.00s' in text and 'sleep 2s -> 3.00s' in text
        assert format_delay_evidence(None) == 'no timing evidence'


# ---------------------------------------------------------------------------
# Scanner time-based detection
# ---------------------------------------------------------------------------


class TestScannerTimingRegression:
    pytestmark = pytest.mark.asyncio

    def _patch(self, monkeypatch, scanner, timed_values, threshold=0.0):
        monkeypatch.setattr(vs, 'TIMING_SCREEN_THRESHOLD', threshold)
        monkeypatch.setattr(scanner, '_request',
                            lambda *a, **k: _Resp(200, '<html>page</html>'))
        monkeypatch.setattr(scanner, '_timed_get',
                            seq(timed_values))

    async def test_slow_host_does_not_confirm_sqli(self, monkeypatch):
        """Regression: 7.5s on a host whose baseline itself hit 14.7s."""
        scanner = make_scanner()
        self._patch(monkeypatch, scanner,
                    [2.48, 4.36, 14.69, 2.7, 3.0, 2.6, 6.0])

        results = await scanner.test_sql_injection_aggressive(
            f'{IN_SCOPE}/page?id=1', {'id': ['1']})

        assert [v for v in results if 'SQL' in v.get('type', '')] == []
        await scanner.close()

    async def test_scaling_delay_confirms_sqli(self, monkeypatch):
        scanner = make_scanner()
        # baseline 0.5/0.5, then SLEEP(2)->2.3s and SLEEP(5)->5.0s
        self._patch(monkeypatch, scanner, [0.5, 0.5, 2.3, 5.0])

        results = await scanner.test_sql_injection_aggressive(
            f'{IN_SCOPE}/page?id=1', {'id': ['1']})

        sqli = [v for v in results if v.get('type', '').startswith('SQL Injection')]
        assert len(sqli) == 1
        assert 'confirmed' in sqli[0]['description']
        assert sqli[0]['evidence']['method'] == 'time_based'
        await scanner.close()

    async def test_slow_host_does_not_confirm_command_injection(self, monkeypatch):
        scanner = make_scanner()
        self._patch(monkeypatch, scanner, [9.0, 14.0, 10.0, 11.0])

        results = await scanner.test_command_injection_aggressive(
            f'{IN_SCOPE}/page', {'cmd': ['id']})

        assert [v for v in results if 'Time-Based' in v.get('type', '')] == []
        await scanner.close()


# ---------------------------------------------------------------------------
# Error pages are not content
# ---------------------------------------------------------------------------


class TestErrorPageGating:
    pytestmark = pytest.mark.asyncio

    async def test_xss_not_confirmed_on_error_page(self, monkeypatch):
        """A 406 that echoes the URL is still an error document."""
        scanner = make_scanner()
        payload = "<script>alert('XSS')</script>"
        monkeypatch.setattr(
            scanner, '_request',
            lambda *a, **k: _Resp(406, f'<html>406: {payload}</html>'))

        results = await scanner.test_xss_aggressive(
            f'{IN_SCOPE}/search', {'q': ['test']})

        assert [v for v in results if 'XSS' in v.get('type', '')] == []
        await scanner.close()

    async def test_xss_confirmed_on_real_reflection(self, monkeypatch):
        scanner = make_scanner()
        payload = "<script>alert('XSS')</script>"
        monkeypatch.setattr(
            scanner, '_request',
            lambda *a, **k: _Resp(200, f'<html>Results: {payload}</html>'))

        results = await scanner.test_xss_aggressive(
            f'{IN_SCOPE}/search', {'q': ['test']})

        assert [v for v in results if 'XSS' in v.get('type', '')]
        await scanner.close()

    async def test_ssti_needs_an_evaluated_expression(self, monkeypatch):
        scanner = make_scanner()

        def reflected(method, url, kwargs):
            # payload echoed back, nothing evaluated
            if '7%2A' in url:
                return dict(status=200, body='Order {{7*7}} shipped')
            return dict(status=200, body='Order form')

        monkeypatch.setattr(scanner, '_request', self._awaitable(reflected))
        found = await scanner.test_ssti(f'{IN_SCOPE}/ctl', {'search': ['x']})
        assert [v for v in found if 'Template' in v.get('type', '')] == []

        def static_indicators(method, url, kwargs):
            # "49 items" is on every page - the baseline gate must catch it
            return dict(status=200, body='Catalog: 49 items in stock')

        monkeypatch.setattr(scanner, '_request', self._awaitable(static_indicators))
        found = await scanner.test_ssti(f'{IN_SCOPE}/ctl', {'search': ['x']})
        assert [v for v in found if 'Template' in v.get('type', '')] == []

        def evaluated(method, url, kwargs):
            if '7%2A' in url:
                return dict(status=200, body='Order 49 shipped')
            return dict(status=200, body='Order form')

        monkeypatch.setattr(scanner, '_request', self._awaitable(evaluated))
        found = await scanner.test_ssti(f'{IN_SCOPE}/ctl', {'search': ['x']})
        assert [v for v in found if 'Template' in v.get('type', '')]
        await scanner.close()

    @staticmethod
    def _awaitable(responder):
        async def _request(method, url, **kwargs):
            return _Resp(**responder(method, url, kwargs))
        return _request

    async def test_xpath_ignores_a_large_but_unchanged_page(self, monkeypatch):
        scanner = make_scanner()
        body = '<html>' + 'a' * 800 + '</html>'
        monkeypatch.setattr(scanner, '_request',
                            lambda *a, **k: _Resp(200, body))

        results = await scanner.test_xpath_injection(
            f'{IN_SCOPE}/data?category=books', {'category': ['books']})

        assert [v for v in results if 'XPath' in v.get('type', '')] == []
        await scanner.close()


# ---------------------------------------------------------------------------
# HTTP method / cache poisoning evidence
# ---------------------------------------------------------------------------


class TestMethodAndCacheEvidence:
    pytestmark = pytest.mark.asyncio

    async def test_error_responses_are_not_accepted_methods(self, monkeypatch):
        scanner = make_scanner()
        monkeypatch.setattr(scanner, '_ensure_session',
                            self._session(lambda *a: dict(status=406, body='nope')))

        results = await scanner.test_http_method_fuzzing(f'{IN_SCOPE}/page')
        assert results == []
        await scanner.close()

    async def test_accepted_put_is_reported(self, monkeypatch):
        scanner = make_scanner()

        def responder(method, url, kwargs):
            if method == 'PUT':
                return dict(status=200, body='stored')
            return dict(status=406, body='nope')

        monkeypatch.setattr(scanner, '_ensure_session', self._session(responder))
        results = await scanner.test_http_method_fuzzing(f'{IN_SCOPE}/page')

        assert len(results) == 1
        assert results[0]['payload'] == 'PUT'
        await scanner.close()

    async def test_options_only_flagged_when_write_method_advertised(self, monkeypatch):
        scanner = make_scanner()

        def responder(method, url, kwargs):
            if method == 'OPTIONS':
                return dict(status=200, body='',
                            headers={'Allow': 'GET, POST, PUT, DELETE'})
            return dict(status=405, body='')

        monkeypatch.setattr(scanner, '_ensure_session', self._session(responder))
        results = await scanner.test_http_method_fuzzing(f'{IN_SCOPE}/page')

        assert len(results) == 1
        assert 'PUT' in results[0]['payload']
        await scanner.close()

    async def test_cache_poisoning_requires_a_distinct_marker(self, monkeypatch):
        """Regression: X-Forwarded-Scheme 'http' matched every HTML page."""
        scanner = make_scanner()
        monkeypatch.setattr(scanner, '_ensure_session', self._session(
            lambda *a: dict(status=200, body='<html><a href="http://x/">i</a></html>')))

        results = await scanner.test_cache_poisoning(f'{IN_SCOPE}/page')
        assert results == []
        await scanner.close()

    async def test_cache_poisoning_detects_reflected_host(self, monkeypatch):
        scanner = make_scanner()
        monkeypatch.setattr(scanner, '_ensure_session', self._session(
            lambda *a: dict(status=200, body='<html>Host: evil.com</html>')))

        results = await scanner.test_cache_poisoning(f'{IN_SCOPE}/page')
        assert len(results) == 1
        await scanner.close()

    @staticmethod
    def _session(responder):
        async def _ensure(*args, **kwargs):
            return _FakeSession(responder)
        return _ensure


# ---------------------------------------------------------------------------
# Attempt detail + report rendering
# ---------------------------------------------------------------------------


class TestAttemptDetailAndReport:
    pytestmark = pytest.mark.asyncio

    async def test_inconclusive_attempt_explains_itself(self):
        from modules.exploitation_runner import ExploitationRunner
        from modules.engagement import AD_HOC_TECHNIQUES, Technique, ad_hoc_engagement

        engagement = ad_hoc_engagement(
            [IN_SCOPE],
            techniques=[*AD_HOC_TECHNIQUES, Technique.EXPLOITATION.value])
        runner = ExploitationRunner(engagement=engagement, delay=0)
        runner.module = SimpleNamespace(
            exploit_vulnerability=self._stub(None))

        summary = await runner.execute(IN_SCOPE, [
            {'type': 'SQL Injection', 'url': f'{IN_SCOPE}/view?id=1',
             'severity': 'CRITICAL'}])

        attempt = summary['attempts'][0]
        assert attempt['status'] == 'inconclusive'
        assert 'no proof' in attempt['detail']

    async def test_confirmed_attempt_carries_the_handler_description(self):
        from modules.exploitation_runner import ExploitationRunner
        from modules.engagement import AD_HOC_TECHNIQUES, Technique, ad_hoc_engagement

        engagement = ad_hoc_engagement(
            [IN_SCOPE],
            techniques=[*AD_HOC_TECHNIQUES, Technique.EXPLOITATION.value])
        runner = ExploitationRunner(engagement=engagement, delay=0)
        runner.module = SimpleNamespace(
            exploit_vulnerability=self._stub(
                {'status': 'SUCCESS', 'description': 'union columns matched'}))

        summary = await runner.execute(IN_SCOPE, [
            {'type': 'SQL Injection', 'url': f'{IN_SCOPE}/view?id=1',
             'severity': 'CRITICAL'}])

        attempt = summary['attempts'][0]
        assert attempt['status'] == 'confirmed'
        assert attempt['detail'] == 'union columns matched'

    @staticmethod
    def _stub(result):
        async def _handle(finding):
            return result
        return _handle

    async def test_html_report_renders_the_automated_exploitation_section(self):
        report = ReportGenerator().generate_comprehensive_report({
            'target': IN_SCOPE,
            'vulnerabilities': [],
            'discovery': {},
            'exploitation': [
                {'type': 'SQL Injection (Blind)', 'url': f'{IN_SCOPE}/view?id=1',
                 'status': 'inconclusive', 'detail': 'handler returned no proof'},
            ],
        })
        html = athena._generate_html_report(report)

        assert 'Automated Exploitation' in html
        assert 'handler returned no proof' in html
        summary = report['athena_security_audit']['audit_summary']
        assert summary['exploitation_attempted'] == 1
        assert summary['exploitation_inconclusive'] == 1
        assert summary['successful_demonstrations'] == 0

    async def test_html_report_states_when_nothing_was_retested(self):
        report = ReportGenerator().generate_comprehensive_report({
            'target': IN_SCOPE, 'vulnerabilities': [], 'discovery': {},
        })
        html = athena._generate_html_report(report)
        assert 'No findings were actively re-tested' in html
        # no attempt rows and no fabricated counts
        assert 'Attempted: <strong>0</strong>' not in html
