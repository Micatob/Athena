"""
tests/test_light_recon.py – Phase B light recon + crt.sh subdomains
====================================================================
From the live report review:

  * ``-m vuln`` skipped discovery entirely, so the report claimed
    "Open Ports / URLs / Subdomains: None detected" while the scanner was
    happily testing a single guessed URL;
  * subdomain enumeration was wordlist-only, so it could never find names
    the list does not contain;
  * the scanner never received the URLs recon did find.

Adds: selectable discovery stages (stage-keyed results, so skipping a stage
cannot shift another stage's result), a free crt.sh certificate-transparency
source, light recon wired into ``-m vuln``, and URL hand-off to the scanner.
"""

import asyncio
import socket
import sys
from pathlib import Path


HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import athena
from modules.discovery import DiscoveryModule


class _FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status = status
        self._payload = payload

    async def json(self, content_type=None):
        return self._payload

    async def text(self):
        return ''


class _AsyncCtx:
    def __init__(self, response=None, error=None):
        self._response = response
        self._error = error

    async def __aenter__(self):
        if self._error is not None:
            raise self._error
        return self._response

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    """Only implements what the code paths under test touch."""

    def __init__(self, get_response=None, get_error=None):
        self._get_response = get_response
        self._get_error = get_error
        self.closed = False

    def get(self, *args, **kwargs):
        return _AsyncCtx(response=self._get_response, error=self._get_error)

    def head(self, *args, **kwargs):
        return _AsyncCtx(error=ConnectionError('no http in tests'))

    async def close(self):
        self.closed = True


def _coro(value=None, error=None):
    async def _run(*args, **kwargs):
        if error is not None:
            raise error
        return value
    return _run


def _fake_session(session):
    """``_get_session`` is a coroutine - the fake has to be awaitable."""
    async def _get():
        return session
    return _get


class TestStageSelection:
    def _discovery(self, monkeypatch, stages_map):
        d = DiscoveryModule()
        calls = []

        class _NoHiddenAssets:
            def __init__(self, *args, **kwargs):
                pass

            async def run(self, *args, **kwargs):
                return {}

            async def close(self):
                return None

        monkeypatch.setattr('modules.discovery.HiddenAssetScanner',
                            _NoHiddenAssets)
        for name, value in stages_map.items():
            def make(n, v):
                async def _fake(target):
                    calls.append(n)
                    if callable(v):
                        v()
                    return v
                return _fake
            setattr(d, name, make(name, value))
        monkeypatch.setattr(d, '_sanitize_technologies', _coro())
        monkeypatch.setattr(
            d, '_get_session',
            _fake_session(_FakeSession(get_response=_FakeResponse(status=404))))
        return d, calls

    def test_only_requested_stages_run(self, monkeypatch):
        d, calls = self._discovery(monkeypatch, {
            'crawl_urls': lambda: d.discovered_urls.add('https://t/a'),
            'enumerate_subdomains': None,
            'scan_ports': [443],
        })
        results = asyncio.run(d.run('https://t', stages=['crawl']))
        assert calls == ['crawl_urls']
        assert results['urls'] == ['https://t/a']
        assert results['stages_run'] == ['crawl']

    def test_default_runs_every_stage(self, monkeypatch):
        d, calls = self._discovery(monkeypatch, {
            'crawl_urls': None, 'enumerate_subdomains': None,
            'scan_ports': [80], 'detect_technologies': None,
            'find_hidden_directories': None, 'analyze_dns_records': {},
            'check_tls_certificate': {}, 'discover_security_endpoints': [],
            'discover_admin_panels': [],
        })
        results = asyncio.run(d.run('https://t'))
        assert results['stages_run'] == list(DiscoveryModule.ALL_STAGES)
        assert len(calls) == 9  # hidden_assets uses HiddenAssetScanner

    def test_skipping_a_stage_does_not_shift_other_results(self, monkeypatch):
        """The old index-based mapping (results[2], results[5], ...) broke
        the moment a stage was omitted."""
        d, _ = self._discovery(monkeypatch, {
            'analyze_dns_records': {'a_records': ['1.2.3.4']},
            'check_tls_certificate': {'domain': 't'},
            'discover_security_endpoints': [{'url': 'https://t/robots.txt'}],
            'discover_admin_panels': [{'url': 'https://t/admin'}],
        })
        results = asyncio.run(
            d.run('https://t', stages=['dns', 'tls', 'security_endpoints',
                                       'admin_panels']))
        assert results['dns_records'] == {'a_records': ['1.2.3.4']}
        assert results['tls_certificate'] == {'domain': 't'}
        assert results['security_endpoints'] == [
            {'url': 'https://t/robots.txt'}]
        assert results['admin_panels'] == [{'url': 'https://t/admin'}]
        assert results['ports'] == []          # stage not requested
        assert results['stages_run'] == [
            'dns', 'tls', 'security_endpoints', 'admin_panels']

    def test_unknown_stage_is_ignored_not_fatal(self, monkeypatch):
        d, calls = self._discovery(monkeypatch, {'crawl_urls': None})
        results = asyncio.run(d.run('https://t', stages=['crawl', 'bogus']))
        assert calls == ['crawl_urls']
        assert results['stages_run'] == ['crawl']

    def test_failed_stage_yields_default_not_crash(self, monkeypatch):
        d, _ = self._discovery(monkeypatch, {'scan_ports': None})
        # make the stage raise instead of returning
        async def boom(target):
            raise RuntimeError('port scan exploded')
        d.scan_ports = boom
        results = asyncio.run(d.run('https://t', stages=['ports']))
        assert results['ports'] == []

    def test_light_stages_exist_and_are_a_subset(self):
        assert set(DiscoveryModule.LIGHT_STAGES) <= set(DiscoveryModule.ALL_STAGES)
        # the heavy wordlist phases stay out of the light pass
        assert 'hidden_dirs' not in DiscoveryModule.LIGHT_STAGES
        assert 'hidden_assets' not in DiscoveryModule.LIGHT_STAGES
        # but light recon still covers the assets the report displays
        for stage in ('crawl', 'subdomains', 'ports', 'technologies'):
            assert stage in DiscoveryModule.LIGHT_STAGES


class TestCrtShSource:
    def test_parses_names_and_drops_foreign_hosts(self, monkeypatch):
        payload = [
            {'name_value': 'www.example.com\nmail.example.com'},
            {'name_value': '*.api.example.com'},
            {'name_value': 'evil.com'},
            {'name_value': 'example.com.evil.com'},
            {'name_value': 'not a host'},
        ]
        d = DiscoveryModule()
        monkeypatch.setattr(d, '_get_session', _fake_session(_FakeSession(get_response=_FakeResponse(payload=payload))))
        hosts = asyncio.run(d._crtsh_hosts('example.com'))
        assert hosts == {'www.example.com', 'mail.example.com',
                         'api.example.com'}

    def test_non_200_returns_empty(self, monkeypatch):
        d = DiscoveryModule()
        monkeypatch.setattr(d, '_get_session', _fake_session(_FakeSession(get_response=_FakeResponse(status=503))))
        assert asyncio.run(d._crtsh_hosts('example.com')) == set()

    def test_network_failure_is_non_fatal(self, monkeypatch):
        d = DiscoveryModule()
        monkeypatch.setattr(d, '_get_session', _fake_session(_FakeSession(get_error=ConnectionError('offline'))))
        assert asyncio.run(d._crtsh_hosts('example.com')) == set()

    def test_malformed_payload_returns_empty(self, monkeypatch):
        d = DiscoveryModule()
        monkeypatch.setattr(d, '_get_session', _fake_session(_FakeSession(get_response=_FakeResponse(payload='nope'))))
        assert asyncio.run(d._crtsh_hosts('example.com')) == set()

    def test_ct_names_are_merged_into_the_wordlist_pass(self, monkeypatch):
        d = DiscoveryModule()
        monkeypatch.setattr(
            d, '_crtsh_hosts', _coro({'vpn-02.example.com'}))

        def resolve(name):
            if name == 'vpn-02.example.com':
                return '10.0.0.9'
            raise socket.gaierror('not in DNS')
        monkeypatch.setattr(socket, 'gethostbyname', resolve)
        monkeypatch.setattr(d, '_get_session', _fake_session(_FakeSession(get_error=ConnectionError('no http'))))

        asyncio.run(d.enumerate_subdomains('https://example.com'))
        assert 'http://vpn-02.example.com' in d.discovered_subdomains
        assert 'https://vpn-02.example.com' in d.discovered_subdomains


class TestScannerTargetHandOff:
    def test_empty_discovery_falls_back_to_bare_target(self):
        assert athena._scan_targets({}) == []
        assert athena._scan_targets(None) == []

    def test_collects_crawl_admin_and_wellknown_urls(self):
        targets = athena._scan_targets({
            'urls': ['https://t/', 'https://t/index.php?page=',
                     'https://t/'],
            'security_endpoints': [{'url': 'https://t/robots.txt'}],
            'admin_panels': [{'url': 'https://t/admin', 'status': 200},
                             {'panel_type': 'CPANEL'}],
        })
        assert targets == ['https://t/', 'https://t/index.php?page=',
                           'https://t/robots.txt', 'https://t/admin']

    def test_non_string_entries_are_ignored(self):
        assert athena._scan_targets({'urls': [None, 42, {'no': 'url'}]}) == []


class TestRunDiscoveryPassesStages:
    def test_stages_are_forwarded(self, monkeypatch):
        seen = {}

        class _Recorder:
            def __init__(self):
                seen['stages'] = 'NOT_CALLED'

            async def run(self, target, stages=None):
                seen['stages'] = stages
                return {'urls': [], 'subdomains': [], 'ports': [],
                        'technologies': []}

            async def harvest_emails(self, target, urls):
                return []

            async def close(self):
                return None

        monkeypatch.setattr(athena, 'DiscoveryModule', _Recorder)
        asyncio.run(athena.run_discovery(
            'https://t', stages=list(DiscoveryModule.LIGHT_STAGES)))
        assert seen['stages'] == list(DiscoveryModule.LIGHT_STAGES)

    def test_default_is_full_discovery(self, monkeypatch):
        seen = {}

        class _Recorder:
            async def run(self, target, stages=None):
                seen['stages'] = stages
                return {}

            async def harvest_emails(self, target, urls):
                return []

            async def close(self):
                return None

        monkeypatch.setattr(athena, 'DiscoveryModule', _Recorder)
        asyncio.run(athena.run_discovery('https://t'))
        assert seen['stages'] is None
