"""Tests for sqlmap/dalfox/wafw00f/httpx adapters + CISA KEV enrichment.

Everything runs against fakes: no binary is executed and no network is
touched.  The contract under test is the same as the nuclei adapter -
clean degradation when absent, evidence-only findings when present.
"""

import argparse
import asyncio
import json

import pytest

from modules import tool_bridge as tb


def asyncio_run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


SQLMAP_VULN = """---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234
---
"""

DALFOX_JSON = json.dumps({
    'findings': [
        {'url': 'https://t.example/search?q=1', 'param': 'q',
         'poc': '<script>alert(45)</script>', 'result_type': 'V',
         'severity': 'High', 'confidence': 'high'},
        {'url': 'https://t.example/search?q=2', 'param': 'q',
         'type': 'R', 'severity': 'Low'},
    ],
})

HTTPX_JSONL = '\n'.join([
    json.dumps({'url': 'https://t.example/', 'input': 't.example',
                'status-code': 200, 'title': 'Example',
                'webserver': 'nginx 1.22.0', 'tech': ['nginx 1.22.0'],
                'ip': '93.184.216.34'}),
])


# -- sqlmap ------------------------------------------------------------------

def test_sqlmap_parses_injectable_parameter():
    findings = tb.parse_sqlmap_stdout(SQLMAP_VULN, 'https://t.example/?id=1')
    assert len(findings) == 1
    assert findings[0]['type'] == 'SQL Injection'
    assert findings[0]['severity'] == 'CRITICAL'
    assert findings[0]['url'] == 'https://t.example/?id=1'
    assert findings[0]['source'] == 'sqlmap'
    assert findings[0]['verified'] is True


def test_sqlmap_clean_miss_is_no_findings():
    raw = '[INFO] all tested parameters do not appear to be injectable'
    assert tb.parse_sqlmap_stdout(raw, 'https://t.example/') == []
    assert tb.parse_sqlmap_stdout('', 'https://t.example/') == []


def test_sqlmap_chatter_without_parameter_is_not_evidence():
    assert tb.parse_sqlmap_stdout('[INFO] testing connection\n[INFO] heuristics', 'https://t/') == []


def test_sqlmap_missing_binary_is_structured_skip(monkeypatch):
    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): None)
    out = asyncio_run(tb.run_sqlmap('https://t.example/?id=1'))
    assert out['status'] == 'unavailable'
    assert out['findings'] == []
    assert 'sqlmap' in out['reason'].lower()


def test_sqlmap_disabled_flag(monkeypatch):
    out = asyncio_run(tb.run_sqlmap('https://t.example/?id=1', enabled=False))
    assert out['status'] == 'disabled'


def test_sqlmap_executes_and_reports(monkeypatch):
    async def _run(argv, timeout):
        assert argv[0] == '/opt/sqlmap'
        assert '--batch' in argv
        assert isinstance(argv, list)
        return {'ok': True, 'stdout': SQLMAP_VULN, 'stderr': '',
                'returncode': 0, 'duration_s': 3.0}

    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): '/opt/sqlmap')
    monkeypatch.setattr(tb, '_run_process', _run)
    out = asyncio_run(tb.run_sqlmap('https://t.example/?id=1'))
    assert out['status'] == 'executed'
    assert out['matched'] == 1


def test_sqlmap_candidate_urls_prefers_query_strings():
    urls = ['https://t/a', 'https://t/b?x=1', 'https://t/c?y=2']
    picked = tb.sqlmap_candidate_urls(urls, limit=2)
    assert picked == ['https://t/b?x=1', 'https://t/c?y=2']


def test_sqlmap_broken_launch_is_unavailable_with_reinstall_hint(monkeypatch):
    async def _run(argv, timeout):
        return {'ok': False, 'stdout': '',
                'stderr': ("python.exe: can't open file "
                           "'C:\\\\tools\\\\sqlmap\\\\sqlmap.py': "
                           "[Errno 2] No such file or directory"),
                'returncode': 1, 'duration_s': 0.1}

    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): '/opt/sqlmap.cmd')
    monkeypatch.setattr(tb, '_run_process', _run)
    out = asyncio_run(tb.run_sqlmap('https://t.example/?id=1'))
    assert out['status'] == 'unavailable'
    assert out['findings'] == []
    assert 'install_tools.py --only sqlmap' in out['reason']


def test_sqlmap_timeout_stays_failed(monkeypatch):
    async def _run(argv, timeout):
        return {'ok': False, 'stdout': '', 'stderr': '', 'returncode': None,
                'timeout': True, 'duration_s': 300.0}

    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): '/opt/sqlmap')
    monkeypatch.setattr(tb, '_run_process', _run)
    out = asyncio_run(tb.run_sqlmap('https://t.example/?id=1'))
    assert out['status'] == 'failed'
    assert out['reason'].startswith('timed out')


# -- dalfox ------------------------------------------------------------------

def test_dalfox_keeps_verified_only():
    findings = tb.parse_dalfox_json(DALFOX_JSON, 'https://t.example/')
    assert len(findings) == 1
    assert findings[0]['severity'] == 'HIGH'
    assert 'XSS' in findings[0]['type']
    assert findings[0]['verified'] is True


def test_dalfox_empty_is_clean():
    assert tb.parse_dalfox_json('', 'https://t/') == []
    assert tb.parse_dalfox_json('not json', 'https://t/') == []


def test_dalfox_missing_binary_is_structured_skip(monkeypatch):
    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): None)
    out = asyncio_run(tb.run_dalfox('https://t.example/'))
    assert out['status'] == 'unavailable'
    assert out['findings'] == []


def test_dalfox_exit_1_with_findings_is_executed(monkeypatch):
    async def _run(argv, timeout):
        assert 'scan' in argv
        return {'ok': False, 'stdout': DALFOX_JSON, 'stderr': '',
                'returncode': 1, 'duration_s': 2.0}

    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): '/opt/dalfox')
    monkeypatch.setattr(tb, '_run_process', _run)
    out = asyncio_run(tb.run_dalfox('https://t.example/'))
    assert out['status'] == 'executed'
    assert out['matched'] == 1


# -- wafw00f -----------------------------------------------------------------

def test_wafw00f_text_detects_waf():
    parsed = tb.parse_wafw00f_text('Checking https://t/\nThe site is behind Cloudflare (Cloudflare)', 'https://t/')
    assert parsed['detected'] is True


def test_wafw00f_text_clean_miss():
    parsed = tb.parse_wafw00f_text('Checking https://t/\nNo WAF detected', 'https://t/')
    assert parsed['detected'] is False


def test_wafw00f_detection_is_info_not_vuln(monkeypatch):
    async def _run(argv, timeout):
        return {'ok': True, 'stdout': 'The site is behind ModSecurity', 'stderr': '',
                'returncode': 0, 'duration_s': 1.0}

    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): '/opt/wafw00f')
    monkeypatch.setattr(tb, '_run_process', _run)
    out = asyncio_run(tb.run_wafw00f('https://t.example/'))
    assert out['status'] == 'executed'
    assert out['matched'] == 1
    assert out['findings'][0]['severity'] == 'INFO'
    assert out['findings'][0]['type'] == 'WAF Detected'


def test_wafw00f_no_waf_is_executed_clean_miss(monkeypatch):
    async def _run(argv, timeout):
        return {'ok': True, 'stdout': 'No WAF detected by the generic detection', 'stderr': '',
                'returncode': 0, 'duration_s': 1.0}

    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): '/opt/wafw00f')
    monkeypatch.setattr(tb, '_run_process', _run)
    out = asyncio_run(tb.run_wafw00f('https://t.example/'))
    assert out['status'] == 'executed'
    assert out['findings'] == []


# -- httpx -------------------------------------------------------------------

def test_httpx_parses_host_records():
    hosts = tb.parse_httpx_jsonl(HTTPX_JSONL)
    assert len(hosts) == 1
    assert hosts[0]['status'] == 200
    assert 'nginx' in hosts[0]['webserver'].lower()


def test_httpx_never_returns_vuln_findings(monkeypatch):
    async def _run(argv, timeout):
        if argv[1:2] == ['-version']:
            return {'ok': True, 'stdout': 'v1.7.0', 'stderr': '',
                    'returncode': 0, 'duration_s': 0.1}
        assert '-json' in argv
        return {'ok': True, 'stdout': HTTPX_JSONL, 'stderr': '',
                'returncode': 0, 'duration_s': 1.0}

    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): '/opt/httpx')
    monkeypatch.setattr(tb, '_run_process', _run)
    out = asyncio_run(tb.run_httpx('https://t.example/'))
    assert out['status'] == 'executed'
    assert out['findings'] == []
    assert len(out['hosts']) == 1


def test_httpx_old_binary_falls_back(monkeypatch):
    calls = []

    async def _run(argv, timeout):
        calls.append(list(argv))
        if argv[1:2] == ['-version']:
            return {'ok': True, 'stdout': 'v1.7.0', 'stderr': '',
                    'returncode': 0, 'duration_s': 0.1}
        if '-tech-detect' in argv:
            return {'ok': False, 'stdout': '', 'stderr': 'Error: unknown flag: -tech-detect',
                    'returncode': 2, 'duration_s': 0.1}
        return {'ok': True, 'stdout': HTTPX_JSONL, 'stderr': '',
                'returncode': 0, 'duration_s': 0.5}

    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): '/opt/httpx')
    monkeypatch.setattr(tb, '_run_process', _run)
    out = asyncio_run(tb.run_httpx('https://t.example/'))
    assert out['status'] == 'executed'
    assert len(calls) == 3  # pd-httpx probe + full argv + bare fallback


# -- notices / status --------------------------------------------------------

@pytest.mark.parametrize('tool', ['sqlmap', 'dalfox', 'wafw00f', 'httpx'])
def test_missing_tool_notice_names_flag(tool):
    unavailable = tb.tool_notice({'tool': tool, 'status': 'unavailable', 'reason': 'not installed'})
    assert tool.capitalize() in unavailable or tool in unavailable.lower()
    disabled = tb.tool_notice({'tool': tool, 'status': 'disabled', 'reason': ''})
    assert f'--no-{tool}' in disabled


def test_tool_status_supports_new_tools(monkeypatch):
    async def _run(argv, timeout):
        return {'ok': True, 'stdout': 'v1.2.3', 'stderr': '', 'returncode': 0, 'duration_s': 0.1}

    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): f'/opt/{name}')
    monkeypatch.setattr(tb, '_run_process', _run)
    for tool in ('sqlmap', 'dalfox', 'wafw00f', 'httpx'):
        status = asyncio_run(tb.tool_status(tool))
        assert status['installed'] is True
        assert status['version'] == 'v1.2.3'


def test_supported_tools_excludes_ffuf():
    assert 'ffuf' not in tb.SUPPORTED_TOOLS
    assert set(tb.SUPPORTED_TOOLS) == {'nuclei', 'sqlmap', 'dalfox', 'wafw00f', 'httpx'}


def test_httpx_python_package_collision_is_not_mistaken_for_pd(monkeypatch):
    async def _run(argv, timeout):
        return {'ok': False, 'stdout': '', 'stderr': 'Usage: httpx [OPTIONS] URL\nError: No such option: -e',
                'returncode': 2, 'duration_s': 0.1}

    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): '/opt/httpx')
    monkeypatch.setattr(tb, '_run_process', _run)
    status = asyncio_run(tb.tool_status('httpx'))
    assert status['installed'] is False
    out = asyncio_run(tb.run_httpx('https://t.example/'))
    assert out['status'] == 'unavailable'
    assert 'ProjectDiscovery' in out['reason']


# -- athena wiring -----------------------------------------------------------

def test_cli_skip_flags_default_off(monkeypatch):
    import sys
    import athena
    monkeypatch.setattr(sys, 'argv', ['athena.py', '-t', 'https://t.example/'])
    args = athena.parse_args()
    assert args.no_sqlmap is False
    assert args.no_dalfox is False
    assert args.no_wafw00f is False
    assert args.no_httpx is False
    assert args.no_kev is False


def test_extended_tools_degrade_cleanly_when_nothing_installed(monkeypatch, capsys):
    import athena

    async def _reachable(url, timeout=10.0):
        return True

    monkeypatch.setattr(athena, '_quick_reachable', _reachable)
    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): None)
    args = argparse.Namespace(no_sqlmap=False, no_dalfox=False, no_wafw00f=False, no_httpx=False)
    out = asyncio_run(athena.run_extended_tools('https://t.example/', args, ['https://t.example/']))
    assert isinstance(out, list)
    assert all(s['status'] == 'unavailable' for s in out)
    printed = capsys.readouterr().out
    assert 'unavailable' in printed


def test_extended_tools_respect_skip_flags(monkeypatch):
    import athena

    async def _reachable(url, timeout=10.0):
        return True

    monkeypatch.setattr(athena, '_quick_reachable', _reachable)
    called = []

    async def _fake_run(target, binary=None, timeout=1.0, extra_args=(), enabled=True):
        called.append(enabled)
        return {'tool': 'x', 'status': 'disabled' if not enabled else 'executed',
                'findings': [], 'matched': 0, 'duration_s': 0.0, 'argv': []}

    monkeypatch.setattr(tb, 'run_sqlmap', _fake_run)
    monkeypatch.setattr(tb, 'run_dalfox', _fake_run)
    monkeypatch.setattr(tb, 'run_wafw00f', _fake_run)
    monkeypatch.setattr(tb, 'run_httpx', _fake_run)
    args = argparse.Namespace(no_sqlmap=True, no_dalfox=True, no_wafw00f=True, no_httpx=True)
    out = asyncio_run(athena.run_extended_tools('https://t.example/', args, ['https://t.example/']))
    assert out
    assert all(s['status'] == 'disabled' for s in out)


def test_httpx_enrichment_adds_unseen_tech():
    import athena
    discovery = {'technologies': ['nginx'], 'technologies_with_confidence': []}
    summary = {'tool': 'httpx', 'status': 'executed',
               'hosts': [{'url': 'https://t/', 'webserver': 'Apache 2.4.49',
                          'tech': ['Apache 2.4.49'], 'status': 200,
                          'title': '', 'ip': '', 'cdn': False}]}
    athena._merge_httpx_into_discovery(discovery, summary)
    assert any('apache' in str(t).lower() for t in discovery['technologies'])
    assert any(e.get('technology') == 'Apache' for e in discovery['technologies_with_confidence'])


def test_httpx_enrichment_never_raises():
    import athena
    athena._merge_httpx_into_discovery(None, None)
    athena._merge_httpx_into_discovery({}, {'tool': 'httpx'})


def test_html_renders_new_tool_rows():
    import athena
    tools = [
        {'tool': 'sqlmap', 'status': 'executed', 'matched': 1, 'target': 'https://t/?id=1',
         'binary': '/usr/bin/sqlmap', 'duration_s': 5.0, 'findings': []},
        {'tool': 'wafw00f', 'status': 'executed', 'matched': 1, 'waf_detected': True,
         'waf': 'Cloudflare', 'binary': '/usr/bin/wafw00f', 'duration_s': 2.0, 'findings': []},
        {'tool': 'httpx', 'status': 'executed', 'matched': 0, 'hosts_probed': 3,
         'binary': '/usr/bin/httpx', 'duration_s': 2.0, 'findings': []},
    ]
    html_out = athena._generate_html_report({'athena_security_audit': {'external_tools': tools}})
    assert 'injectable parameter' in html_out
    assert 'Cloudflare' in html_out
    assert 'host(s) probed' in html_out


# -- KEV ---------------------------------------------------------------------

def test_kev_index_and_exact_match():
    from modules import kev
    payload = {'vulnerabilities': [
        {'cveID': 'CVE-2021-44228', 'vendorProject': 'Apache',
         'product': 'Log4j2', 'vulnerabilityName': 'Log4Shell',
         'dateAdded': '2021-12-10', 'dueDate': '2021-12-24',
         'shortDescription': 'RCE', 'requiredAction': 'Patch',
         'knownRansomwareCampaignUse': 'Known'},
    ]}
    catalog = kev._index(payload)
    assert kev.is_kev('cve-2021-44228', catalog) is True
    assert kev.is_kev('CVE-2021-99999', catalog) is False


def test_kev_annotate_flags_matching_cves():
    from modules import kev

    class _Cve:
        def __init__(self, cve_id):
            self.cve_id = cve_id

    class _Ver:
        def __init__(self, cves):
            self.cves = cves

    catalog = {'CVE-2021-44228': {'cve_id': 'CVE-2021-44228', 'due_date': '2021-12-24', 'name': 'Log4Shell'}}
    results = [_Ver([_Cve('CVE-2021-44228'), _Cve('CVE-2020-0001')])]
    summary = kev.annotate_cve_results(results, catalog)
    assert summary['kev_count'] == 1
    assert summary['kev_ids'] == ['CVE-2021-44228']
    assert results[0].cves[0].kev is True
    assert results[0].cves[1].kev is False


def test_kev_offline_returns_empty_catalog(monkeypatch, tmp_path):
    from modules import kev
    monkeypatch.setattr(kev, 'fetch_kev_feed', lambda url=kev.KEV_URL, timeout=15: (_ for _ in ()).throw(OSError('offline')))
    catalog = kev.load_kev_catalog(cache_path=str(tmp_path / 'kev.json'), refresh=True)
    assert catalog == {}
    assert kev.annotate_cve_results([], {}) == {'kev_count': 0, 'kev_ids': [], 'catalog_size': 0}

def test_extended_tools_skip_fanout_when_target_unreachable(monkeypatch, capsys):
    import athena

    async def _unreachable(url, timeout=10.0):
        return False

    monkeypatch.setattr(athena, "_quick_reachable", _unreachable)
    monkeypatch.setattr(tb, "find_binary", lambda name, extra_dirs=(): "/opt/x")
    args = argparse.Namespace(no_sqlmap=False, no_dalfox=False,
                              no_wafw00f=True, no_httpx=True)
    out = asyncio_run(athena.run_extended_tools(
        "https://down.example/", args, ["https://down.example/"]))
    by_tool = {s["tool"]: s["status"] for s in out}
    assert by_tool.get("sqlmap") == "skipped"
    assert by_tool.get("dalfox") == "skipped"
    assert "fan-out skipped" in capsys.readouterr().out


def _clean_dalfox(target):
    return {'tool': 'dalfox', 'status': 'executed', 'binary': '/opt/dalfox',
            'reason': '', 'findings': [], 'matched': 0,
            'duration_s': 1.0, 'argv': [], 'target': target}


def test_dalfox_skips_host_after_timeout(monkeypatch, capsys):
    """One tarpit host burns a single timeout, not one per URL."""
    import athena

    async def _reachable(url, timeout=10.0):
        return True

    monkeypatch.setattr(athena, "_quick_reachable", _reachable)
    calls = []

    async def _fake_dalfox(target, binary=None, timeout=300.0, extra_args=(),
                           enabled=True):
        calls.append(target)
        if "slow.example" in target:
            return {'tool': 'dalfox', 'status': 'failed', 'binary': '/opt/dalfox',
                    'reason': 'timed out after 300s', 'findings': [], 'matched': 0,
                    'duration_s': 300.0, 'argv': [], 'target': target}
        return _clean_dalfox(target)

    monkeypatch.setattr(tb, "run_dalfox", _fake_dalfox)
    monkeypatch.setattr(tb, "find_binary", lambda name, extra_dirs=(): None)
    args = argparse.Namespace(no_sqlmap=False, no_dalfox=False,
                              no_wafw00f=True, no_httpx=True)
    urls = ["https://slow.example/a", "https://slow.example/b",
            "https://ok.example/"]
    out = asyncio_run(athena.run_extended_tools(
        "https://slow.example/a", args, urls))

    assert calls == ["https://slow.example/a", "https://ok.example/"]
    dalfox_rows = [s for s in out if s.get("tool") == "dalfox"]
    assert len(dalfox_rows) == 3  # timeout + tarpit-skip + clean, all kept
    assert any("earlier probe" in str(s.get("reason", ""))
               for s in dalfox_rows)


def test_dalfox_console_stays_compact_on_mixed_outcomes(monkeypatch, capsys):
    """Nine probes print a handful of lines; the report keeps all nine."""
    import athena

    async def _reachable(url, timeout=10.0):
        return True

    monkeypatch.setattr(athena, "_quick_reachable", _reachable)

    async def _fake_dalfox(target, binary=None, timeout=300.0, extra_args=(),
                           enabled=True):
        if target.endswith("/bad"):
            return {'tool': 'dalfox', 'status': 'failed', 'binary': '/opt/dalfox',
                    'reason': 'connection reset by peer', 'findings': [],
                    'matched': 0, 'duration_s': 2.0, 'argv': [], 'target': target}
        if "slow" in target:
            return {'tool': 'dalfox', 'status': 'failed', 'binary': '/opt/dalfox',
                    'reason': 'timed out after 300s', 'findings': [],
                    'matched': 0, 'duration_s': 300.0, 'argv': [], 'target': target}
        return _clean_dalfox(target)

    monkeypatch.setattr(tb, "run_dalfox", _fake_dalfox)
    monkeypatch.setattr(tb, "find_binary", lambda name, extra_dirs=(): None)
    args = argparse.Namespace(no_sqlmap=False, no_dalfox=False,
                              no_wafw00f=True, no_httpx=True)
    urls = (["https://clean.example/"]
            + [f"https://clean.example/{i}" for i in range(1, 6)]
            + ["https://slow-a.example/", "https://slow-b.example/x",
               "https://odd.example/bad"])
    out = asyncio_run(athena.run_extended_tools(
        "https://clean.example/", args, urls))

    dalfox_rows = [s for s in out if s.get("tool") == "dalfox"]
    assert len(dalfox_rows) == 9
    lines = [line for line in capsys.readouterr().out.splitlines()
             if "Dalfox:" in line]
    assert len(lines) <= 4
    assert any("across 6 URL(s)" in line for line in lines)
