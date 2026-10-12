"""A None anywhere in the findings pipeline must never crash a scan.

Regression tests for the `[!] Fatal error: 'NoneType' object has no
attribute 'get'` that killed a live run in `generate_report`'s
`_dedup_vulnerabilities` sort.  Every aggregation boundary now drops
non-dict entries with a debug log instead of raising.
"""
import asyncio
from types import SimpleNamespace

from modules.reporting import ReportGenerator
from modules.exploitation_runner import ExploitationRunner


def _vulns_with_none():
    return [
        {'id': 'a1', 'type': 'SQL Injection',
         'url': 'https://x.test/?id=1', 'severity': 'HIGH',
         'description': 'd1'},
        None,
        {'id': 'a2', 'type': 'Open Redirect',
         'url': 'https://x.test/go?u=1', 'severity': 'MEDIUM',
         'description': 'd2'},
    ]


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_dedup_drops_none():
    gen = ReportGenerator()
    out = gen._dedup_vulnerabilities(_vulns_with_none())
    assert len(out) == 2
    assert all(isinstance(v, dict) for v in out)


def test_recommendations_skip_none():
    gen = ReportGenerator()
    recs = gen.generate_recommendations(_vulns_with_none())
    assert isinstance(recs, list) and recs


def test_details_skip_none():
    gen = ReportGenerator()
    details = gen._generate_vulnerability_details(_vulns_with_none())
    assert 'SQL Injection' in details
    assert 'Open Redirect' in details


def test_comprehensive_report_with_none():
    gen = ReportGenerator()
    report = gen.generate_comprehensive_report({
        'target': 'https://x.test',
        'vulnerabilities': _vulns_with_none(),
        'discovery': {'urls': ['https://x.test/']},
        'exploitation': [],
    })
    audit = report.get('athena_security_audit', report)
    assert audit['audit_summary']['total_vulnerabilities'] == 2


def test_csv_export_skips_none(tmp_path):
    gen = ReportGenerator()
    dest = str(tmp_path / 'out.csv')
    gen.export_to_csv({'vulnerabilities': _vulns_with_none()}, dest)
    body = open(dest, encoding='utf-8').read()
    assert 'SQL Injection' in body
    assert 'Open Redirect' in body


class _AllowEngagement:
    def can_use(self, technique, target):
        return SimpleNamespace(allowed=True, reason='test')


class _TimeoutModule:
    async def exploit_vulnerability(self, finding):
        raise asyncio.TimeoutError()

    async def close(self):
        pass


def test_runner_with_none_findings_and_timeouts():
    runner = ExploitationRunner(engagement=_AllowEngagement(), ai=None,
                                request_timeout=5)
    runner.module = _TimeoutModule()
    vulns = [None,
             {'type': 'Server-Side Template Injection (Freemarker)',
              'url': 'https://x.test/e?a=1', 'severity': 'HIGH'},
             {'type': 'LDAP Injection',
              'url': 'https://x.test/?id=1', 'severity': 'MEDIUM'}]
    summary = _run(runner.execute('https://x.test', vulns))
    assert summary['status'] == 'executed'
    assert summary['attempted'] == 2
    assert all(isinstance(a, dict) for a in summary['attempts'])
    assert all('timed out' in a.get('detail', '') for a in summary['attempts'])


def test_auto_exploitation_skips_unreachable_host(monkeypatch, capsys):
    import athena

    async def _unreachable(url, timeout=10.0):
        return False

    monkeypatch.setattr(athena, '_quick_reachable', _unreachable)
    args = SimpleNamespace(exploit_max=5, exploit_delay=0,
                           exploit_aggressive=False, exploit_concurrency=1,
                           mode='full')
    summary = _run(athena.run_auto_exploitation(
        'https://down.example',
        [{'type': 'XSS', 'url': 'https://down.example/?q=1',
          'severity': 'MEDIUM'}],
        args))
    assert summary['status'] == 'denied'
    assert 'unreachable' in summary['scope_reason']
    assert 'skipped' in capsys.readouterr().out


def test_attempts_loop_survives_none_attempt(monkeypatch, capsys):
    import athena
    import modules.exploitation_runner as runner_mod

    async def _reachable(url, timeout=10.0):
        return True

    class _StubRunner:
        def __init__(self, **kwargs):
            pass

        async def execute(self, target, vulns):
            return {'status': 'executed', 'scope_reason': 't', 'mode': 'safe',
                    'attempted': 2, 'confirmed': 0, 'possible': 0,
                    'inconclusive': 2,
                    'attempts': [
                        {'type': 'LDAP Injection',
                         'url': 'https://down.example/?id=1',
                         'status': 'inconclusive',
                         'detail': 'timed out after 40s',
                         'error': 'timed out after 40s'},
                        None,
                    ],
                    'duration_ms': 1, 'detected': 2, 'candidates': 2,
                    'max_findings': 5, 'coverage_pct': 100.0, 'capped': False}

        async def close(self):
            pass

    monkeypatch.setattr(athena, '_quick_reachable', _reachable)
    monkeypatch.setattr(runner_mod, 'ExploitationRunner', _StubRunner)
    monkeypatch.setattr(athena, '_resolve_exploitation_engagement',
                        lambda t, a: _AllowEngagement())
    args = SimpleNamespace(exploit_max=5, exploit_delay=0,
                           exploit_aggressive=False, exploit_concurrency=1,
                           mode='full')
    summary = _run(athena.run_auto_exploitation(
        'https://down.example',
        [{'type': 'LDAP Injection', 'url': 'https://down.example/?id=1',
          'severity': 'MEDIUM'}],
        args))
    out = capsys.readouterr().out
    assert summary['status'] == 'executed'
    assert 'timed out after 40s' in out


def test_ogitech_report_crash_repro():
    """2026-10-12 ogitech.edu.ng: Fatal error after exploitation loop.

    Mixed None entries across discovery/techs/exploitation/external-tools
    must never kill generate_comprehensive_report or the HTML renderer.
    """
    import athena
    gen = ReportGenerator()
    data = {
        'target': 'https://ogitech.edu.ng',
        'vulnerabilities': [
            None,
            {'id': 'a1', 'type': 'SQL Injection',
             'url': 'https://ogitech.edu.ng/?id=1', 'severity': 'HIGH',
             'description': 'd1'},
        ],
        'discovery': {
            'urls': ['https://ogitech.edu.ng/'],
            'technologies': ['Apache', None, 'cPanel'],
            'technologies_with_confidence': [
                None,
                {'technology': 'jQuery', 'version': '3.7.1', 'confidence': 3},
            ],
            'ports': [80, 443],
        },
        'exploitation': [
            None,
            {'type': 'XSS', 'url': 'https://ogitech.edu.ng/?q=1',
             'status': 'inconclusive'},
        ],
        'bruteforce': {'web_logins': [None], 'admin_panels': [None]},
        'enumeration': {'smtp_25': None},
        'cve_mapping': [None],
        'external_tools': [
            None,
            {'tool': 'dalfox', 'status': 'executed', 'matched': 0,
             'target': 'https://ogitech.edu.ng', 'duration_s': 4},
        ],
        'ai_analysis': {'statements': [], 'filtered_findings': [None],
                        'consolidation': None},
    }
    report = gen.generate_comprehensive_report(data)
    assert report['athena_security_audit']['audit_summary']['total_vulnerabilities'] == 1
    html_out = athena._generate_html_report(report)
    assert 'ogitech' in html_out.lower() or 'SQL Injection' in html_out
