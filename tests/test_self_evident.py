"""Self-evident disclosure verification + universal repro payloads.

Fast, no network: the disclosure pass-through must never send a probe.
"""
import asyncio
import sys
from pathlib import Path

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from test_exploitation_runner import IN_SCOPE, authorized_engagement, runner
from modules.reporting import ReportGenerator


def asyncio_run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def phpinfo_finding():
    url = f'{IN_SCOPE}/phpinfo.php'
    return {'type': 'Exposed phpinfo()', 'severity': 'CRITICAL',
            'url': url,
            'description': 'phpinfo() page exposed (v8.1.34)',
            'payload': f'curl -sk "{url}" | grep -i -m3 "php version"',
            'evidence': {'markers': ['PHP Version', 'phpinfo()'],
                         'marker_count': 2, 'php_version': '8.1.34'}}


def test_disclosure_confirmed_without_network():
    r = runner()
    called = []

    async def _boom(finding):
        called.append(finding)
        raise AssertionError('no probe must be sent for self-evident findings')

    r.module.exploit_vulnerability = _boom
    f = phpinfo_finding()
    out = asyncio_run(r.execute(f['url'], [f]))
    assert out['status'] == 'executed'
    assert out['confirmed'] == 1
    assert f.get('verified') is True
    assert f['verification']['status'] == 'confirmed'
    assert f['verification']['proof_kind'] == 'response_signature'
    assert called == []


def test_disclosure_without_evidence_stays_inconclusive():
    r = runner()
    f = {'type': 'Exposed phpinfo()', 'severity': 'CRITICAL',
         'url': f'{IN_SCOPE}/phpinfo.php', 'description': 'bare claim'}
    out = asyncio_run(r.execute(f['url'], [f]))
    assert out['inconclusive'] == 1
    assert not f.get('verified')


def test_disclosure_selected_as_candidate():
    r = runner()
    picked = r.select_candidates([phpinfo_finding()])
    assert len(picked) == 1


def test_report_disclosure_has_repro_techniques():
    gen = ReportGenerator()
    techs = gen._generate_url_specific_techniques(
        ['base step'], 'https://t.example/phpinfo.php', '', 'Exposed phpinfo()')
    blob = '\n'.join(techs)
    assert 'Reproduce' in blob and 'curl' in blob


def test_report_row_backfills_repro_payload():
    gen = ReportGenerator()
    details = gen._generate_vulnerability_details(
        [{'type': 'Exposed phpinfo()', 'severity': 'CRITICAL',
          'url': 'https://t.example/phpinfo.php', 'description': 'x'}])
    row = details['Exposed phpinfo()']['confirmed_findings'][0]
    assert row['payload'].startswith('curl')
    assert 'https://t.example/phpinfo.php' in row['payload']
