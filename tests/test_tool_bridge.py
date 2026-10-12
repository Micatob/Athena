"""Tests for the external tool bridge (nuclei adapter).

Everything runs against fakes: no binary is executed and no network is
touched.  The contract under test is the one the pipeline relies on - clean
degradation when the tool is absent, evidence-only findings when it is not.
"""

import json
import sys

import pytest

from modules import tool_bridge as tb


JSONL = '\n'.join([
    json.dumps({
        'template-id': 'cves/CVE-2021-44228',
        'info': {
            'name': 'Apache Log4j RCE',
            'severity': 'critical',
            'description': 'Remote code execution in log4j.',
            'reference': ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
        },
        'matched-at': 'https://target.example/login',
        'matcher-name': 'log4j-rce',
        'extracted-results': ['jndi:ldap://evil/a'],
        'type': 'http',
        'curl-command': 'curl -sk https://target.example/login',
    }),
    json.dumps({
        'template-id': 'misconfiguration/generic-exposed-panel',
        'info': {'name': 'Exposed Admin Panel', 'severity': 'medium'},
        'matched-at': 'https://target.example/admin/',
        'type': 'http',
    }),
])


def _fake_exec(stdout=JSONL, stderr='', ok=True, returncode=0):
    async def _run(argv, timeout):
        return {'ok': ok, 'stdout': stdout, 'stderr': stderr,
                'returncode': returncode, 'duration_s': 1.5}
    return _run


# -- availability / degradation ------------------------------------------------

def test_disabled_run_is_reported_not_silently_skipped():
    out = asyncio_run(tb.run_nuclei('https://t.example', enabled=False))
    assert out['status'] == 'disabled'
    assert out['findings'] == []


def test_missing_binary_is_a_structured_skip(monkeypatch):
    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): None)
    out = asyncio_run(tb.run_nuclei('https://t.example'))
    assert out['status'] == 'unavailable'
    assert out['matched'] == 0
    assert 'nuclei is not installed' in out['reason']
    assert out['findings'] == []


def test_empty_target_is_skipped(monkeypatch):
    monkeypatch.setattr(tb, 'find_binary',
                        lambda name, extra_dirs=(): '/usr/bin/nuclei')
    out = asyncio_run(tb.run_nuclei(''))
    assert out['status'] == 'skipped'


def test_find_binary_returns_none_when_absent(monkeypatch):
    monkeypatch.setattr(tb.shutil, 'which', lambda name: None)
    monkeypatch.setattr(tb.os.path, 'isfile', lambda p: False)
    assert tb.find_binary('definitely-not-a-real-tool') is None


# -- argv construction ---------------------------------------------------------

def test_executes_with_jsonl_and_severity_filter(monkeypatch):
    seen = {}

    async def _run(argv, timeout):
        seen['argv'] = list(argv)
        return {'ok': True, 'stdout': JSONL, 'stderr': '',
                'returncode': 0, 'duration_s': 2.0}

    monkeypatch.setattr(tb, 'find_binary',
                        lambda name, extra_dirs=(): '/opt/nuclei')
    monkeypatch.setattr(tb, '_run_process', _run)
    monkeypatch.setattr(tb, '_templates_present', lambda: True)
    out = asyncio_run(tb.run_nuclei('https://t.example',
                                    severity='critical,high'))
    assert out['status'] == 'executed'
    assert seen['argv'][0] == '/opt/nuclei'
    assert '-jsonl' in seen['argv']
    assert '-silent' in seen['argv']
    assert seen['argv'][seen['argv'].index('-severity') + 1] == 'critical,high'
    assert seen['argv'][seen['argv'].index('-u') + 1] == 'https://t.example'
    assert '-exclude-tags' in seen['argv']
    assert seen['argv'][seen['argv'].index('-exclude-tags') + 1] == tb.EXCLUDE_TAGS
    assert '-l' not in seen['argv']
    # argv is a list - the target can never be interpreted as shell syntax.
    assert isinstance(seen['argv'], list)
    assert out['matched'] == 2
    assert out['findings'][0]['severity'] == 'CRITICAL'


def test_older_binary_falls_back_to_json_file(monkeypatch):
    calls = []

    async def _run(argv, timeout):
        calls.append(list(argv))
        if '-jsonl' in argv:
            return {'ok': False, 'stdout': '', 'returncode': 2,
                    'stderr': 'Error: unknown flag: -jsonl', 'duration_s': 0.1}
        path = argv[argv.index('-o') + 1]
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump([json.loads(JSONL.splitlines()[0])], fh)
        return {'ok': True, 'stdout': '', 'stderr': '',
                'returncode': 0, 'duration_s': 0.5}

    monkeypatch.setattr(tb, 'find_binary',
                        lambda name, extra_dirs=(): '/opt/nuclei')
    monkeypatch.setattr(tb, '_run_process', _run)
    monkeypatch.setattr(tb, '_templates_present', lambda: True)
    out = asyncio_run(tb.run_nuclei('https://t.example'))
    assert len(calls) == 2
    assert '-jsonl' not in calls[1]
    assert out['status'] == 'executed'
    assert out['matched'] == 1
    assert out['findings'][0]['severity'] == 'CRITICAL'


def test_failure_returns_reason_without_findings(monkeypatch):
    async def _run(argv, timeout):
        return {'ok': False, 'stdout': '', 'returncode': 1,
                'stderr': 'template file missing\nsecond line',
                'duration_s': 0.2}

    monkeypatch.setattr(tb, 'find_binary',
                        lambda name, extra_dirs=(): '/opt/nuclei')
    monkeypatch.setattr(tb, '_run_process', _run)
    monkeypatch.setattr(tb, '_templates_present', lambda: True)
    out = asyncio_run(tb.run_nuclei('https://t.example'))
    assert out['status'] == 'failed'
    assert out['findings'] == []
    assert 'template file missing' in out['reason']


def test_timeout_is_reported(monkeypatch):
    async def _run(argv, timeout):
        return {'ok': False, 'stdout': '', 'stderr': 'timeout',
                'returncode': None, 'duration_s': timeout,
                'timeout': True}

    monkeypatch.setattr(tb, 'find_binary',
                        lambda name, extra_dirs=(): '/opt/nuclei')
    monkeypatch.setattr(tb, '_run_process', _run)
    monkeypatch.setattr(tb, '_templates_present', lambda: True)
    out = asyncio_run(tb.run_nuclei('https://t.example', timeout=1.0))
    assert out['status'] == 'failed'
    assert 'timed out' in out['reason']


# -- JSONL parsing -------------------------------------------------------------

def test_parser_extracts_evidence_backed_findings():
    findings = tb.parse_nuclei_jsonl(JSONL, 'https://t.example')
    assert len(findings) == 2
    first = findings[0]
    assert first['type'] == 'Apache Log4j RCE'
    assert first['url'] == 'https://target.example/login'
    assert first['severity'] == 'CRITICAL'
    assert first['source'] == 'nuclei'
    assert first['confidence'] == 'high'
    assert first['evidence']['template'] == 'cves/CVE-2021-44228'
    assert first['evidence']['matcher'] == 'log4j-rce'
    assert first['evidence']['extracted'] == ['jndi:ldap://evil/a']
    assert 'log4j-rce' in first['description']
    # severity mapping for every level nuclei can emit
    assert findings[1]['severity'] == 'MEDIUM'
    assert findings[1]['evidence']['matcher'] == ''


def test_parser_maps_every_severity():
    lines = [json.dumps({'template-id': f't{i}',
                         'info': {'name': f'N{i}', 'severity': sev},
                         'matched-at': 'https://t/x'})
             for i, sev in enumerate(['critical', 'high', 'medium', 'low',
                                      'info', 'madeup'])]
    got = [f['severity'] for f in tb.parse_nuclei_jsonl('\n'.join(lines), '')]
    assert got == ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'INFO']


def test_parser_skips_malformed_and_urlless_events():
    raw = '\n'.join([
        'not json',
        '{"broken": ',
        json.dumps({'info': {'name': 'No URL'}}),
        '',
        '[]',
        json.dumps({'info': {'name': 'Good', 'severity': 'high'},
                    'matched-at': 'https://t/ok'}),
    ])
    findings = tb.parse_nuclei_jsonl(raw, '')
    assert len(findings) == 1
    assert findings[0]['url'] == 'https://t/ok'


def test_parser_deduplicates_identical_matches():
    line = json.dumps({'template-id': 't', 'info': {'name': 'N'},
                       'matched-at': 'https://t/x', 'matcher-name': 'm'})
    findings = tb.parse_nuclei_jsonl('\n'.join([line] * 5), '')
    assert len(findings) == 1


def test_parser_caps_flood():
    lines = [json.dumps({'template-id': f't{i}',
                         'info': {'name': f'N{i}'},
                         'matched-at': f'https://t/{i}'})
             for i in range(tb.MAX_FINDINGS + 40)]
    assert len(tb.parse_nuclei_jsonl('\n'.join(lines), '')) == tb.MAX_FINDINGS


# -- console notice ------------------------------------------------------------

@pytest.mark.parametrize('summary,needle', [
    ({'status': 'executed', 'matched': 3, 'severity_filter': 'critical,high,medium',
      'duration_s': 12.0}, '3 template match(es)'),
    ({'status': 'disabled'}, '--no-nuclei'),
    ({'status': 'unavailable', 'reason': 'nuclei is not installed'},
     'Nuclei unavailable'),
    ({'status': 'failed', 'reason': 'exit 1'}, 'Nuclei failed'),
])
def test_notice_lines(summary, needle):
    assert needle in tb.nuclei_notice(summary)


def test_notice_of_none_is_empty():
    assert tb.nuclei_notice(None) == ''


# -- pipeline wiring -----------------------------------------------------------

def test_run_external_scan_degrades_cleanly(monkeypatch, capsys):
    import athena
    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): None)
    summary = asyncio_run(athena.run_external_scan('https://t.example'))
    assert summary['status'] == 'unavailable'
    out = capsys.readouterr().out
    assert 'Nuclei unavailable' in out


def test_run_external_scan_respects_no_nuclei_flag(monkeypatch, capsys):
    import argparse
    import athena
    args = argparse.Namespace(no_nuclei=True)
    summary = asyncio_run(athena.run_external_scan('https://t.example',
                                                   args=args))
    assert summary['status'] == 'disabled'


def test_run_external_scan_never_raises(monkeypatch, capsys):
    import athena

    async def _boom(*a, **k):
        raise RuntimeError('bridge exploded')

    monkeypatch.setattr(tb, 'find_binary',
                        lambda name, extra_dirs=(): '/opt/nuclei')
    monkeypatch.setattr(tb, '_templates_present', lambda: True)
    monkeypatch.setattr(tb, 'run_nuclei', _boom)
    assert asyncio_run(athena.run_external_scan('https://t.example')) is None
    assert 'Nuclei bridge error' in capsys.readouterr().out


def test_report_carries_external_tool_status(tmp_path):
    import athena
    summary = {'tool': 'nuclei', 'status': 'unavailable',
               'binary': 'nuclei', 'reason': 'nuclei is not installed',
               'findings': [], 'matched': 0, 'duration_s': 0.0, 'argv': []}
    path = athena.generate_report('https://t.example', {}, [],
                                  output_format='json',
                                  output_path=str(tmp_path / 'rep'),
                                  external_tools=[summary])
    import json as _json
    with open(f'{path}.json', encoding='utf-8') as fh:
        data = _json.load(fh)
    audit = data.get('athena_security_audit', data)
    tools = audit['external_tools']
    assert tools[0]['tool'] == 'nuclei'
    assert tools[0]['status'] == 'unavailable'


def test_html_renders_external_tool_section():
    import athena
    executed = {'tool': 'nuclei', 'status': 'executed',
                'binary': '/usr/bin/nuclei', 'reason': '', 'matched': 4,
                'severity_filter': 'critical,high,medium',
                'findings': [], 'duration_s': 31.0, 'argv': []}
    html_out = athena._generate_html_report({
        'athena_security_audit': {'external_tools': [executed]},
    })
    assert 'External Tool Runs' in html_out
    assert '4 template match(es)' in html_out
    assert '/usr/bin/nuclei' in html_out


def test_html_omits_tool_section_when_none_ran():
    import athena
    html_out = athena._generate_html_report({'athena_security_audit': {}})
    assert 'External Tool Runs' not in html_out


# -- real subprocess ------------------------------------------------------------

def test_run_process_reports_success_for_a_real_process(tmp_path):
    """Regression: ``ok`` must come from the actual return code.

    A live stand-in binary once reported 'failed: exit code 0' because the
    return code was read from an uninitialised local.
    """
    import asyncio
    script = tmp_path / 'ok.py'
    script.write_text('print("{\\"matched-at\\": \\"https://t/x\\"}")\n',
                      encoding='utf-8')
    result = asyncio.new_event_loop().run_until_complete(
        tb._run_process([sys.executable, str(script)], 30))
    assert result['returncode'] == 0
    assert result['ok'] is True
    assert 'https://t/x' in result['stdout']


def test_run_process_reports_failure_for_a_real_process(tmp_path):
    import asyncio
    script = tmp_path / 'bad.py'
    script.write_text('import sys; sys.stderr.write("boom\\n"); sys.exit(3)\n',
                      encoding='utf-8')
    result = asyncio.new_event_loop().run_until_complete(
        tb._run_process([sys.executable, str(script)], 30))
    assert result['returncode'] == 3
    assert result['ok'] is False
    assert 'boom' in result['stderr']


def test_run_process_times_out(tmp_path):
    import asyncio
    script = tmp_path / 'slow.py'
    script.write_text('import time; time.sleep(10)\n', encoding='utf-8')
    result = asyncio.new_event_loop().run_until_complete(
        tb._run_process([sys.executable, str(script)], 0.5))
    assert result['ok'] is False
    assert result.get('timeout') is True


def asyncio_run(coro):
    """Run a coroutine in a plain sync test."""
    import asyncio
    return asyncio.new_event_loop().run_until_complete(coro)

# -- tool status / --list-tools -----------------------------------------------

def test_tool_status_reports_installed_tool(monkeypatch):
    async def _run(argv, timeout):
        return {'ok': True, 'stdout': '', 'stderr': '[INF] Nuclei Engine Version: v3.11.1',
                'returncode': 0, 'duration_s': 0.1}

    monkeypatch.setattr(tb, 'find_binary',
                        lambda name, extra_dirs=(): '/opt/nuclei')
    monkeypatch.setattr(tb, '_run_process', _run)
    monkeypatch.setattr(tb, '_templates_present', lambda: True)
    status = asyncio_run(tb.tool_status('nuclei'))
    assert status['installed'] is True
    assert status['version'] == 'v3.11.1'
    assert status['templates'] == tb.NUCLEI_TEMPLATE_DIR


def test_tool_status_reports_absent_tool(monkeypatch):
    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): None)
    status = asyncio_run(tb.tool_status('nuclei'))
    assert status['installed'] is False
    assert status['binary'] is None
    assert status['version'] is None


def test_tool_status_never_raises(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError('nope')

    monkeypatch.setattr(tb, 'find_binary', _boom)
    status = asyncio_run(tb.tool_status('nuclei'))
    assert status['installed'] is False


def test_list_tools_flag_prints_status(capsys):
    import asyncio
    import athena
    asyncio.new_event_loop().run_until_complete(athena.show_tool_status())
    out = capsys.readouterr().out
    assert 'EXTERNAL TOOLS' in out
    assert 'nuclei' in out


def test_templates_present_accepts_directory_layout(tmp_path, monkeypatch):
    """Templates live one level down; a top level without .yaml must count."""
    (tmp_path / 'http').mkdir()
    (tmp_path / 'http' / 'misc.yaml').write_text('id: x\n', encoding='utf-8')
    monkeypatch.setattr(tb, 'NUCLEI_TEMPLATE_DIR', str(tmp_path))
    assert tb._templates_present() is True


def test_templates_present_false_when_dir_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(tb, 'NUCLEI_TEMPLATE_DIR', str(tmp_path / 'nope'))
    assert tb._templates_present() is False


# -- scanner disagreement / error accounting ---------------------------------

def test_error_events_are_not_turned_into_findings():
    raw = json.dumps({'template-id': 'conn-error', 'type': 'error',
                      'error': 'connection refused',
                      'matched-at': 'https://target.test/a'})
    assert tb.parse_nuclei_jsonl(raw, 'https://target.test') == []
    assert tb.count_nuclei_errors(raw) == 1


def test_count_nuclei_errors_counts_only_error_events():
    good = json.dumps({'template-id': 'cve-x', 'matcher-name': 'word',
                       'info': {'severity': 'low', 'name': 'X'},
                       'matched-at': 'https://target.test/b'})
    bad = json.dumps({'type': 'error', 'error': 'i/o timeout'})
    assert tb.count_nuclei_errors(good + chr(10) + bad) == 1
    assert tb.count_nuclei_errors(good) == 0


def test_notice_surfaces_error_count():
    line = tb.nuclei_notice({'status': 'executed', 'matched': 0, 'errors': 3,
                             'severity_filter': 'critical,high',
                             'duration_s': 12.0})
    assert '0 template match' in line
    assert '3 error(s)' in line


# -- tool disagreement must be visible, not averaged away --------------------

def test_disagreement_flagged_when_nuclei_matches_nothing():
    import athena
    summary = {'status': 'executed', 'matched': 0, 'errors': 0}
    native = [{'severity': 'CRITICAL'}, {'severity': 'HIGH'}, {'severity': 'LOW'}]

    athena._flag_tool_disagreement(summary, native)

    assert summary['native_critical_high'] == 2
    assert 'disagree' in summary['corroboration']
    assert 'unverified' in summary['corroboration']


def test_disagreement_is_inconclusive_when_nuclei_errored():
    import athena
    summary = {'status': 'executed', 'matched': 0, 'errors': 7}

    athena._flag_tool_disagreement(summary, [{'severity': 'CRITICAL'}])

    assert 'INCONCLUSIVE' in summary['corroboration']
    assert '7 error(s)' in summary['corroboration']


def test_no_disagreement_flagged_on_a_clean_miss_without_native_hits():
    import athena
    summary = {'status': 'executed', 'matched': 0, 'errors': 0}

    athena._flag_tool_disagreement(summary, [{'severity': 'LOW'}])

    assert 'corroboration' not in summary


def test_no_disagreement_flagged_when_nuclei_found_something():
    import athena
    summary = {'status': 'executed', 'matched': 4, 'errors': 0}

    athena._flag_tool_disagreement(summary, [{'severity': 'CRITICAL'}])

    assert 'corroboration' not in summary

# -- dalfox exit-2 (blocked / unreachable host) -------------------------------

_EMPTY_ENVELOPE = json.dumps({
    'findings': [],
    'meta': {'dalfox_version': '3.2.4', 'findings_count': 0},
})


def test_dalfox_exit2_with_empty_envelope_is_executed_unreachable(monkeypatch):
    async def _run(argv, timeout):
        return {'ok': False, 'stdout': _EMPTY_ENVELOPE, 'stderr': '',
                'returncode': 2, 'duration_s': 20.0}

    monkeypatch.setattr(tb, 'find_binary',
                        lambda name, extra_dirs=(): '/opt/dalfox')
    monkeypatch.setattr(tb, '_run_process', _run)
    out = asyncio_run(tb.run_dalfox('https://blocked.example/'))
    assert out['status'] == 'executed'
    assert out['matched'] == 0
    assert out['findings'] == []
    assert 'not a clean XSS miss' in out['reason']


def test_dalfox_exit2_without_envelope_stays_failed(monkeypatch):
    async def _run(argv, timeout):
        return {'ok': False, 'stdout': '', 'stderr': '',
                'returncode': 2, 'duration_s': 0.5}

    monkeypatch.setattr(tb, 'find_binary',
                        lambda name, extra_dirs=(): '/opt/dalfox')
    monkeypatch.setattr(tb, '_run_process', _run)
    out = asyncio_run(tb.run_dalfox('https://blocked.example/'))
    assert out['status'] == 'failed'
    assert 'exit code 2' in out['reason']


def test_dalfox_notice_unreachable_is_info_not_alarm():
    line = tb.dalfox_notice({'tool': 'dalfox', 'status': 'executed',
                             'matched': 0,
                             'reason': 'no scannable response (blocked, timeout, or refused) - not a clean XSS miss',
                             'target': 'https://blocked.example/',
                             'duration_s': 20.0})
    assert line.startswith('  [*]')
    assert 'not a clean XSS miss' in line


def test_quick_reachable_true_on_200():
    import athena
    from aioresponses import aioresponses
    with aioresponses() as mock_http:
        mock_http.get('https://up.example/', status=200, body='ok')
        assert asyncio_run(athena._quick_reachable('https://up.example/')) is True


def test_quick_reachable_false_on_connection_error():
    import athena
    from aioresponses import aioresponses
    with aioresponses():
        # Unregistered host -> aioresponses raises -> unreachable.
        assert asyncio_run(athena._quick_reachable('https://down.example/')) is False
