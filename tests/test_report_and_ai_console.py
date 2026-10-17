"""
tests/test_report_and_ai_console.py – console truthfulness + report records
===========================================================================
Follow-up fixes from the first live end-to-end run:

  * the CLI said "AI output is advisory; findings are not reclassified"
    while simultaneously removing 23 findings from the active set - the
    notices must state what actually happens (excluded from testing,
    retained in the report);
  * provider failures (Groq 404, Gemini outage) scrolled by as raw log
    lines - they are now counted and summarised as "AI degraded";
  * ``-o all`` claimed a PDF but silently skipped it when reportlab is
    missing - the skip must be visible;
  * ``findings_registry`` entries were a concatenated title with an empty
    id and a fabricated ``confidence: 0.0`` - they must be machine
    readable (type, url, id, verification state).
"""

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import athena
from modules.ai_integration import AIIntegration, AIProvider
from modules.reporting import ReportGenerator


@pytest.fixture(autouse=True)
def _pinned_ai_env(monkeypatch):
    """Deterministic AI environment for every test in this module.

    Failover partners come from ``configured_providers()`` (env-dependent)
    and rate-limit cooldowns are global state - both would make the failure
    counter assertions machine-dependent.  No failover, no cooldown here.
    """
    monkeypatch.setattr('modules.ai_integration.configured_providers',
                        lambda: [])
    monkeypatch.setattr('modules.ai_integration.provider_cooldown_remaining',
                        lambda provider: 0)


class TestConsoleTruthfulness:
    def test_filter_notice_says_excluded_not_deleted(self):
        line = athena.ai_filter_notice(30, 7, 23)
        assert '23 finding(s)' in line
        assert '(30 -> 7 kept)' in line
        assert 'excluded from active testing' in line
        assert 'retained in the report' in line

    def test_filter_notice_never_claims_reclassification(self):
        line = athena.ai_filter_notice(30, 7, 23)
        assert 'not reclassified' not in line

    def test_degraded_notice_counts_failures(self):
        line = athena.ai_degraded_notice(3)
        assert '3 provider call(s) failed' in line
        assert 'authoritative' in line

    def test_notices_are_single_console_lines(self):
        assert '\n' not in athena.ai_filter_notice(30, 7, 23)
        assert '\n' not in athena.ai_degraded_notice(1)

    def test_degraded_notice_breaks_down_providers(self):
        line = athena.ai_degraded_notice(7, {'groq': 4, 'gemini': 2,
                                             'openrouter': 1})
        assert '[!] AI degraded: 7 provider call(s) failed' in line
        assert 'groq: 4' in line and 'gemini: 2' in line
        assert 'openrouter: 1' in line
        assert '\n' not in line

    def test_degraded_notice_without_breakdown_is_legacy_string(self):
        assert athena.ai_degraded_notice(3) == (
            '  [!] AI degraded: 3 provider call(s) failed; '
            'deterministic validation remains authoritative')

    def test_print_ai_degraded_passes_breakdown(self, capsys):
        assert athena.print_ai_degraded(
            {'provider_call_failures': 2,
             'provider_failures_by': {'groq': 2}}) == 2
        out = capsys.readouterr().out
        assert 'groq: 2' in out

    def test_degraded_notice_printed_for_failed_analysis(self, capsys):
        assert athena.print_ai_degraded({'provider_call_failures': 2}) == 2
        out = capsys.readouterr().out
        assert '[!] AI degraded: 2 provider call(s) failed' in out

    def test_no_notice_without_failures(self, capsys):
        assert athena.print_ai_degraded({}) == 0
        assert athena.print_ai_degraded(None) == 0
        assert athena.print_ai_degraded({'provider_call_failures': 0}) == 0
        assert capsys.readouterr().out == ''

    @pytest.mark.asyncio
    async def test_run_ai_analysis_surfaces_failures_from_any_engine(
            self, monkeypatch):
        """The pass that fails may be a per-provider triage engine, not the
        main analysis engine - the notice must still fire."""
        from modules import ai_integration as ai_mod

        class _Stmt:
            def __init__(self, content):
                self.content = content
                self.metadata = {}
                self.confidence = 0.5

            def to_dict(self):
                return {'content': self.content, 'metadata': self.metadata,
                        'confidence': self.confidence}

        class _Bundle:
            def __init__(self, statements):
                self.statements = statements
                self.reasoning = 'no findings to reason about'
                self.confidence = 0.5

        class _FakeEngine:
            enabled = True
            provider = AIProvider.GROQ
            model = 'fake-model'
            call_failures = 0

            async def validate_findings(self, findings):
                # simulate one provider call dying with a 404 mid-pass
                ai_mod._CALL_FAILURES += 1
                return _Bundle([])

            async def correlate_findings(self, payload, extra):
                return _Bundle([_Stmt('correlation statement')])

            async def analyze_recon(self, discovery):
                return [_Stmt('recon statement')]

            async def suggest_next_steps(self, payload, context):
                return [_Stmt('next step statement')]

        monkeypatch.setattr(ai_mod, 'AIIntegration', _FakeEngine)

        analysis = await athena.run_ai_analysis('http://wiring.test', {}, [])
        assert analysis['provider_call_failures'] == 1


class TestTerminalHidesFalsePositives:
    """Operator rule: no FP rows in the terminal, from any source."""

    @pytest.mark.asyncio
    async def test_fp_findings_hidden_from_terminal_kept_in_report(
            self, monkeypatch, capsys):
        from modules import ai_integration as ai_mod

        class _Stmt:
            def __init__(self, content, metadata):
                self.content = content
                self.metadata = metadata
                self.confidence = 0.9

            def to_dict(self):
                return {'content': self.content, 'metadata': self.metadata,
                        'confidence': self.confidence}

        class _Bundle:
            def __init__(self, statements):
                self.statements = statements
                self.reasoning = 'validation pass'
                self.confidence = 0.9

        class _FakeEngine:
            enabled = True
            provider = AIProvider.GROQ
            model = 'fake-model'

            async def validate_findings(self, findings):
                return _Bundle([
                    _Stmt('Finding #0 is likely a false positive. not reflected',
                          {'verdict': 'likely_false_positive',
                           'finding_index': 0,
                           'reasoning': 'not reflected'}),
                    _Stmt('Finding #1 is likely a false positive. static page',
                          {'verdict': 'likely_false_positive',
                           'finding_index': 1,
                           'reasoning': 'static page'}),
                ])

            async def correlate_findings(self, payload, extra):
                return _Bundle([_Stmt('advisory correlation', {})])

            async def analyze_recon(self, discovery):
                return [_Stmt('advisory recon', {})]

            async def suggest_next_steps(self, payload, context):
                return [_Stmt('advisory next step', {})]

        monkeypatch.setattr(ai_mod, 'AIIntegration', _FakeEngine)

        vulns = [
            {'type': 'XSS', 'url': 'https://fp.test/1',
             'severity': 'HIGH', 'description': 'reflected?'},
            {'type': 'XSS', 'url': 'https://fp.test/2',
             'severity': 'HIGH', 'description': 'reflected?'},
        ]
        analysis = await athena.run_ai_analysis('http://fp.test', {}, vulns)
        out = capsys.readouterr().out

        assert '[AI-FP' not in out
        assert 'Potential false positive' not in out
        assert 'https://fp.test/1' not in out
        assert 'https://fp.test/2' not in out
        assert 'flagged 2 finding(s)' in out
        # The report keeps everything the terminal hides.
        assert len(analysis['filtered_indices']) == 2
        assert len(analysis['filtered_findings']) == 2
        assert analysis['filtered_findings'][0]['url'] == 'https://fp.test/1'


class TestProviderFailureCounter:
    @pytest.mark.asyncio
    async def test_failed_call_is_counted(self, monkeypatch):
        ai = AIIntegration(api_key='test-key', provider=AIProvider.GROQ)
        assert ai.call_failures == 0

        async def boom(*args, **kwargs):
            raise RuntimeError('404 Not Found')

        monkeypatch.setattr(ai, '_post_once', boom)
        assert await ai._call_llm('prompt') is None
        assert ai.call_failures == 1

    @pytest.mark.asyncio
    async def test_successful_call_does_not_count(self, monkeypatch):
        ai = AIIntegration(api_key='test-key', provider=AIProvider.GROQ)
        monkeypatch.setattr('modules.ai_integration.provider_cooldown_remaining',
                            lambda provider: 0)

        async def ok(*args, **kwargs):
            return 'model reply'

        monkeypatch.setattr(ai, '_post_once', ok)
        assert await ai._call_llm('prompt') == 'model reply'
        assert ai.call_failures == 0

    @pytest.mark.asyncio
    async def test_failures_accumulate_across_calls(self, monkeypatch):
        ai = AIIntegration(api_key='test-key', provider=AIProvider.GROQ)
        monkeypatch.setattr('modules.ai_integration.provider_cooldown_remaining',
                            lambda provider: 0)

        async def boom(*args, **kwargs):
            raise RuntimeError('404 Not Found')

        monkeypatch.setattr(ai, '_post_once', boom)
        await ai._call_llm('one')
        await ai._call_llm('two')
        assert ai.call_failures == 2

    @pytest.mark.asyncio
    async def test_failures_from_other_engines_are_counted(self, monkeypatch):
        """ensemble_triage builds one engine per provider - the CLI notice
        must see their failures too, not just the main analysis engine's."""
        from modules import ai_integration as ai_mod

        before = ai_mod.provider_call_failures()

        async def boom(*args, **kwargs):
            raise RuntimeError('404 Not Found')

        main_engine = AIIntegration(api_key='k', provider=AIProvider.GROQ)
        triage_engine = AIIntegration(api_key='k', provider=AIProvider.GEMINI)
        monkeypatch.setattr(main_engine, '_post_once', boom)
        monkeypatch.setattr(triage_engine, '_post_once', boom)

        await main_engine._call_llm('one')
        await triage_engine._call_llm('two')

        assert main_engine.call_failures == 1
        assert triage_engine.call_failures == 1
        assert ai_mod.provider_call_failures() - before == 2


class TestModelScoping:
    """ATHENA_AI_MODEL is provider-specific; sending a Groq model id to the
    Gemini endpoint 404s and used to disable every failover attempt."""

    def test_global_model_only_applies_to_primary(self, monkeypatch):
        monkeypatch.setenv('ATHENA_AI_PROVIDER', 'groq')
        monkeypatch.setenv('ATHENA_AI_MODEL', 'groq-model')
        primary = AIIntegration(api_key='k', provider=AIProvider.GROQ)
        other = AIIntegration(api_key='k', provider=AIProvider.GEMINI)
        assert primary.model == 'groq-model'
        assert other.model == 'gemini-flash-latest'

    def test_per_provider_override_wins(self, monkeypatch):
        monkeypatch.setenv('ATHENA_AI_PROVIDER', 'groq')
        monkeypatch.setenv('ATHENA_AI_MODEL', 'groq-model')
        monkeypatch.setenv('ATHENA_AI_MODEL_GEMINI', 'gemini-own')
        assert AIIntegration(api_key='k',
                             provider=AIProvider.GEMINI).model == 'gemini-own'

    def test_fallback_hop_gets_its_own_model(self, monkeypatch):
        monkeypatch.setenv('ATHENA_AI_PROVIDER', 'groq')
        monkeypatch.setenv('ATHENA_AI_MODEL', 'groq-model')
        engine = AIIntegration(api_key='k')
        assert engine.provider == AIProvider.GROQ
        assert engine._model_for(AIProvider.GROQ) == 'groq-model'
        assert engine._model_for(AIProvider.GEMINI) == 'gemini-flash-latest'

    def test_groq_default_is_a_live_model_id(self):
        from modules.ai_integration import AI_PROVIDERS
        # llama-3.3-70b-versatile / llama-3.1-8b-instant now 404 on Groq.
        assert AI_PROVIDERS[AIProvider.GROQ]['model'] == 'openai/gpt-oss-120b'


class TestReportRegistry:
    def _registry(self, findings):
        report = ReportGenerator().generate_comprehensive_report({
            'target': 'http://registry.test.local',
            'vulnerabilities': findings,
            'discovery': {},
        })
        return report['athena_security_audit']['findings_registry']

    def test_entries_are_machine_readable(self):
        registry = self._registry([
            {'type': 'SQL Injection', 'url': 'http://registry.test.local/?id=1',
             'severity': 'HIGH',
             'evidence': {'method': 'time_based', 'baseline_s': 1.0}},
        ])
        assert len(registry) == 1
        entry = registry[0]
        assert entry['id'], 'id must not be empty'
        assert entry['type'] == 'SQL Injection'
        assert entry['url'].startswith('http')
        assert entry['title'].startswith('SQL Injection at http')
        assert entry['severity'] == 'HIGH'

    def test_verification_state_is_exposed(self):
        registry = self._registry([
            {'type': 'Cross-Site Scripting (XSS)',
             'url': 'http://registry.test.local/search', 'severity': 'MEDIUM',
             'verified': True,
             'verification': {'status': 'confirmed'},
             'evidence': {'payload': '<script>'}},
        ])
        entry = registry[0]
        assert entry['verified'] is True
        assert entry['verification'] == 'confirmed'
        assert entry['has_evidence'] is True

    def test_missing_confidence_is_not_fabricated(self):
        registry = self._registry([
            {'type': 'Missing Security Headers',
             'url': 'http://registry.test.local/', 'severity': 'MEDIUM'},
        ])
        entry = registry[0]
        assert entry['confidence'] is None
        assert entry['verified'] is False
        assert entry['has_evidence'] is False

    def test_ids_are_unique(self):
        registry = self._registry([
            {'type': 'Missing Security Headers', 'url': 'http://a.test/one',
             'severity': 'MEDIUM'},
            {'type': 'Missing Security Headers', 'url': 'http://a.test/two',
             'severity': 'MEDIUM'},
        ])
        assert len({e['id'] for e in registry}) == len(registry)


class TestPdfSkipIsVisible:
    def test_skipped_pdf_is_printed(self, capsys, monkeypatch, tmp_path):
        monkeypatch.setattr(ReportGenerator, 'generate_pdf_report',
                            lambda self, results, filename: False)

        athena.generate_report('http://pdf.test.local', {}, [],
                               output_format='pdf',
                               output_path=str(tmp_path / 'r'))

        out = capsys.readouterr().out
        assert 'PDF report skipped' in out
        assert 'reportlab' in out
        assert '[+] PDF report:' not in out

    def test_generated_pdf_is_announced(self, capsys, monkeypatch, tmp_path):
        monkeypatch.setattr(ReportGenerator, 'generate_pdf_report',
                            lambda self, results, filename: True)

        athena.generate_report('http://pdf.test.local', {}, [],
                               output_format='pdf',
                               output_path=str(tmp_path / 'r'))

        assert '[+] PDF report:' in capsys.readouterr().out
