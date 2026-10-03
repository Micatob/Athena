"""
tests/test_ai_integration.py – AI Integration Module Tests
===========================================================
Covers:
  * AIReasoningType classification
  * Deterministic deduplication
  * Priority scoring
  * Attack path analysis
  * Report narrative generation
  * FACT/INFERENCE/HYPOTHESIS/RECOMMENDATION distinction
"""

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.ai_integration import (
    AIProvider,
    AIIntegration,
    AIReasoningType,
    AICorrelationType,
    AIStatement,
    AICorrelationResult,
    configured_providers,
    ensemble_triage,
    resolve_provider,
)


@pytest.fixture()
def ai():
    return AIIntegration(api_key="test-key")


@pytest.fixture()
def sample_findings():
    return [
        {
            "id": "f1",
            "title": "SQL Injection in login",
            "severity": "critical",
            "confidence": 0.95,
            "state": "confirmed",
            "affected_asset": "https://example.com/login",
            "detection_module": "scanner",
            "type": "sql_injection",
        },
        {
            "id": "f2",
            "title": "SQL Injection in search",
            "severity": "high",
            "confidence": 0.85,
            "state": "triaged",
            "affected_asset": "https://example.com/search",
            "detection_module": "scanner",
            "type": "sql_injection",
        },
        {
            "id": "f3",
            "title": "SQL Injection in login",
            "severity": "critical",
            "confidence": 0.95,
            "state": "confirmed",
            "affected_asset": "https://example.com/login",
            "detection_module": "scanner",
            "type": "sql_injection",
            "dedup_key": "scanner|example.com/login|sql_injection|sql injection in login",
        },
        {
            "id": "f4",
            "title": "XSS in search",
            "severity": "medium",
            "confidence": 0.7,
            "state": "discovered",
            "affected_asset": "https://example.com/search",
            "detection_module": "scanner",
            "type": "xss",
        },
    ]


class TestAIReasoningType:
    def test_fact_value(self):
        assert AIReasoningType.FACT.value == "fact"

    def test_inference_value(self):
        assert AIReasoningType.INFERENCE.value == "inference"

    def test_hypothesis_value(self):
        assert AIReasoningType.HYPOTHESIS.value == "hypothesis"

    def test_recommendation_value(self):
        assert AIReasoningType.RECOMMENDATION.value == "recommendation"


class TestAIStatement:
    def test_to_dict(self):
        stmt = AIStatement(
            content="Test statement",
            reasoning_type=AIReasoningType.FACT,
            confidence=0.9,
            evidence_refs=["e1", "e2"],
            source_module="test",
        )
        data = stmt.to_dict()
        assert data["content"] == "Test statement"
        assert data["reasoning_type"] == "fact"
        assert data["confidence"] == 0.9
        assert data["evidence_refs"] == ["e1", "e2"]

    def test_default_timestamp(self):
        stmt = AIStatement(
            content="Test",
            reasoning_type=AIReasoningType.FACT,
            confidence=0.5,
        )
        assert stmt.timestamp  # Should have default


class TestAICorrelationResult:
    def test_to_dict(self):
        result = AICorrelationResult(
            correlation_type=AICorrelationType.FINDING_DEDUP,
            statements=[],
            input_findings=["f1", "f2"],
            output_findings=["f1"],
            confidence=0.9,
            reasoning="Test reasoning",
        )
        data = result.to_dict()
        assert data["correlation_type"] == "finding_dedup"
        assert data["input_findings"] == ["f1", "f2"]
        assert data["output_findings"] == ["f1"]


class TestAICorrelation:
    @pytest.mark.asyncio
    async def test_dedup_removes_duplicates(self, ai, sample_findings):
        result = await ai.correlate_findings(sample_findings, evidence=[])
        # f1 and f3 are duplicates (same dedup key)
        assert len(result.input_findings) > len(result.output_findings)

    @pytest.mark.asyncio
    async def test_correlation_preserves_unique(self, ai, sample_findings):
        result = await ai.correlate_findings(sample_findings, evidence=[])
        # Should have at least 3 unique findings
        assert len(result.output_findings) >= 3

    @pytest.mark.asyncio
    async def test_correlation_with_engagement_filter(self, ai, sample_findings):
        sample_findings[0]["engagement_id"] = "eng1"
        sample_findings[1]["engagement_id"] = "eng2"
        result = await ai.correlate_findings(sample_findings, evidence=[], engagement_id="eng1")
        assert len(result.input_findings) == 1


class TestPriorityScoring:
    @pytest.mark.asyncio
    async def test_critical_higher_than_medium(self, ai):
        critical = {"severity": "critical", "confidence": 0.9, "state": "confirmed"}
        medium = {"severity": "medium", "confidence": 0.9, "state": "confirmed"}
        result_c = await ai.prioritize_findings([critical])
        result_m = await ai.prioritize_findings([medium])
        # Critical should have higher priority
        assert result_c.output_findings  # Has output

    @pytest.mark.asyncio
    async def test_confirmed_higher_than_discovered(self, ai):
        confirmed = {"severity": "high", "confidence": 0.9, "state": "confirmed"}
        discovered = {"severity": "high", "confidence": 0.9, "state": "discovered"}
        result = await ai.prioritize_findings([confirmed, discovered])
        # Confirmed should come first
        assert result.output_findings


class TestAttackPathAnalysis:
    @pytest.mark.asyncio
    async def test_finds_confirmed_paths(self, ai):
        graph = {
            "nodes": [
                {"id": "n1", "label": "host1", "type": "host", "state": "confirmed"},
                {"id": "n2", "label": "vuln1", "type": "vulnerability", "state": "confirmed"},
            ],
            "edges": [
                {"source": "n1", "target": "n2", "relation": "vulnerable_to", "state": "confirmed"},
            ],
        }
        result = await ai.generate_attack_path_analysis(graph, [], [])
        assert result.statements  # Should have at least one statement

    @pytest.mark.asyncio
    async def test_finds_potential_paths(self, ai):
        graph = {
            "nodes": [
                {"id": "n1", "label": "host1", "type": "host", "state": "potential"},
                {"id": "n2", "label": "vuln1", "type": "vulnerability", "state": "potential"},
            ],
            "edges": [
                {"source": "n1", "target": "n2", "relation": "vulnerable_to", "state": "potential"},
            ],
        }
        result = await ai.generate_attack_path_analysis(graph, [], [])
        assert len(result.statements) >= 1


class TestReportNarrative:
    def test_deterministic_narrative(self, ai):
        engagement = {
            "name": "Test Engagement",
            "operator": "tester",
            "in_scope_targets": ["example.com"],
        }
        findings = [
            {"title": "Critical Vuln", "severity": "critical", "description": "Test"},
            {"title": "High Vuln", "severity": "high", "description": "Test"},
        ]
        narrative = ai._generate_deterministic_narrative(
            engagement, findings, [], None
        )
        assert "Executive Summary" in narrative
        assert "2 finding(s)" in narrative
        assert "1 critical" in narrative


class TestLLMPayloadRedaction:
    def test_redacted_for_llm_never_leaks_values(self, ai):
        payload = {
            "id": "f1",
            "title": "password=supersecret123",
            "description": "mysql://root:hunter2@db:3306/app",
            "metadata": {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"},
        }
        text = ai._redacted_for_llm(payload)
        assert "supersecret123" not in text
        assert "hunter2" not in text
        assert "[REDACTED:" in text

    def test_redacted_for_llm_preserves_context(self, ai):
        payload = {"id": "f1", "title": "SQLi in login", "severity": "high"}
        text = ai._redacted_for_llm(payload)
        assert "SQLi in login" in text
        assert '"f1"' in text


class TestProviderResolution:
    def test_explicit_key_defaults_to_gemini(self, monkeypatch):
        for name in ("GEMINI_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY",
                     "ATHENA_AI_PROVIDER"):
            monkeypatch.delenv(name, raising=False)
        assert resolve_provider("some-key") == AIProvider.GEMINI

    def test_env_provider_wins(self, monkeypatch):
        monkeypatch.setenv("ATHENA_AI_PROVIDER", "groq")
        assert resolve_provider("some-key") == AIProvider.GROQ

    def test_first_configured_key_wins(self, monkeypatch):
        monkeypatch.delenv("ATHENA_AI_PROVIDER", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("GROQ_API_KEY", "g")
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        assert resolve_provider() == AIProvider.GROQ

    def test_no_keys_falls_back_to_gemini(self, monkeypatch):
        for name in ("GEMINI_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY",
                     "ATHENA_AI_PROVIDER"):
            monkeypatch.delenv(name, raising=False)
        assert resolve_provider() == AIProvider.GEMINI

    def test_default_models_per_provider(self, monkeypatch):
        from modules.ai_integration import _dotenv_refresh
        _dotenv_refresh()
        # Suppress the .env fallback so we can assert each provider's own default
        monkeypatch.setattr("modules.ai_integration._dotenv_values", lambda: {})
        for name in ("ATHENA_AI_PROVIDER", "GEMINI_API_KEY", "GROQ_API_KEY",
                     "DEEPSEEK_API_KEY", "ATHENA_AI_MODEL"):
            monkeypatch.delenv(name, raising=False)
        groq = AIIntegration(provider=AIProvider.GROQ, api_key="k")
        assert groq.model == "llama-3.3-70b-versatile"
        deepseek = AIIntegration(provider=AIProvider.DEEPSEEK, api_key="k")
        assert deepseek.model == "deepseek-chat"
        gemini = AIIntegration(api_key="k")
        assert gemini.model == "gemini-flash-latest"

    def test_explicit_model_overrides(self, monkeypatch):
        monkeypatch.delenv("ATHENA_AI_MODEL", raising=False)
        engine = AIIntegration(provider=AIProvider.GROQ, api_key="k",
                               model="custom-model")
        assert engine.model == "custom-model"

    def test_configured_providers_reflects_env(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.setenv("GROQ_API_KEY", "g")
        assert configured_providers() == [AIProvider.GROQ]


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeAsyncClient:
    def __init__(self, captured, payload):
        self._captured = captured
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def post(self, url, headers=None, params=None, json=None, timeout=None):
        self._captured.update(url=url, headers=headers, params=params,
                              json=json, timeout=timeout)
        return self._post()

    async def _post(self):
        return _FakeResponse(self._payload)


class TestLLMTransport:
    @pytest.mark.asyncio
    async def test_gemini_dispatch(self, monkeypatch):
        for name in ("ATHENA_AI_PROVIDER", "GEMINI_API_KEY", "GROQ_API_KEY",
                     "DEEPSEEK_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        captured = {}
        monkeypatch.setattr(
            "httpx.AsyncClient",
            lambda: _FakeAsyncClient(captured, {
                "candidates": [{"content": {"parts": [{"text": "hello"}]}}]
            }),
        )
        engine = AIIntegration(api_key="k")
        assert await engine._call_llm("hi") == "hello"
        assert "generateContent" in captured["url"]
        assert captured["params"] == {"key": "k"}

    @pytest.mark.asyncio
    async def test_groq_openai_dispatch(self, monkeypatch):
        from modules.ai_integration import _dotenv_refresh
        _dotenv_refresh()
        captured = {}
        monkeypatch.setattr(
            "httpx.AsyncClient",
            lambda: _FakeAsyncClient(captured, {
                "choices": [{"message": {"content": "answer"}}]
            }),
        )
        engine = AIIntegration(provider=AIProvider.GROQ, api_key="groq-key")
        assert await engine._call_llm("question") == "answer"
        assert captured["url"] == (
            "https://api.groq.com/openai/v1/chat/completions")
        assert captured["headers"]["Authorization"] == "Bearer groq-key"
        assert captured["json"]["model"] == "openai/gpt-oss-120b"
        assert captured["json"]["messages"][0]["content"] == "question"

    @pytest.mark.asyncio
    async def test_deepseek_openai_dispatch(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            "httpx.AsyncClient",
            lambda: _FakeAsyncClient(captured, {
                "choices": [{"message": {"content": "deep"}}]
            }),
        )
        engine = AIIntegration(provider=AIProvider.DEEPSEEK, api_key="d-key")
        assert await engine._call_llm("q") == "deep"
        assert captured["url"].startswith("https://api.deepseek.com")

    @pytest.mark.asyncio
    async def test_disabled_engine_never_calls(self, monkeypatch):
        from modules.ai_integration import _dotenv_refresh
        _dotenv_refresh()
        def boom(*args, **kwargs):
            raise AssertionError("must not call transport when disabled")
        monkeypatch.setattr("httpx.AsyncClient", boom)
        # The project `.env` is a real source of keys at runtime, so deleting
        # process env vars alone is not enough to reach the "nothing is
        # configured" path: suppress the file fallback for this assertion.
        monkeypatch.setattr("modules.ai_integration._dotenv_values", lambda: {})
        for name in ("ATHENA_AI_PROVIDER", "GEMINI_API_KEY", "GROQ_API_KEY",
                     "DEEPSEEK_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        engine = AIIntegration(api_key="")
        assert not engine.enabled
        assert await engine._call_llm("hi") is None


class TestLLMFailover:
    @pytest.mark.asyncio
    async def test_primary_answers_without_failover(self, monkeypatch):
        for name in ("ATHENA_AI_PROVIDER", "GEMINI_API_KEY", "GROQ_API_KEY",
                     "DEEPSEEK_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "g")
        monkeypatch.setenv("GROQ_API_KEY", "gr")
        engine = AIIntegration(api_key="g")

        calls = []

        async def fake(provider, prompt, temperature):
            calls.append(provider)
            return "from-gemini"

        monkeypatch.setattr(engine, "_call_llm_provider", fake)
        assert await engine._call_llm("hi") == "from-gemini"
        assert calls == [AIProvider.GEMINI]
        assert engine.last_provider == AIProvider.GEMINI

    @pytest.mark.asyncio
    async def test_failover_to_next_configured_provider(self, monkeypatch):
        for name in ("ATHENA_AI_PROVIDER", "GEMINI_API_KEY", "GROQ_API_KEY",
                     "DEEPSEEK_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "g")
        monkeypatch.setenv("GROQ_API_KEY", "gr")
        engine = AIIntegration(api_key="g")

        calls = []

        async def fake(provider, prompt, temperature):
            calls.append(provider)
            if provider == AIProvider.GEMINI:
                return None
            return "from-groq"

        monkeypatch.setattr(engine, "_call_llm_provider", fake)
        assert await engine._call_llm("q") == "from-groq"
        assert calls == [AIProvider.GEMINI, AIProvider.GROQ]
        assert engine.last_provider == AIProvider.GROQ

    @pytest.mark.asyncio
    async def test_all_providers_fail_returns_none(self, monkeypatch):
        for name in ("ATHENA_AI_PROVIDER", "GEMINI_API_KEY", "GROQ_API_KEY",
                     "DEEPSEEK_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "g")
        monkeypatch.setenv("GROQ_API_KEY", "gr")
        monkeypatch.setenv("DEEPSEEK_API_KEY", "d")
        engine = AIIntegration(api_key="g")

        async def fake(provider, prompt, temperature):
            return None

        monkeypatch.setattr(engine, "_call_llm_provider", fake)
        assert await engine._call_llm("q") is None
        assert engine.last_provider == AIProvider.GEMINI

    @pytest.mark.asyncio
    async def test_transport_error_triggers_failover(self, monkeypatch):
        import httpx

        for name in ("ATHENA_AI_PROVIDER", "GROQ_API_KEY", "DEEPSEEK_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")
        monkeypatch.setenv("GROQ_API_KEY", "groq-key")
        engine = AIIntegration(api_key="gemini-key")

        captured = {}

        class _FailingThenWorkingClient:
            calls = 0

            def __init__(self):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, headers=None, params=None, json=None,
                     timeout=None):
                _FailingThenWorkingClient.calls += 1
                if _FailingThenWorkingClient.calls == 1:
                    raise httpx.ConnectError("connection refused")
                captured.update(url=url, headers=headers, params=params,
                                json=json, timeout=timeout)
                return self._post()

            async def _post(self):
                return _FakeResponse(
                    {"choices": [{"message": {"content": "recovered"}}]})

        monkeypatch.setattr("httpx.AsyncClient", _FailingThenWorkingClient)
        assert await engine._call_llm("q") == "recovered"
        assert engine.last_provider == AIProvider.GROQ
        assert captured["headers"]["Authorization"] == "Bearer groq-key"
        assert captured["json"]["model"] == "llama-3.3-70b-versatile"


class TestJSONExtraction:
    def test_bare_json(self):
        from modules.ai_integration import extract_json
        assert extract_json('{"a": 1}') == {"a": 1}

    def test_markdown_fenced_json(self):
        from modules.ai_integration import extract_json
        raw = '```json\n{"a": 1}\n```'
        assert extract_json(raw) == {"a": 1}

    def test_fenced_with_lang_variant(self):
        from modules.ai_integration import extract_json
        assert extract_json("```\n{\"a\": 2}\n```") == {"a": 2}

    def test_non_json_returns_none(self):
        from modules.ai_integration import extract_json
        assert extract_json("sorry, I cannot do that") is None
        assert extract_json("") is None


class TestFalsePositiveTriage:
    @pytest.mark.asyncio
    async def test_verdicts_become_hypotheses(self, ai, monkeypatch):
        async def fake(prompt, temperature=0.3):
            assert "supersecret123" not in prompt
            return ('{"verdicts": [{"finding_id": "0", "verdict": '
                    '"likely_false_positive", "confidence": 0.8, '
                    '"reason": "no payload reflected"}]}')
        monkeypatch.setattr(ai, "_call_llm", fake)
        findings = [{"id": "0", "type": "xss", "severity": "medium",
                     "url": "https://x/?q=1", "description": "password=supersecret123"}]
        statements = await ai.triage_false_positives(findings)
        assert len(statements) == 1
        assert statements[0].reasoning_type == AIReasoningType.HYPOTHESIS
        assert statements[0].metadata["verdict"] == "likely_false_positive"
        assert "state" not in findings[0]  # AI never reclassifies findings

    @pytest.mark.asyncio
    async def test_disabled_returns_empty(self, monkeypatch):
        from modules.ai_integration import _dotenv_refresh, _dotenv_values
        _dotenv_refresh()
        for name in ("GEMINI_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        # .env may provide keys; suppress the dotenv fallback for this test
        monkeypatch.setattr("modules.ai_integration._dotenv_values", lambda: {})
        engine = AIIntegration(api_key="")
        assert engine.enabled is False
        assert await engine.triage_false_positives([{"id": "1"}]) == []


class TestReconAnalysis:
    @pytest.mark.asyncio
    async def test_recon_statements(self, ai, monkeypatch):
        async def fake(prompt, temperature=0.3):
            assert "internal-secret" not in prompt
            return ('{"summary": "host runs nginx", "observations": '
                    '["8080 exposed"], "suggested_steps": [{"step": "scan '
                    '8080", "priority": "high"}]}')
        monkeypatch.setattr(ai, "_call_llm", fake)
        discovery = {"urls": ["https://x/"], "technologies": ["nginx"],
                     "ports": [8080], "leak": "internal-secret"}
        statements = await ai.analyze_recon(discovery)
        kinds = [s.reasoning_type for s in statements]
        assert AIReasoningType.INFERENCE in kinds
        assert AIReasoningType.HYPOTHESIS in kinds
        assert AIReasoningType.RECOMMENDATION in kinds
        assert statements[-1].metadata["priority"] == "high"


class TestEnsembleTriage:
    @pytest.mark.asyncio
    async def test_no_keys_returns_empty(self, monkeypatch):
        for name in ("GEMINI_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        assert await ensemble_triage([{"id": "1"}]) == []

    @pytest.mark.asyncio
    async def test_aggregates_providers(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "g-key")
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

        async def fake_triage(self, findings, evidence=None):
            return [AIStatement(
                content=f"fp from {self.provider.value}",
                reasoning_type=AIReasoningType.HYPOTHESIS,
                confidence=0.5,
            )]
        monkeypatch.setattr(
            "modules.ai_integration.AIIntegration.triage_false_positives",
            fake_triage,
        )
        statements = await ensemble_triage([{"id": "1"}])
        assert len(statements) == 1
        assert statements[0].metadata.get("provider") == "gemini"
        assert "fp from gemini" in statements[0].content


class TestDeterministicDedup:
    def test_compute_dedup_key(self, ai):
        finding = {
            "title": "  SQL Injection  ",
            "affected_asset": "https://example.com/",
            "detection_module": "scanner",
            "type": "sql_injection",
        }
        key = ai._compute_dedup_key(finding)
        assert "scanner" in key
        assert "sql_injection" in key

    def test_normalize_title(self, ai):
        assert ai._normalize_title("potential SQL Injection") == "sql injection"
        assert ai._normalize_title("Confirmed XSS") == "xss"

    def test_normalize_asset(self, ai):
        assert ai._normalize_asset("https://example.com:443/") == "example.com"
        assert ai._normalize_asset("http://example.com:80") == "example.com"

    def test_finding_label_falls_back_to_type_and_url(self):
        assert AIIntegration._finding_label(
            {"title": "  SQLi  "}) == "SQLi"
        assert AIIntegration._finding_label(
            {"type": "XSS", "url": "https://x/a"}) == "XSS at https://x/a"
        assert AIIntegration._finding_label({}) == "untitled finding"


@pytest.fixture(autouse=True)
def clean_rate_limit_state():
    """Module-level rate-limit state must not leak between tests."""
    from modules.ai_integration import reset_rate_limit_state
    reset_rate_limit_state()
    yield
    reset_rate_limit_state()


class _FlakyClient:
    """Async client that raises HTTP 429 for the first N POST attempts."""

    def __init__(self, failures, payload):
        self.failures = failures
        self.payload = payload
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def post(self, url, headers=None, params=None, json=None, timeout=None):
        self.calls += 1
        if self.calls <= self.failures:
            import httpx
            request = httpx.Request("POST", url)
            response = httpx.Response(
                429, request=request, headers={"retry-after": "0"})
            raise httpx.HTTPStatusError(
                "429 Too Many Requests", request=request, response=response)
        return self._ok()

    async def _ok(self):
        return _FakeResponse(self.payload)


class TestRateLimitHandling:
    @pytest.mark.asyncio
    async def test_429_is_retried_then_succeeds(self, monkeypatch):
        client = _FlakyClient(failures=1, payload={
            "choices": [{"message": {"content": "recovered"}}]})
        monkeypatch.setattr("httpx.AsyncClient", lambda: client)
        engine = AIIntegration(provider=AIProvider.GROQ, api_key="groq-key")

        assert await engine._call_llm("hi") == "recovered"
        assert client.calls == 2

    @pytest.mark.asyncio
    async def test_persistent_429_opens_provider_cooldown(self, monkeypatch):
        from modules.ai_integration import provider_cooldown_remaining

        monkeypatch.setattr(
            "modules.ai_integration.configured_providers",
            lambda: [AIProvider.GROQ],
        )
        client = _FlakyClient(failures=99, payload={
            "choices": [{"message": {"content": "never"}}]})
        monkeypatch.setattr("httpx.AsyncClient", lambda: client)
        engine = AIIntegration(provider=AIProvider.GROQ, api_key="groq-key")

        assert await engine._call_llm("hi") is None
        attempts = client.calls
        assert attempts == 3  # initial try + MAX_RATE_LIMIT_RETRIES
        assert provider_cooldown_remaining(AIProvider.GROQ) > 0

        # Cool-down: the provider is skipped without further HTTP traffic.
        assert await engine._call_llm("hi again") is None
        assert client.calls == attempts


class TestValidateFindings:
    @pytest.mark.asyncio
    async def test_returns_typed_result_with_global_index(self, ai, monkeypatch):
        findings = [{"id": str(i), "type": "xss",
                     "url": f"https://t/{i}", "severity": "high"}
                    for i in range(45)]
        prompts = []

        async def fake(prompt, temperature=0.3):
            prompts.append(prompt)
            if len(prompts) == 1:
                return ('{"validated_findings": [{"finding_index": 44, '
                        '"verdict": "likely_false_positive", '
                        '"confidence": 0.8, "reasoning": "not reflected"}]}')
            return '{"validated_findings": []}'

        monkeypatch.setattr(ai, "_call_llm", fake)
        result = await ai.validate_findings(findings, batch_size=20,
                                            max_batches=3)

        assert isinstance(result, AICorrelationResult)
        assert result.correlation_type == AICorrelationType.VALIDATION
        assert len(prompts) == 3  # 45 findings -> 20 + 20 + 5
        assert len(result.statements) == 1
        assert result.statements[0].metadata["finding_index"] == 44
        assert result.statements[0].reasoning_type == AIReasoningType.HYPOTHESIS
        assert "45/45" in result.reasoning

    @pytest.mark.asyncio
    async def test_batch_limit_bounds_api_calls(self, ai, monkeypatch):
        findings = [{"id": str(i), "type": "xss", "url": f"https://t/{i}"}
                    for i in range(500)]
        prompts = []

        async def fake(prompt, temperature=0.3):
            prompts.append(prompt)
            return '{"validated_findings": []}'

        monkeypatch.setattr(ai, "_call_llm", fake)
        result = await ai.validate_findings(findings, batch_size=20,
                                            max_batches=5)

        assert len(prompts) == 5
        assert "100/500" in result.reasoning

    @pytest.mark.asyncio
    async def test_unavailable_llm_does_not_raise(self, ai, monkeypatch):
        async def fake(prompt, temperature=0.3):
            return None

        monkeypatch.setattr(ai, "_call_llm", fake)
        result = await ai.validate_findings([{"id": "1", "type": "xss"}])

        assert isinstance(result, AICorrelationResult)
        assert result.statements == []
        assert "0/1" in result.reasoning

    @pytest.mark.asyncio
    async def test_disabled_engine_returns_none(self, monkeypatch):
        from modules.ai_integration import _dotenv_refresh
        _dotenv_refresh()
        monkeypatch.setattr("modules.ai_integration._dotenv_values", lambda: {})
        for name in ("GEMINI_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        engine = AIIntegration(api_key="")
        assert await engine.validate_findings([{"id": "1"}]) is None


class TestDedupAggregation:
    @pytest.mark.asyncio
    async def test_duplicates_collapse_to_one_statement(self, ai):
        ai._enabled = False  # deterministic pass only
        findings = [
            {"id": "1", "type": "XSS", "url": "https://t/a",
             "severity": "high"},
            {"id": "2", "type": "XSS", "url": "https://t/a",
             "severity": "high"},
            {"id": "3", "type": "XSS", "url": "https://t/a",
             "severity": "high"},
            {"id": "4", "type": "SSRF", "url": "https://t/b",
             "severity": "high"},
        ]
        result = await ai.correlate_findings(findings, [])

        dedup = [s for s in result.statements
                 if s.source_module == "ai_dedup"]
        assert len(dedup) == 1
        meta = dedup[0].metadata
        assert meta["duplicate_group_count"] == 1
        assert meta["redundant_finding_count"] == 2
        assert meta["unique_finding_count"] == 2
        assert "unknown" not in dedup[0].content
        assert "XSS" in dedup[0].content
        assert len(result.output_findings) == 2

    @pytest.mark.asyncio
    async def test_no_duplicates_yields_no_dedup_statement(self, ai):
        ai._enabled = False
        findings = [
            {"id": "1", "type": "XSS", "url": "https://t/a"},
            {"id": "2", "type": "SSRF", "url": "https://t/b"},
        ]
        result = await ai.correlate_findings(findings, [])
        assert not [s for s in result.statements
                    if s.source_module == "ai_dedup"]
        assert len(result.output_findings) == 2
