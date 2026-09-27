"""
Athena AI/LLM Integration Module
================================
Provides structured AI assistance for finding correlation, prioritization,
attack-path reasoning, and report generation.

CRITICAL DESIGN PRINCIPLE:
The LLM must NEVER be the source of truth. Deterministic tools and collected
evidence remain authoritative. The AI may say "Potential SQL injection" but
Athena should not mark "CONFIRMED SQL INJECTION" until the validation
subsystem has produced sufficient evidence.

The AI must clearly distinguish:
- FACT: directly observed and validated
- INFERENCE: derived from evidence with high confidence
- HYPOTHESIS: suggested but unverified
- RECOMMENDATION: suggested next steps
"""

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("athena.ai")


class AIReasoningType(Enum):
    """Classification of AI-generated statements."""
    FACT = "fact"              # Directly observed and validated
    INFERENCE = "inference"    # Derived from evidence with high confidence
    HYPOTHESIS = "hypothesis"  # Suggested but unverified
    RECOMMENDATION = "recommendation"  # Suggested next steps


class AICorrelationType(Enum):
    """Types of correlation the AI can perform."""
    FINDING_DEDUP = "finding_dedup"
    ATTACK_PATH = "attack_path"
    PRIORITY = "priority"
    REMEDIATION = "remediation"
    REPORT_GENERATION = "report_generation"
    VALIDATION = "validation"


class AIProvider(Enum):
    """Supported LLM backends.  Gemini and Groq are OpenAI-compatible in
    shape; DeepSeek is OpenAI-compatible as well (that key was previously
    read but never used - the call was hardcoded to Gemini)."""
    GEMINI = "gemini"
    GROQ = "groq"
    DEEPSEEK = "deepseek"


#: Per-provider configuration: env var for the key, default model, endpoint.
AI_PROVIDERS = {
    AIProvider.GEMINI: {
        "env": "GEMINI_API_KEY",
        # Floating alias: versioned model ids get retired by Google and then
        # 404 (gemini-2.0-flash did), which silently disabled all AI features.
        "model": "gemini-flash-latest",
        "endpoint": "https://generativelanguage.googleapis.com/v1beta/models/"
                    "{model}:generateContent",
        "style": "gemini",
    },
    AIProvider.GROQ: {
        "env": "GROQ_API_KEY",
        "model": "llama-3.3-70b-versatile",
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "style": "openai",
    },
    AIProvider.DEEPSEEK: {
        "env": "DEEPSEEK_API_KEY",
        "model": "deepseek-chat",
        "endpoint": "https://api.deepseek.com/chat/completions",
        "style": "openai",
    },
}

#: Probe order when ``ATHENA_AI_PROVIDER`` is not set.
PROVIDER_PRIORITY: List[AIProvider] = [
    AIProvider.GEMINI, AIProvider.GROQ, AIProvider.DEEPSEEK,
]


def _env_flag_set(name: str) -> bool:
    return bool(os.getenv(name, "").strip())


def extract_json(text: str) -> Any:
    """Parse an LLM response that may wrap JSON in markdown fences.

    Providers differ: Gemini usually returns bare JSON, Groq commonly
    wraps it in ```json ... ``` fences.  This accepts both, and refuses
    text that is not JSON (fail-safe - the caller treats None as no
    statements).
    """
    if not text:
        return None
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = re.sub(r"^```[a-zA-Z]*\s*", "", candidate)
        candidate = re.sub(r"\s*```$", "", candidate)
    try:
        return json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        return None


def _batches(items: List[Any], batch_size: int,
             max_batches: int) -> List[Tuple[int, List[Any]]]:
    """Split ``items`` into ``(offset, batch)`` windows for LLM calls.

    The offset lets callers translate model-local indexes (0..n-1) back to
    positions in the original list.  Coverage is bounded by
    ``batch_size * max_batches`` so a scan with thousands of raw detections
    cannot issue hundreds of sequential API calls.
    """
    if batch_size <= 0 or max_batches <= 0:
        return []
    limit = min(len(items), batch_size * max_batches)
    return [(start, items[start:start + batch_size])
            for start in range(0, limit, batch_size)]


def _as_global_index(raw: Any, total: int) -> Optional[int]:
    """Parse a model-reported finding index, rejecting out-of-range values."""
    try:
        index = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if 0 <= index < total:
        return index
    return None


_DOTENV_CACHE: Optional[Dict[str, str]] = None


def _dotenv_values() -> Dict[str, str]:
    """Parse the project ``.env`` file once (process env still wins)."""
    global _DOTENV_CACHE
    if _DOTENV_CACHE is not None:
        return _DOTENV_CACHE
    values: Dict[str, str] = {}
    try:
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    _DOTENV_CACHE = values
    return values


def _dotenv_refresh() -> None:
    """Discard the cached ``.env`` values and reparse on next call.

    Useful in tests that have removed a key from the process environment
    via monkeypatch and need the module-level cache to reflect that.
    """
    global _DOTENV_CACHE
    _DOTENV_CACHE = None


# Seed missing process-environment variables from the project ``.env``
# file (existing env vars take precedence). This makes ``ATHENA_AI_PROVIDER``
# and API keys written in ``.env`` honoured even when this module is
# imported before ``framework_config``.
for _k, _v in _dotenv_values().items():
    os.environ.setdefault(_k, _v)


def _setting(name: str, default: str = "") -> str:
    """Read a setting from the process env, falling back to ``.env``."""
    return os.getenv(name) or _dotenv_values().get(name, "") or default


def configured_providers() -> List[AIProvider]:
    """All providers that have an API key present in the environment."""
    return [p for p in PROVIDER_PRIORITY
            if _env_flag_set(AI_PROVIDERS[p]["env"])]


def resolve_provider(api_key: str = "") -> AIProvider:
    """Determine which provider to use.

    Priority: explicit ``provider`` argument handled by the caller via
    ``ATHENA_AI_PROVIDER`` env → an explicitly passed key (defaults to
    Gemini for backwards compatibility) → the first provider that has a key.
    """
    explicit = os.getenv("ATHENA_AI_PROVIDER", "").strip().lower()
    if explicit:
        try:
            return AIProvider(explicit)
        except ValueError:
            pass
    if api_key:
        return AIProvider.GEMINI
    available = configured_providers()
    return available[0] if available else AIProvider.GEMINI


# ---------------------------------------------------------------------------
# Rate-limit handling (HTTP 429 / transient 5xx)
# ---------------------------------------------------------------------------
#
# Providers such as Groq enforce per-minute request budgets.  A scan makes
# several LLM calls in a row, so a single burst of 429s would otherwise burn
# the whole budget and silence every AI feature for the rest of the run.
# Two mechanisms keep behaviour predictable:
#
#   1. Per-call backoff: retry 429/5xx responses a couple of times, honouring
#      ``Retry-After`` when the provider sends one.
#   2. Per-provider cooldown: after repeated rate-limit responses the provider
#      is skipped for a cool-down window so the scan fails fast (and other
#      configured providers still get their chance).

#: Status codes worth retrying (everything else fails over immediately).
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

#: Maximum in-call retries for a retryable status.
MAX_RATE_LIMIT_RETRIES = 2

#: Upper bound for a single backoff sleep (seconds).
MAX_BACKOFF_SECONDS = 8.0

#: Consecutive 429s tolerated before a provider is put in cool-down.
RATE_LIMIT_STRIKE_THRESHOLD = 3

#: Cool-down applied once the threshold is reached (seconds).
PROVIDER_COOLDOWN_SECONDS = 60.0

_PROVIDER_COOLDOWN_UNTIL: Dict[AIProvider, float] = {}
_PROVIDER_STRIKES: Dict[AIProvider, int] = {}


def reset_rate_limit_state() -> None:
    """Clear cool-down bookkeeping (used by tests)."""
    _PROVIDER_COOLDOWN_UNTIL.clear()
    _PROVIDER_STRIKES.clear()


def provider_cooldown_remaining(provider: AIProvider) -> float:
    """Seconds until ``provider`` may be called again (0 when available)."""
    return max(0.0, _PROVIDER_COOLDOWN_UNTIL.get(provider, 0.0)
               - time.monotonic())


def _status_code(exc: BaseException) -> Optional[int]:
    """Extract an HTTP status code from an exception, if it has one."""
    response = getattr(exc, "response", None)
    code = getattr(response, "status_code", None)
    return code if isinstance(code, int) else None


def _retry_delay(exc: BaseException, attempt: int) -> float:
    """Backoff delay for a retryable failure, honouring ``Retry-After``."""
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    if headers is not None:
        try:
            retry_after = headers.get("retry-after")
        except Exception:
            # Non-standard header containers: ignore and fall back.
            retry_after = None
        if retry_after:
            try:
                return min(max(float(retry_after), 0.0), MAX_BACKOFF_SECONDS)
            except (TypeError, ValueError):
                pass
    return min(2.0 * (2 ** attempt), MAX_BACKOFF_SECONDS)


def _register_rate_limit(provider: AIProvider, logger: logging.Logger) -> None:
    """Track a 429 and open a cool-down once strikes exceed the threshold."""
    strikes = _PROVIDER_STRIKES.get(provider, 0) + 1
    _PROVIDER_STRIKES[provider] = strikes
    if strikes >= RATE_LIMIT_STRIKE_THRESHOLD:
        _PROVIDER_COOLDOWN_UNTIL[provider] = (
            time.monotonic() + PROVIDER_COOLDOWN_SECONDS
        )
        _PROVIDER_STRIKES[provider] = 0
        logger.warning(
            f"AI provider {provider.value} rate limited {strikes}x; "
            f"cooling down for {int(PROVIDER_COOLDOWN_SECONDS)}s"
        )


@dataclass
class AIStatement:
    """One AI-generated statement with explicit reasoning type."""
    content: str
    reasoning_type: AIReasoningType
    confidence: float  # 0.0 to 1.0
    evidence_refs: List[str] = field(default_factory=list)  # evidence IDs
    source_module: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "reasoning_type": self.reasoning_type.value,
            "confidence": self.confidence,
            "evidence_refs": list(self.evidence_refs),
            "source_module": self.source_module,
            "timestamp": self.timestamp,
            "metadata": dict(self.metadata),
        }


@dataclass
class AICorrelationResult:
    """Result of an AI correlation operation."""
    correlation_type: AICorrelationType
    statements: List[AIStatement]
    input_findings: List[str]  # finding IDs used
    output_findings: List[str]  # finding IDs produced/modified
    confidence: float
    reasoning: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_type": self.correlation_type.value,
            "statements": [s.to_dict() for s in self.statements],
            "input_findings": list(self.input_findings),
            "output_findings": list(self.output_findings),
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "timestamp": self.timestamp,
        }


class AIIntegration:
    """AI integration layer for Athena.
    
    This module provides structured AI assistance while maintaining
    the principle that deterministic tools remain authoritative.
    """
    
    # Prompt templates for different AI tasks
    PROMPTS = {
        "correlation": """You are a security finding correlation engine. Analyze these findings and identify:
1. Duplicates (same vulnerability, different detection)
2. Related findings (part of same attack chain)
3. Causal relationships (one finding enables another)

Findings:
{findings}

Evidence:
{evidence}

Respond with JSON:
{{
  "correlations": [
    {{"finding_ids": ["id1", "id2"], "relationship": "duplicate|related|causal", "confidence": 0.9, "reasoning": "..."}}
  ]
}}""",
        
        "prioritization": """You are a vulnerability prioritization engine. Rank these findings by risk.
Consider: severity, exploitability, asset criticality, evidence strength.

Findings:
{findings}

Context:
{context}

Respond with JSON:
{{
  "prioritized": [
    {{"finding_id": "...", "score": 0.95, "reasoning": "..."}}
  ]
}}""",
        
        "attack_path": """You are an attack path analyzer. Identify how findings connect into attack chains.

Findings:
{findings}

Evidence:
{evidence}

Attack graph nodes:
{nodes}

Respond with JSON:
{{
  "paths": [
    {{"steps": ["finding1", "finding2"], "description": "...", "confidence": 0.85}}
  ]
}}""",
        
        "report": """You are a security report writer. Generate a professional narrative for this assessment.

Engagement: {engagement}
Findings: {findings}
Evidence: {evidence}

Write a clear, concise executive summary and technical details section.""",

        "triage": """You are a security analyst reviewing automated scan findings for false positives.
For each finding decide whether it is LIKELY FALSE POSITIVE, LIKELY TRUE, or UNCERTAIN.
Be conservative: without strong evidence, keep findings as UNCERTAIN.
Your verdict is a HYPOTHESIS only - it never overrides deterministic validation.

Findings:
{findings}

Respond with JSON:
{{
  "verdicts": [
    {{"finding_id": "...", "verdict": "likely_false_positive|likely_true|uncertain", "confidence": 0.7, "reason": "..."}}
  ]
}}""",

        "recon": """You are a security reconnaissance analyst. Summarize the recon data and
suggest the most promising next assessment steps. Distinguish FACT from HYPOTHESIS.

Recon data:
{recon}

Respond with JSON:
{{
  "summary": "...",
  "observations": ["..."],
  "suggested_steps": [{{"step": "...", "priority": "high|medium|low"}}]
}}""",

        "next_steps": """You are a security assessment advisor. Based on the current findings and
post-exploitation context, suggest the next assessment steps. Label each as a
RECOMMENDATION and do not assert unverified facts as confirmed.

Context:
{context}

Respond with JSON:
{{
  "steps": [{{"step": "...", "priority": "high|medium|low", "reason": "..."}}]
}}""",

        "hidden_asset_scanner": """You are an aggressive web reconnaissance specialist. Hidden directories and backup files are CONFIRMED attack surfaces, not minor findings.

TARGET: {target_url}
BASELINE_LENGTH: {baseline_length}

Produce confirmed JSON with hidden_directories, backup_files, misconfigurations, security_headers_analysis, and http_method_vulnerabilities.
Hidden paths returning HTTP 200 are ALWAYS CRITICAL severity.
Backup files (.bak, .sql, .dump, .zip) returning HTTP 200 are ALWAYS CRITICAL.
The word "minor" must NEVER appear. Every path must have a copy-paste exploitation command.
Return ONLY valid JSON, no markdown fences.""",

        "post_exploitation_validation": """You are a senior penetration tester validating post-exploitation results.

PHASE RESULTS: {phase_results}
HIDDEN_FILES_FOUND: {hidden_files_found}
BACKUP_FILES_FOUND: {backup_files_found}
MISCONFIGURATIONS_FOUND: {misconfigurations_found}

Produce confirmed JSON with validated_items, hidden_directory_exploitation, backup_file_exploitation, misconfiguration_exploitation.
Hidden directories (.git, .env, .backup) are NEVER "minor" — they are CRITICAL.
Backup files are ALWAYS CRITICAL — they contain plaintext credentials.
Misconfigurations (directory listing, default creds, CORS, PUT/DELETE/TRACE methods) are ALWAYS HIGH or CRITICAL.
Every command must be copy-paste executable. The word "minor" must NOT appear.""",

        "aggressive_confirmation": """You are a vulnerability validation engine. Every statement MUST be backed by raw HTTP response data.

HIDDEN_ASSET_SCAN_DATA: {hidden_asset_scan_results}
SECURITY_HEADERS_DATA: {security_headers_response}
HTTP_METHOD_TEST_DATA: {http_method_test_results}

Produce confirmed JSON with validated_findings, hidden_directory_confirmations, backup_file_confirmations, misconfiguration_confirmations.
Hidden directories returning HTTP 200 are CONFIRMED_TRUE_POSITIVE with CRITICAL severity.
Backup files returning HTTP 200 are CONFIRMED_TRUE_POSITIVE with CRITICAL severity.
TRACE/PUT/DELETE methods enabled are CONFIRMED_TRUE_POSITIVE with CRITICAL severity.
The word "minor" must NOT appear. exploitation_command must be copy-paste ready."""

    }

    def __init__(self, api_key: str = "", model: str = "",
                 provider: Optional[AIProvider] = None):
        if provider is not None:
            self.provider = provider
        else:
            self.provider = resolve_provider(api_key)
        self.provider_config = AI_PROVIDERS[self.provider]
        if not model:
            model = os.getenv("ATHENA_AI_MODEL") or self.provider_config["model"]
        self.api_key = api_key or _setting(self.provider_config["env"])
        self.model = model
        self.logger = logging.getLogger("athena.ai")
        self._last_provider = self.provider
        self._enabled = bool(self.api_key)

        if not self._enabled:
            self.logger.info(
                f"AI integration disabled (no {self.provider_config['env']} "
                "configured)"
            )

    @property
    def last_provider(self) -> AIProvider:
        """Provider that answered the most recent LLM call (after failover)."""
        return self._last_provider

    @staticmethod
    def _redacted_for_llm(payload: Any) -> str:
        """Serialize payloads for LLM calls with all secrets redacted.

        Secret values (credentials, tokens, keys) never leave the process:
        every string leaf is passed through ``SecretRedactor`` so only
        ``[REDACTED:kind]`` tags reach the LLM provider.
        """
        from modules.findings import SecretRedactor
        return json.dumps(SecretRedactor.redact_dict(payload), indent=2)

    async def _call_llm(self, prompt: str,
                        temperature: float = 0.3) -> Optional[str]:
        """Call the configured LLM provider with automatic failover.

        If the primary provider fails (network error, HTTP error, missing
        key), the call falls through to the next configured provider
        (Gemini → Groq → DeepSeek).  ``last_provider`` reports who answered.
        """
        if not self._enabled:
            return None
        text = await self._call_llm_provider(
            self.provider, prompt, temperature)
        if text is not None:
            self._last_provider = self.provider
            return text
        for fallback in configured_providers():
            if fallback == self.provider:
                continue
            text = await self._call_llm_provider(fallback, prompt, temperature)
            if text is not None:
                self._last_provider = fallback
                self.logger.info(
                    f"AI failover: {self.provider.value} failed; "
                    f"answered via {fallback.value}"
                )
                return text
        return None

    async def _call_llm_provider(self, provider: AIProvider,
                                 prompt: str,
                                 temperature: float = 0.3) -> Optional[str]:
        """Call one specific provider; returns None on failure.

        Retryable failures (429 / 5xx) are retried up to
        ``MAX_RATE_LIMIT_RETRIES`` times with backoff; every other error
        returns immediately so the caller can fail over to the next
        provider without waiting.
        """
        config = AI_PROVIDERS[provider]
        api_key = self.api_key if provider == self.provider \
            else os.getenv(config["env"], "")
        if not api_key:
            return None

        cooldown = provider_cooldown_remaining(provider)
        if cooldown > 0:
            self.logger.info(
                f"Skipping AI provider {provider.value}: rate-limit "
                f"cool-down ({cooldown:.0f}s remaining)"
            )
            return None

        for attempt in range(MAX_RATE_LIMIT_RETRIES + 1):
            try:
                content = await self._post_once(
                    provider, config, api_key, prompt, temperature)
                _PROVIDER_STRIKES[provider] = 0
                return content
            except Exception as e:
                status = _status_code(e)
                if status == 429:
                    _register_rate_limit(provider, self.logger)
                retryable = status in RETRYABLE_STATUS
                if not retryable or attempt >= MAX_RATE_LIMIT_RETRIES:
                    self.logger.warning(f"LLM call failed ({provider.value}): {e}")
                    return None
                delay = _retry_delay(e, attempt)
                self.logger.info(
                    f"LLM call to {provider.value} returned {status}; "
                    f"retrying in {delay:.1f}s "
                    f"({attempt + 1}/{MAX_RATE_LIMIT_RETRIES})"
                )
                await asyncio.sleep(delay)
        return None

    async def _post_once(self, provider: AIProvider, config: Dict[str, Any],
                         api_key: str, prompt: str,
                         temperature: float) -> Optional[str]:
        """Perform a single HTTP round-trip against ``provider``."""
        import httpx

        if config["style"] == "openai":
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    config["endpoint"],
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": (self.model if provider == self.provider
                                  else config["model"]),
                        "messages": [{"role": "user",
                                      "content": prompt}],
                        "temperature": temperature,
                        "max_tokens": 2048,
                    },
                    timeout=30.0,
                )
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]

        async with httpx.AsyncClient() as client:
            model_name = (self.model if provider == self.provider
                          else config["model"])
            response = await client.post(
                "https://generativelanguage.googleapis.com/v1beta/models/"
                f"{model_name}:generateContent",
                params={"key": api_key},
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [
                        {"parts": [{"text": prompt}]}
                    ],
                    "generationConfig": {
                        "temperature": temperature,
                        "maxOutputTokens": 2048,
                    },
                },
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]

    @property
    def enabled(self) -> bool:
        return self._enabled
    
    async def correlate_findings(
        self, 
        findings: List[Dict[str, Any]], 
        evidence: List[Dict[str, Any]],
        engagement_id: str = ""
    ) -> AICorrelationResult:
        """Correlate findings and identify duplicates or related issues.
        
        This is a DETERMINISTIC operation that uses pattern matching,
        not AI. The AI is only used for optional enhancement.
        """
        # Apply engagement filter if specified
        if engagement_id:
            findings = [f for f in findings if f.get("engagement_id") == engagement_id]
        
        # Deterministic deduplication first
        dedup_groups = self._deterministic_dedup(findings)
        
        statements = []
        output_findings = []
        duplicate_groups = []
        
        for group_key, group_findings in sorted(dedup_groups.items()):
            primary = group_findings[0]
            output_findings.append(primary.get("id", ""))
            if len(group_findings) < 2:
                continue

            # Multiple findings with same dedup key
            label = self._finding_label(primary)
            duplicate_groups.append({
                "dedup_key": group_key,
                "title": label,
                "asset": primary.get("affected_asset")
                         or primary.get("url", ""),
                "kept_finding_id": primary.get("id", ""),
                "merged_finding_ids": [f.get("id", "")
                                       for f in group_findings[1:]],
                "duplicate_count": len(group_findings) - 1,
            })
        
        if duplicate_groups:
            # One aggregated statement instead of one line per group: a large
            # scan can produce hundreds of groups, which would drown the
            # console output and the report narrative.
            redundant = sum(g["duplicate_count"] for g in duplicate_groups)
            examples = "; ".join(
                f"{g['title']} ({g['duplicate_count'] + 1}x)"
                for g in duplicate_groups[:5]
            )
            if len(duplicate_groups) > 5:
                examples += f"; +{len(duplicate_groups) - 5} more group(s)"
            statements.append(AIStatement(
                content=(
                    f"Consolidated {len(duplicate_groups)} duplicate group(s): "
                    f"{redundant} redundant finding(s) merged into "
                    f"{len(output_findings)} unique finding(s). "
                    f"Largest: {examples}"
                ),
                reasoning_type=AIReasoningType.FACT,
                confidence=1.0,
                evidence_refs=[fid for g in duplicate_groups
                               for fid in g["merged_finding_ids"]],
                source_module="ai_dedup",
                metadata={
                    "duplicate_group_count": len(duplicate_groups),
                    "redundant_finding_count": redundant,
                    "unique_finding_count": len(output_findings),
                    "duplicate_groups": duplicate_groups[:20],
                },
            ))
        
        # Optional AI enhancement for attack path reasoning
        if self._enabled and findings:
            ai_statements = await self._ai_attack_path_reasoning(findings, evidence)
            statements.extend(ai_statements)
        
        return AICorrelationResult(
            correlation_type=AICorrelationType.FINDING_DEDUP,
            statements=statements,
            input_findings=[f.get("id", "") for f in findings],
            output_findings=output_findings,
            confidence=0.95 if not self._enabled else 0.85,
            reasoning="Deterministic deduplication with optional AI enhancement",
        )
    
    async def prioritize_findings(
        self,
        findings: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> AICorrelationResult:
        """Prioritize findings based on severity, confidence, and impact.
        
        Uses deterministic scoring with optional AI enhancement.
        """
        prioritized = []
        statements = []
        
        for finding in findings:
            score = self._calculate_priority_score(finding, context)
            prioritized.append((score, finding))
            
            statements.append(AIStatement(
                content=f"Finding '{finding.get('title', 'unknown')}' scored {score:.2f} for prioritization",
                reasoning_type=AIReasoningType.FACT,
                confidence=0.9,
                evidence_refs=[finding.get("id", "")],
                source_module="ai_priority",
                metadata={"score": score, "severity": finding.get("severity", "info")},
            ))
        
        # Sort by score descending
        prioritized.sort(key=lambda x: x[0], reverse=True)
        
        return AICorrelationResult(
            correlation_type=AICorrelationType.PRIORITY,
            statements=statements,
            input_findings=[f.get("id", "") for f in findings],
            output_findings=[f.get("id", "") for _, f in prioritized],
            confidence=0.85,
            reasoning="Deterministic priority scoring based on severity and confidence",
        )
    
    async def generate_attack_path_analysis(
        self,
        graph_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        sessions: List[Dict[str, Any]]
    ) -> AICorrelationResult:
        """Analyze attack paths and provide AI-enhanced reasoning.
        
        The graph is built deterministically. AI provides optional
        enhancement for path interpretation.
        """
        statements = []
        
        # Deterministic path analysis
        confirmed_paths = self._find_confirmed_paths(graph_data)
        potential_paths = self._find_potential_paths(graph_data)
        
        if confirmed_paths:
            statements.append(AIStatement(
                content=f"Found {len(confirmed_paths)} confirmed attack path(s)",
                reasoning_type=AIReasoningType.FACT,
                confidence=1.0,
                source_module="ai_attack_path",
                metadata={"confirmed_count": len(confirmed_paths)},
            ))
        
        if potential_paths:
            statements.append(AIStatement(
                content=f"Found {len(potential_paths)} potential attack path(s) requiring validation",
                reasoning_type=AIReasoningType.INFERENCE,
                confidence=0.7,
                source_module="ai_attack_path",
                metadata={"potential_count": len(potential_paths)},
            ))
        
        # Optional AI enhancement
        if self._enabled:
            ai_statements = await self._ai_enhance_attack_paths(
                graph_data, confirmed_paths, potential_paths
            )
            statements.extend(ai_statements)
        
        return AICorrelationResult(
            correlation_type=AICorrelationType.ATTACK_PATH,
            statements=statements,
            input_findings=[f.get("id", "") for f in findings],
            output_findings=[],
            confidence=0.9,
            reasoning="Deterministic graph traversal with optional AI enhancement",
        )
    
    async def generate_report_narrative(
        self,
        engagement: Dict[str, Any],
        findings: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        attack_paths: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate a narrative report section using AI.
        
        The narrative is AI-generated but must be clearly labeled as such
        and must not contradict deterministic findings.
        """
        if not self._enabled:
            return self._generate_deterministic_narrative(
                engagement, findings, evidence, attack_paths
            )
        
        # Build context for AI
        context = self._build_report_context(engagement, findings, evidence, attack_paths)
        
        # AI generation would go here
        # For now, return deterministic narrative
        return self._generate_deterministic_narrative(
            engagement, findings, evidence, attack_paths
        )
    
    # -------------------------------------------------------------------------
    # Deterministic helpers (no AI dependency)
    # -------------------------------------------------------------------------
    
    def _deterministic_dedup(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by dedup key deterministically."""
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for finding in findings:
            key = finding.get("dedup_key") or self._compute_dedup_key(finding)
            if key not in groups:
                groups[key] = []
            groups[key].append(finding)
        return groups
    
    def _compute_dedup_key(self, finding: Dict[str, Any]) -> str:
        """Compute a stable dedup key for a finding."""
        title = (finding.get("title") or "").strip().lower()
        asset = (finding.get("affected_asset") or finding.get("url") or "").strip().lower()
        module = (finding.get("detection_module") or "").strip().lower()
        finding_type = (finding.get("type") or "").strip().lower()
        
        # Normalize common variations
        title = self._normalize_title(title)
        asset = self._normalize_asset(asset)
        
        return f"{module}|{asset}|{finding_type}|{title}"
    
    def _normalize_title(self, title: str) -> str:
        """Normalize a finding title for dedup."""
        title = title.lower()
        prefixes = ["potential ", "possible ", "confirmed ", "detected "]
        for prefix in prefixes:
            if title.startswith(prefix):
                title = title[len(prefix):]
        title = " ".join(title.split())
        return title
    
    def _normalize_asset(self, asset: str) -> str:
        """Normalize an asset identifier for dedup."""
        asset = asset.replace("https://", "").replace("http://", "")
        asset = asset.rstrip("/")
        asset = asset.replace(":443", "").replace(":80", "")
        return asset.lower()

    @staticmethod
    def _finding_label(finding: Dict[str, Any]) -> str:
        """Human-readable label that never degrades to 'unknown'.

        Scan findings do not always carry a ``title``; falling back to the
        finding type plus its URL keeps deduplication reports meaningful.
        """
        title = str(finding.get("title") or "").strip()
        if title:
            return title
        vtype = str(finding.get("type") or "").strip()
        asset = str(finding.get("affected_asset")
                    or finding.get("url") or "").strip()
        if vtype and asset:
            return f"{vtype} at {asset}"
        return vtype or asset or "untitled finding"
    
    def _calculate_priority_score(
        self, 
        finding: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> float:
        """Calculate a deterministic priority score for a finding."""
        severity_scores = {
            "critical": 4.0,
            "high": 3.0,
            "medium": 2.0,
            "low": 1.0,
            "info": 0.0,
        }
        
        severity = finding.get("severity", "info").lower()
        base_score = severity_scores.get(severity, 0.0)
        
        # Confidence multiplier
        confidence = finding.get("confidence", 0.5)
        confidence_multiplier = 0.5 + (confidence * 0.5)  # 0.5 to 1.0
        
        # State multiplier
        state = finding.get("state", "discovered")
        state_multipliers = {
            "confirmed": 1.5,
            "validating": 1.2,
            "triaged": 1.1,
            "discovered": 1.0,
        }
        state_multiplier = state_multipliers.get(state, 1.0)
        
        # Context adjustments
        context_multiplier = 1.0
        if context:
            # Adjust based on engagement context
            if context.get("is_critical_asset"):
                context_multiplier *= 1.3
            if context.get("has_verified_exploit"):
                context_multiplier *= 1.2
        
        return base_score * confidence_multiplier * state_multiplier * context_multiplier
    
    def _find_confirmed_paths(self, graph_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find confirmed attack paths in the graph."""
        confirmed = []
        nodes = {n["id"]: n for n in graph_data.get("nodes", [])}
        edges = graph_data.get("edges", [])
        
        for edge in edges:
            if edge.get("state") == "confirmed":
                source = nodes.get(edge.get("source", ""), {})
                target = nodes.get(edge.get("target", ""), {})
                if source and target:
                    confirmed.append({
                        "source": source.get("label", ""),
                        "target": target.get("label", ""),
                        "relation": edge.get("relation", ""),
                    })
        
        return confirmed
    
    def _find_potential_paths(self, graph_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find potential attack paths in the graph."""
        potential = []
        nodes = {n["id"]: n for n in graph_data.get("nodes", [])}
        edges = graph_data.get("edges", [])
        
        for edge in edges:
            if edge.get("state") == "potential":
                source = nodes.get(edge.get("source", ""), {})
                target = nodes.get(edge.get("target", ""), {})
                if source and target:
                    potential.append({
                        "source": source.get("label", ""),
                        "target": target.get("label", ""),
                        "relation": edge.get("relation", ""),
                    })
        
        return potential
    
    def _generate_deterministic_narrative(
        self,
        engagement: Dict[str, Any],
        findings: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        attack_paths: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate a deterministic narrative without AI."""
        lines = []
        
        # Executive summary
        total_findings = len(findings)
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"The assessment identified {total_findings} finding(s): "
                     f"{critical} critical, {high} high severity.")
        lines.append("")
        
        # Key findings
        if critical > 0:
            lines.append("### Critical Findings")
            lines.append("")
            for finding in findings:
                if finding.get("severity") == "critical":
                    lines.append(f"- **{finding.get('title', 'Unknown')}**: "
                               f"{finding.get('description', 'No description')}")
            lines.append("")
        
        # Attack paths
        if attack_paths:
            confirmed = attack_paths.get("confirmed", [])
            if confirmed:
                lines.append("### Confirmed Attack Paths")
                lines.append("")
                for path in confirmed:
                    lines.append(f"- {path.get('source', '')} → "
                               f"{path.get('target', '')} "
                               f"({path.get('relation', '')})")
                lines.append("")
        
        # Recommendations
        lines.append("### Recommendations")
        lines.append("")
        if critical > 0:
            lines.append("1. Immediately address all critical findings")
        if high > 0:
            lines.append("2. Remediate high-severity findings within 30 days")
        lines.append("3. Implement defense-in-depth controls")
        lines.append("4. Conduct regular security assessments")
        lines.append("")
        
        return "\n".join(lines)
    
    def _build_report_context(
        self,
        engagement: Dict[str, Any],
        findings: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        attack_paths: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Build context for AI report generation."""
        return {
            "engagement_name": engagement.get("name", ""),
            "engagement_operator": engagement.get("operator", ""),
            "target_count": len(engagement.get("in_scope_targets", [])),
            "finding_count": len(findings),
            "evidence_count": len(evidence),
            "severity_breakdown": {
                "critical": sum(1 for f in findings if f.get("severity") == "critical"),
                "high": sum(1 for f in findings if f.get("severity") == "high"),
                "medium": sum(1 for f in findings if f.get("severity") == "medium"),
                "low": sum(1 for f in findings if f.get("severity") == "low"),
            },
            "attack_paths": attack_paths,
        }
    
    # -------------------------------------------------------------------------
    # AI-enhanced methods (require API key)
    # -------------------------------------------------------------------------
    
    async def _ai_attack_path_reasoning(
        self,
        findings: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]]
    ) -> List[AIStatement]:
        """Use AI to reason about attack paths (optional enhancement)."""
        if not self._enabled:
            return []
        
        findings_text = self._redacted_for_llm(findings[:20])  # Limit to avoid token limits
        evidence_text = self._redacted_for_llm(evidence[:10])
        
        prompt = self.PROMPTS["attack_path"].format(
            findings=findings_text,
            evidence=evidence_text,
            nodes="[]",  # Will be populated by caller if needed
        )
        
        response = await self._call_llm(prompt)
        if not response:
            return []
        
        try:
            data = extract_json(response)
            if not data:
                return []
            statements = []
            for path in data.get("paths", []):
                statements.append(AIStatement(
                    content=f"AI-identified attack path: {path.get('description', '')}",
                    reasoning_type=AIReasoningType.INFERENCE,
                    confidence=path.get("confidence", 0.7),
                    evidence_refs=path.get("steps", []),
                    source_module="ai_attack_path",
                    metadata={"path": path},
                ))
            return statements
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.warning(f"Failed to parse AI attack path response: {e}")
            return []
    
    async def _ai_enhance_attack_paths(
        self,
        graph_data: Dict[str, Any],
        confirmed_paths: List[Dict[str, Any]],
        potential_paths: List[Dict[str, Any]]
    ) -> List[AIStatement]:
        """Use AI to enhance attack path analysis (optional)."""
        if not self._enabled:
            return []
        
        nodes_raw = graph_data.get("nodes", [])
        if isinstance(nodes_raw, list):
            nodes = self._redacted_for_llm([n.get("label", n.get("id", "")) for n in nodes_raw[:20]])
        else:
            nodes = self._redacted_for_llm(list(nodes_raw.keys())[:20])
        
        prompt = self.PROMPTS["attack_path"].format(
            findings=self._redacted_for_llm(confirmed_paths + potential_paths)[:2000],
            evidence="[]",
            nodes=nodes,
        )
        
        response = await self._call_llm(prompt)
        if not response:
            return []
        
        try:
            data = extract_json(response)
            if not data:
                return []
            statements = []
            for path in data.get("paths", []):
                statements.append(AIStatement(
                    content=f"AI-enhanced path: {path.get('description', '')}",
                    reasoning_type=AIReasoningType.INFERENCE,
                    confidence=path.get("confidence", 0.7),
                    evidence_refs=path.get("steps", []),
                    source_module="ai_attack_path_enhance",
                    metadata={"path": path},
                ))
            return statements
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.warning(f"Failed to parse AI attack path enhance response: {e}")
            return []
    
    async def ai_correlate_findings(
        self,
        findings: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]]
    ) -> List[AIStatement]:
        """Use AI to identify correlations between findings."""
        if not self._enabled:
            return []
        
        findings_text = self._redacted_for_llm(findings[:30])
        evidence_text = self._redacted_for_llm(evidence[:15])
        
        prompt = self.PROMPTS["correlation"].format(
            findings=findings_text,
            evidence=evidence_text,
        )
        
        response = await self._call_llm(prompt)
        if not response:
            return []
        
        try:
            data = extract_json(response)
            if not data:
                return []
            statements = []
            for corr in data.get("correlations", []):
                statements.append(AIStatement(
                    content=f"AI correlation: {corr.get('reasoning', '')}",
                    reasoning_type=AIReasoningType.INFERENCE,
                    confidence=corr.get("confidence", 0.7),
                    evidence_refs=corr.get("finding_ids", []),
                    source_module="ai_correlation",
                    metadata={"relationship": corr.get("relationship", "")},
                ))
            return statements
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.warning(f"Failed to parse AI correlation response: {e}")
            return []
    
    async def ai_prioritize_findings(
        self,
        findings: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> List[AIStatement]:
        """Use AI to prioritize findings by risk."""
        if not self._enabled:
            return []
        
        findings_text = self._redacted_for_llm(findings[:30])
        context_text = self._redacted_for_llm(context or {})
        
        prompt = self.PROMPTS["prioritization"].format(
            findings=findings_text,
            context=context_text,
        )
        
        response = await self._call_llm(prompt)
        if not response:
            return []
        
        try:
            data = extract_json(response)
            if not data:
                return []
            statements = []
            for item in data.get("prioritized", []):
                statements.append(AIStatement(
                    content=f"AI priority: {item.get('reasoning', '')}",
                    reasoning_type=AIReasoningType.INFERENCE,
                    confidence=item.get("score", 0.5),
                    evidence_refs=[item.get("finding_id", "")],
                    source_module="ai_priority",
                    metadata={"score": item.get("score", 0)},
                ))
            return statements
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.warning(f"Failed to parse AI priority response: {e}")
            return []
    
    async def ai_generate_report_narrative(
        self,
        engagement: Dict[str, Any],
        findings: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]]
    ) -> Optional[str]:
        """Use AI to generate a report narrative."""
        if not self._enabled:
            return None
        
        engagement_text = self._redacted_for_llm(engagement)[:500]
        findings_text = self._redacted_for_llm(findings[:20])
        evidence_text = self._redacted_for_llm(evidence[:10])
        
        prompt = self.PROMPTS["report"].format(
            engagement=engagement_text,
            findings=findings_text,
            evidence=evidence_text,
        )
        
        return await self._call_llm(prompt, temperature=0.5)

    # -------------------------------------------------------------------------
    # AI-assisted analysis methods (statements only; never mutate findings)
    # -------------------------------------------------------------------------

    async def triage_false_positives(
        self,
        findings: List[Dict[str, Any]],
        evidence: Optional[List[Dict[str, Any]]] = None,
        batch_size: int = 20,
        max_batches: int = 10
    ) -> List[AIStatement]:
        """Ask the LLM for false-positive hypotheses about scan findings.

        Returns HYPOTHESIS statements only.  Findings are never reclassified
        by the AI - deterministic validation stays authoritative.

        Findings are sent in batches; ``statement.metadata`` carries both
        ``finding_index`` (position in ``findings``) and ``finding_id`` so
        callers can map a verdict back to the finding it refers to.
        """
        if not self._enabled or not findings:
            return []
        statements: List[AIStatement] = []
        for offset, batch in _batches(findings, batch_size, max_batches):
            payload = []
            for i, f in enumerate(batch):
                payload.append({
                    "finding_id": str(offset + i),
                    "type": f.get("type", ""),
                    "severity": f.get("severity", ""),
                    "url": f.get("url", ""),
                    "description": f.get("description", "")[:400],
                    "confidence": f.get("confidence", ""),
                    "state": f.get("state", ""),
                })
            prompt = self.PROMPTS["triage"].format(
                findings=self._redacted_for_llm(payload)
            )
            response = await self._call_llm(prompt, temperature=0.1)
            if not response:
                break
            data = extract_json(response)
            if not data:
                continue
            for verdict in data.get("verdicts", []):
                raw_id = verdict.get("finding_id", "")
                index = _as_global_index(raw_id, len(findings))
                v = verdict.get("verdict", "uncertain")
                statements.append(AIStatement(
                    content=(f"AI triage hypothesis for finding "
                             f"{raw_id if index is None else index}: {v} - "
                             f"{verdict.get('reason', '')}"),
                    reasoning_type=AIReasoningType.HYPOTHESIS,
                    confidence=float(verdict.get("confidence", 0.5)),
                    evidence_refs=[],
                    source_module="ai_triage",
                    metadata={
                        "finding_id": str(raw_id),
                        "finding_index": index,
                        "verdict": v,
                        "reason": verdict.get("reason", ""),
                    },
                ))
        return statements

    async def analyze_recon(
        self,
        discovery: Dict[str, Any]
    ) -> List[AIStatement]:
        """Summarize recon data and suggest next assessment steps."""
        if not self._enabled or not discovery:
            return []
        recon_payload = {
            k: discovery.get(k, [])[:30]
            for k in ("urls", "subdomains", "technologies", "ports",
                      "emails", "open_ports")
            if discovery.get(k)
        }
        prompt = self.PROMPTS["recon"].format(
            recon=self._redacted_for_llm(recon_payload)
        )
        response = await self._call_llm(prompt, temperature=0.2)
        if not response:
            return []
        try:
            data = extract_json(response)
            if not data:
                return []
        except json.JSONDecodeError:
            return []
        statements = []
        if data.get("summary"):
            statements.append(AIStatement(
                content=data["summary"],
                reasoning_type=AIReasoningType.INFERENCE,
                confidence=0.6,
                source_module="ai_recon",
            ))
        for obs in data.get("observations", [])[:10]:
            statements.append(AIStatement(
                content=obs,
                reasoning_type=AIReasoningType.HYPOTHESIS,
                confidence=0.5,
                source_module="ai_recon",
            ))
        for step in data.get("suggested_steps", [])[:10]:
            statements.append(AIStatement(
                content=step.get("step", ""),
                reasoning_type=AIReasoningType.RECOMMENDATION,
                confidence=0.6,
                source_module="ai_recon",
                metadata={"priority": step.get("priority", "medium")},
            ))
        return statements

    async def suggest_next_steps(
        self,
        findings: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> List[AIStatement]:
        """Suggest next assessment steps from current findings/context."""
        if not self._enabled:
            return []
        ctx = dict(context or {})
        ctx["finding_count"] = len(findings)
        ctx["severity_breakdown"] = {
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
        }
        prompt = self.PROMPTS["next_steps"].format(
            context=self._redacted_for_llm(ctx)
        )
        response = await self._call_llm(prompt, temperature=0.2)
        if not response:
            return []
        try:
            data = extract_json(response)
            if not data:
                return []
        except json.JSONDecodeError:
            return []
        statements = []
        for step in data.get("steps", [])[:10]:
            statements.append(AIStatement(
                content=step.get("step", ""),
                reasoning_type=AIReasoningType.RECOMMENDATION,
                confidence=0.6,
                source_module="ai_next_steps",
                metadata={"priority": step.get("priority", "medium"),
                          "reason": step.get("reason", "")},
            ))
        return statements

    async def validate_post_exploitation(
        self,
        phase_results: Dict[str, Any],
        hidden_files: List[Dict[str, Any]] = None,
        backup_files: List[Dict[str, Any]] = None,
        misconfigurations: List[Dict[str, Any]] = None,
    ) -> List[AIStatement]:
        """Validate post-exploitation results with focus on hidden directories,
        backup files, and security misconfigurations."""
        if not self._enabled:
            return []
        phase_text = self._redacted_for_llm(phase_results)
        hidden_text = self._redacted_for_llm(hidden_files or [])
        backup_text = self._redacted_for_llm(backup_files or [])
        misconfig_text = self._redacted_for_llm(misconfigurations or [])
        prompt = self.PROMPTS["post_exploitation_validation"].format(
            phase_results=phase_text,
            hidden_files_found=hidden_text,
            backup_files_found=backup_text,
            misconfigurations_found=misconfig_text,
        )
        response = await self._call_llm(prompt, temperature=0.1)
        if not response:
            return []
        try:
            data = extract_json(response)
            if not data:
                return []
        except json.JSONDecodeError:
            return []
        statements = []
        for item in data.get("validated_items", []):
            statements.append(AIStatement(
                content=f"Post-exploitation validation: {item.get('item', '')} - {item.get('status', 'UNKNOWN')}",
                reasoning_type=AIReasoningType.FACT if item.get("status") == "CONFIRMED" else AIReasoningType.INFERENCE,
                confidence=item.get("confidence", 0.5),
                evidence_refs=[],
                source_module="ai_post_exploitation_validation",
                metadata=item,
            ))
        for hd in data.get("hidden_directory_exploitation", []):
            statements.append(AIStatement(
                content=f"Hidden directory exploitation: {hd.get('directory', '')}",
                reasoning_type=AIReasoningType.FACT,
                confidence=0.95,
                evidence_refs=[],
                source_module="ai_hidden_directory_exploitation",
                metadata=hd,
            ))
        for bf in data.get("backup_file_exploitation", []):
            statements.append(AIStatement(
                content=f"Backup file exploitation: {bf.get('file', '')} - credentials extracted",
                reasoning_type=AIReasoningType.FACT,
                confidence=0.95,
                evidence_refs=[],
                source_module="ai_backup_file_exploitation",
                metadata=bf,
            ))
        for mi in data.get("misconfiguration_exploitation", []):
            statements.append(AIStatement(
                content=f"Misconfiguration exploitation: {mi.get('misconfig', '')} at {mi.get('path', '')}",
                reasoning_type=AIReasoningType.FACT,
                confidence=0.9,
                evidence_refs=[],
                source_module="ai_misconfiguration_exploitation",
                metadata=mi,
            ))
        return statements

    async def validate_hidden_assets(
        self,
        hidden_asset_data: Dict[str, Any],
    ) -> List[AIStatement]:
        """Validate hidden directories and backup files found during scanning."""
        if not self._enabled:
            return []
        hidden_text = self._redacted_for_llm(hidden_asset_data)
        prompt = self.PROMPTS["hidden_asset_scanner"].format(
            target_url=hidden_asset_data.get("target", ""),
            baseline_body=hidden_asset_data.get("baseline_body", ""),
            baseline_length=hidden_asset_data.get("baseline_length", 0),
        )
        response = await self._call_llm(prompt, temperature=0.1)
        if not response:
            return []
        try:
            data = extract_json(response)
            if not data:
                return []
        except json.JSONDecodeError:
            return []
        statements = []
        for hd in data.get("hidden_directories", []):
            statements.append(AIStatement(
                content=f"Hidden directory found: {hd.get('path', '')} — {hd.get('what_it_leaks', '')}",
                reasoning_type=AIReasoningType.FACT,
                confidence=0.95,
                evidence_refs=[],
                source_module="ai_hidden_directory_discovery",
                metadata=hd,
            ))
        for bf in data.get("backup_files", []):
            statements.append(AIStatement(
                content=f"Backup file found: {bf.get('path', '')} — contains plaintext credentials",
                reasoning_type=AIReasoningType.FACT,
                confidence=0.95,
                evidence_refs=[],
                source_module="ai_backup_file_discovery",
                metadata=bf,
            ))
        for mi in data.get("misconfigurations", []):
            statements.append(AIStatement(
                content=f"Misconfiguration found: {mi.get('type', '')} at {mi.get('path', '')}",
                reasoning_type=AIReasoningType.FACT,
                confidence=0.9,
                evidence_refs=[],
                source_module="ai_misconfiguration_discovery",
                metadata=mi,
            ))
        return statements

    async def analyze_misconfigurations(
        self,
        security_headers: Dict[str, Any],
        http_method_results: Dict[str, Any],
        misconfigurations: List[Dict[str, Any]],
    ) -> List[AIStatement]:
        """Analyze security misconfigurations including CORS, HTTP methods, verbose errors."""
        if not self._enabled:
            return []
        headers_text = self._redacted_for_llm(security_headers)
        methods_text = self._redacted_for_llm(http_method_results)
        misconfig_text = self._redacted_for_llm(misconfigurations)
        prompt = self.PROMPTS["aggressive_confirmation"].format(
            hidden_asset_scan_results=headers_text,
            security_headers_response=methods_text,
            http_method_test_results=misconfig_text,
        )
        response = await self._call_llm(prompt, temperature=0.1)
        if not response:
            return []
        try:
            data = extract_json(response)
            if not data:
                return []
        except json.JSONDecodeError:
            return []
        statements = []
        for mf in data.get("misconfiguration_confirmations", []):
            statements.append(AIStatement(
                content=f"Misconfiguration confirmed: {mf.get('type', '')} at {mf.get('path', '')}",
                reasoning_type=AIReasoningType.FACT,
                confidence=0.95,
                evidence_refs=[],
                source_module="ai_misconfiguration_confirmation",
                metadata=mf,
            ))
        for hdc in data.get("hidden_directory_confirmations", []):
            statements.append(AIStatement(
                content=f"Hidden directory confirmed: {hdc.get('path', '')}",
                reasoning_type=AIReasoningType.FACT,
                confidence=0.95,
                evidence_refs=[],
                source_module="ai_hidden_directory_confirmation",
                metadata=hdc,
            ))
        for bfc in data.get("backup_file_confirmations", []):
            statements.append(AIStatement(
                content=f"Backup file confirmed: {bfc.get('path', '')}",
                reasoning_type=AIReasoningType.FACT,
                confidence=0.95,
                evidence_refs=[],
                source_module="ai_backup_file_confirmation",
                metadata=bfc,
            ))
        for vf in data.get("validated_findings", []):
            if vf.get("status") == "CONFIRMED_TRUE_POSITIVE":
                statements.append(AIStatement(
                    content=f"Confirmed: {vf.get('type', '')} at {vf.get('url', '')}",
                    reasoning_type=AIReasoningType.FACT,
                    confidence=vf.get("confidence", 0.95),
                    evidence_refs=[],
                    source_module="ai_aggressive_confirmation",
                    metadata=vf,
                ))
        return statements

    async def prioritize_bruteforce_targets(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use AI to prioritize and filter bruteforce targets for maximum efficiency.
        
        Returns targets in priority order, filtering out low-value targets
        and suggesting optimal attack strategies.
        """
        if not self.enabled or not targets:
            return targets

        # Prepare target summary for AI
        target_summary = []
        for i, t in enumerate(targets[:20]):  # Limit to top 20 for AI analysis
            url = t.get('url', '')
            form_type = t.get('form_type', 'unknown')
            source = t.get('source', '')
            priority = t.get('priority', 'medium')
            target_summary.append({
                'index': i,
                'url': url,
                'form_type': form_type,
                'source': source,
                'priority': priority
            })

        prompt = f"""Analyze these login form targets and return a JSON object with:
        1. "prioritized_indices": array of indices sorted by attack priority (highest first)
        2. "skip_indices": array of indices that should be skipped (low value)
        3. "reasons": object mapping index to priority reason

        Consider:
        - Admin panels (cPanel, WHM, webmail) are HIGH priority
        - CMS admin panels (WordPress, Joomla) are MEDIUM-HIGH priority  
        - Registration/signup forms should be skipped
        - Public login forms are lower priority
        - Forms with email fields may be vulnerable to account enumeration

        Targets: {json.dumps(target_summary, indent=2)}

        Return ONLY valid JSON, no other text."""

        try:
            response = await self._call_llm(prompt, temperature=0.1)
            if not response:
                return targets
            
            data = extract_json(response)
            if not data:
                return targets
            
            prioritized_indices = data.get("prioritized_indices", list(range(len(targets))))
            skip_indices = set(data.get("skip_indices", []))
            reasons = data.get("reasons", {})
            
            # Rebuild target list in priority order, skipping low-value targets
            result = []
            for idx in prioritized_indices:
                if idx < len(targets) and idx not in skip_indices:
                    target = targets[idx].copy()
                    target['ai_priority_reason'] = reasons.get(str(idx), '')
                    result.append(target)
            
            # Add any targets not in the prioritized list (in case AI missed some)
            seen_indices = set(prioritized_indices)
            for i, target in enumerate(targets):
                if i not in seen_indices and i not in skip_indices:
                    result.append(target)
            
            return result if result else targets
            
        except Exception as e:
            logger.warning(f"AI prioritization failed: {e}")
            return targets

    async def validate_findings(
        self,
        findings: List[Dict[str, Any]],
        batch_size: int = 20,
        max_batches: int = 10,
    ) -> Optional['AICorrelationResult']:
        """Validate findings using AI to identify potential false positives.

        Findings are sent to the LLM in batches of ``batch_size`` (at most
        ``batch_size * max_batches`` items), each carrying its global
        ``finding_index``.  Verdicts become HYPOTHESIS statements only -
        deterministic validation stays authoritative and no finding is ever
        reclassified by this method.
        """
        if not self.enabled or not findings:
            return None

        statements: List[AIStatement] = []
        covered = 0
        total = len(findings)

        for offset, batch in _batches(findings, batch_size, max_batches):
            payload = []
            for i, f in enumerate(batch):
                payload.append({
                    "finding_index": offset + i,
                    "type": f.get("type", ""),
                    "severity": f.get("severity", ""),
                    "url": f.get("url", ""),
                    "payload": str(f.get("payload", ""))[:200],
                    "description": str(f.get("description", ""))[:300],
                })

            prompt = f"""Analyze these security findings and determine which are likely TRUE positives vs FALSE POSITIVES.

For each finding, consider:
1. Does the URL/response evidence support the vulnerability claim?
2. Is the payload actually present in the confirmed URL?
3. Are the detection indicators reliable (not just HTTP 200)?
4. Could this be a normal application behavior being misidentified?

Findings to validate (echo the exact "finding_index" value for each verdict):
{self._redacted_for_llm(payload)}

Return a JSON object with:
{{
  "validated_findings": [
    {{
      "finding_index": 0,
      "verdict": "true_positive|likely_false_positive|uncertain",
      "confidence": 0.0-1.0,
      "reasoning": "explanation"
    }}
  ]
}}

Focus on:
- SQL Injection: Verify actual database error messages or timing delays
- SSRF: Verify actual internal service access (not just HTTP 200)
- LDAP/XPath: Verify actual authentication bypass evidence
- XSS: Verify actual script execution context

Return ONLY valid JSON."""

            response = await self._call_llm(prompt, temperature=0.1)
            if not response:
                break
            covered = offset + len(batch)
            data = extract_json(response)
            if not data:
                continue

            for v in data.get("validated_findings", []):
                verdict = v.get("verdict", "uncertain")
                confidence = float(v.get("confidence", 0.5))
                # Providers are inconsistent: the prompt asks for
                # "reasoning" but models often answer with "reason".
                reasoning = str(v.get("reasoning") or v.get("reason") or "")
                finding_index = _as_global_index(v.get("finding_index"), total)

                # Only create statements for likely false positives
                if verdict == "likely_false_positive":
                    statements.append(AIStatement(
                        content=(
                            f"AI validation: Finding #{finding_index} is "
                            f"likely a false positive. {reasoning}"
                        ),
                        reasoning_type=AIReasoningType.HYPOTHESIS,
                        confidence=confidence,
                        source_module="ai_finding_validation",
                        metadata={
                            "verdict": verdict,
                            "finding_index": finding_index,
                            "finding_id": str(finding_index),
                            "reasoning": reasoning,
                        },
                    ))

        return AICorrelationResult(
            correlation_type=AICorrelationType.VALIDATION,
            statements=statements,
            input_findings=[str(f.get("id", offset_i))
                            for offset_i, f in enumerate(findings[:covered])],
            output_findings=[],
            confidence=0.7,
            reasoning=(
                f"AI false-positive hypotheses for {covered}/{total} finding(s) "
                "(advisory only; deterministic validation remains authoritative)"
            ),
        )


# ============================================================================
# AI-ASSISTED ANALYSIS (statements only - never deterministic truth)
# ============================================================================


async def ensemble_triage(findings: List[Dict[str, Any]],
                          evidence: Optional[List[Dict[str, Any]]] = None
                          ) -> List[AIStatement]:
    """Run false-positive triage across every configured provider.

    Statements from each provider are merged and tagged with their
    provider.  With zero keys configured, returns an empty list.
    """
    statements: List[AIStatement] = []
    for provider in configured_providers():
        try:
            engine = AIIntegration(provider=provider)
            if not engine.enabled:
                continue
            stmts = await engine.triage_false_positives(findings, evidence)
            for stmt in stmts:
                stmt.metadata["provider"] = provider.value
            statements.extend(stmts)
        except Exception:  # nosec B112
            continue
    return statements


# ============================================================================
# FACTORY FUNCTION
# ============================================================================


def create_ai_integration(api_key: str = "", model: str = "") -> AIIntegration:
    """Create an AI integration instance.

    Provider is resolved from ``ATHENA_AI_PROVIDER``, then from whichever
    key is configured (GEMINI → GROQ → DEEPSEEK).  An explicitly passed
    ``api_key`` defaults to the Gemini backend for backwards compatibility.
    """
    return AIIntegration(api_key=api_key, model=model)
