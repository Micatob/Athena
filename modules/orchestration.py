"""
Athena Module Orchestration
===========================
Central orchestration mechanism for the assessment pipeline::

    ENGAGEMENT
        ↓ RECON
        ↓ ENUMERATION
        ↓ DISCOVERY
        ↓ SCANNING
        ↓ VALIDATION
        ↓ INITIAL ACCESS
        ↓ POST-EXPLOITATION ASSESSMENT
        ↓ ATTACK-PATH ANALYSIS
        ↓ IMPACT ASSESSMENT
        ↓ REPORTING

Every stage is independently executable - operators can run one module
without running the entire pipeline.  A failed stage never destroys the
engagement: its state becomes ``FAILED`` with a structured error, dependent
stages that need its outputs become ``BLOCKED_BY_POLICY``, and everything
else keeps running.
"""

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .logging_config import audit_operation

# ============================================================================
# STATES & STRUCTURED ERRORS
# ============================================================================


class StageState(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    BLOCKED_BY_SCOPE = "blocked_by_scope"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    REQUIRES_AUTHORIZATION = "requires_authorization"
    PARTIAL = "partial"


VALID_STAGE_STATES: Dict[str, StageState] = {s.value: s for s in StageState}


class StructuredError(Exception):
    """Error with a stable code so callers can react without parsing text."""

    def __init__(
        self,
        code: str,
        message: str,
        stage: str = "",
        details: Optional[Dict[str, Any]] = None,
        transient: bool = False,
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.stage = stage
        self.details = dict(details or {})
        self.transient = transient

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "stage": self.stage,
            "details": dict(self.details),
            "transient": self.transient,
        }


# ============================================================================
# STAGE REGISTRY
# ============================================================================


@dataclass(frozen=True)
class StageSpec:
    """Definition of one pipeline stage."""

    key: str
    name: str
    description: str = ""
    produces: tuple = ()  # artifact keys this stage produces
    requires: tuple = ()  # artifact keys this stage needs
    runnable_independently: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "produces": list(self.produces),
            "requires": list(self.requires),
            "runnable_independently": self.runnable_independently,
        }


#: Canonical ordered pipeline (PTES-aligned).
PIPELINE_STAGES: List[StageSpec] = [
    StageSpec(
        "engagement",
        "Engagement & Authorization",
        "Establish scope, authorization and operator identity.",
        produces=("engagement",),
        requires=(),
    ),
    StageSpec(
        "recon",
        "Reconnaissance",
        "Passive/open-source target discovery.",
        produces=("targets",),
        requires=("engagement",),
    ),
    StageSpec(
        "enumeration",
        "Enumeration",
        "Active service and asset enumeration on in-scope targets.",
        produces=("services",),
        requires=("targets",),
    ),
    StageSpec(
        "discovery",
        "Discovery",
        "Web crawling, fingerprinting, DNS/TLS and content discovery.",
        produces=("urls", "technologies", "ports"),
        requires=("targets",),
    ),
    StageSpec(
        "scanning",
        "Vulnerability Scanning",
        "Automated vulnerability tests against discovered surfaces.",
        produces=("vulnerabilities",),
        requires=("urls", "technologies"),
    ),
    StageSpec(
        "validation",
        "Validation",
        "Deterministic confirmation of candidate findings with " "evidence.",
        produces=("validated_findings",),
        requires=("vulnerabilities",),
    ),
    StageSpec(
        "initial_access",
        "Initial Access",
        "Controlled foothold under engagement authorization.",
        produces=("sessions",),
        requires=("validated_findings",),
    ),
    StageSpec(
        "post_exploitation_assessment",
        "Post-Exploitation Assessment",
        "Evidence-focused host/privilege/network assessment " "post-foothold.",
        produces=("assessment",),
        requires=("sessions",),
    ),
    StageSpec(
        "attack_path_analysis",
        "Attack-Path Analysis",
        "State-labeled graph of nodes, edges and confirmed paths.",
        produces=("attack_graph",),
        requires=("validated_findings", "sessions"),
    ),
    StageSpec(
        "impact_assessment",
        "Impact Assessment",
        "Deterministic impact and risk scoring of confirmed findings.",
        produces=("impact",),
        requires=("validated_findings",),
    ),
    StageSpec(
        "reporting",
        "Reporting",
        "Reproducible HTML/JSON/CSV/PDF reports with evidence.",
        produces=("report",),
        requires=("impact", "attack_graph"),
    ),
]

STAGE_BY_KEY: Dict[str, StageSpec] = {s.key: s for s in PIPELINE_STAGES}


# ============================================================================
# ORCHESTRATOR
# ============================================================================

StageRunner = Callable[[], Awaitable[Any]]


@dataclass
class StageResult:
    """Structured outcome of one stage execution."""

    stage_key: str
    state: StageState = StageState.QUEUED
    error: Optional[Dict[str, Any]] = None
    output: Any = None
    started_at: str = ""
    ended_at: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage_key,
            "state": self.state.value,
            "error": self.error,
            "duration_seconds": round(self.duration_seconds, 3),
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        }


class PipelineOrchestrator:
    """Runs pipeline stages with isolation, timeout and cancellation."""

    def __init__(self, engagement_id: str = "",
                 default_timeout_seconds: float = 0, audit=None):
        self.engagement_id = engagement_id
        self.default_timeout_seconds = default_timeout_seconds  # 0=no timeout
        self.audit = audit
        self.results: Dict[str, StageResult] = {}
        self.artifacts: Dict[str, Any] = {}
        self._cancel_event = asyncio.Event()
        self._timeline: List[Dict[str, str]] = []

    # -- lifecycle ----------------------------------------------------------

    def cancel(self, reason: str = "operator cancelled") -> None:
        self._cancel_event.set()
        self._timeline.append(
            {
                "at": datetime.now(timezone.utc).isoformat(),
                "event": "CANCEL_REQUESTED",
                "reason": reason,
            }
        )

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    # -- single-stage execution ---------------------------------------------

    async def run_stage(
        self,
        stage_key: str,
        runner: StageRunner,
        timeout_seconds: Optional[float] = None,
        requires_authorization: bool = False,
        in_scope: Optional[bool] = None,
    ) -> StageResult:
        """Execute one stage independently and capture its structured result.

        A stage can be run alone (``run_stage``) or as part of the pipeline
        (``run_pipeline``).  ``in_scope=False`` blocks it with
        ``BLOCKED_BY_SCOPE``; ``requires_authorization`` without a granted
        confirmation produces ``REQUIRES_AUTHORIZATION``.
        """
        spec = STAGE_BY_KEY.get(stage_key)
        result = StageResult(stage_key=stage_key)
        self.results[stage_key] = result

        if spec is None:
            result.state = StageState.FAILED
            result.error = StructuredError(
                "INVALID_STAGE_KEY",
                f"unknown stage {stage_key!r}",
                stage=stage_key,
            ).to_dict()
            result.ended_at = datetime.now(timezone.utc).isoformat()
            self._audit_stage(result)
            return result

        if spec is not None and not spec.runnable_independently:
            result.state = StageState.BLOCKED_BY_POLICY
            result.error = StructuredError(
                "STAGE_NOT_INDEPENDENT",
                f"stage {stage_key!r} cannot run standalone",
                stage=stage_key,
            ).to_dict()
            result.ended_at = datetime.now(timezone.utc).isoformat()
            self._audit_stage(result)
            return result

        if in_scope is False:
            result.state = StageState.BLOCKED_BY_SCOPE
            result.error = StructuredError(
                "BLOCKED_BY_SCOPE",
                f"target for stage {stage_key!r} is out of scope",
                stage=stage_key,
            ).to_dict()
            result.ended_at = datetime.now(timezone.utc).isoformat()
            self._audit_stage(result)
            return result

        if requires_authorization:
            result.state = StageState.REQUIRES_AUTHORIZATION
            result.error = StructuredError(
                "REQUIRES_AUTHORIZATION",
                f"stage {stage_key!r} needs explicit operator authorization",
                stage=stage_key,
            ).to_dict()
            result.ended_at = datetime.now(timezone.utc).isoformat()
            self._audit_stage(result)
            return result

        if self._cancel_event.is_set():
            result.state = StageState.CANCELLED
            result.ended_at = datetime.now(timezone.utc).isoformat()
            self._audit_stage(result)
            return result

        timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else self.default_timeout_seconds
        )
        result.state = StageState.RUNNING
        result.started_at = datetime.now(timezone.utc).isoformat()
        start = time.monotonic()

        try:
            task = runner()
            if timeout and timeout > 0:
                task = asyncio.wait_for(task, timeout=timeout)
            result.output = await task
            result.state = StageState.COMPLETED
            self._timeline.append(
                {
                    "at": datetime.now(timezone.utc).isoformat(),
                    "event": "STAGE_COMPLETED",
                    "stage": stage_key,
                }
            )
        except asyncio.TimeoutError:
            result.state = StageState.TIMEOUT
            result.error = StructuredError(
                "STAGE_TIMEOUT",
                f"stage {stage_key!r} exceeded {timeout}s",
                stage=stage_key,
                transient=True,
            ).to_dict()
        except asyncio.CancelledError:
            result.state = StageState.CANCELLED
            result.error = StructuredError(
                "STAGE_CANCELLED",
                f"stage {stage_key!r} was cancelled",
                stage=stage_key,
            ).to_dict()
        except StructuredError as exc:
            exc.stage = stage_key
            result.state = StageState.FAILED
            result.error = exc.to_dict()
        except Exception as exc:  # noqa: BLE001 - isolation boundary
            result.state = StageState.FAILED
            result.error = StructuredError(
                "INTERNAL_ERROR",
                str(exc),
                stage=stage_key,
            ).to_dict()

        result.ended_at = datetime.now(timezone.utc).isoformat()
        result.duration_seconds = time.monotonic() - start
        if (result.state == StageState.COMPLETED
                and spec is not None
                and isinstance(result.output, dict)):
            for artifact in spec.produces:
                if artifact in result.output:
                    self.artifacts[artifact] = result.output[artifact]
        self._audit_stage(result)
        return result

    def _audit_stage(self, result: StageResult) -> None:
        """Emit a structured STAGE_RUN audit event for the stage outcome."""
        if self.audit is None:
            return
        state = result.state
        scope = ""
        if state == StageState.BLOCKED_BY_SCOPE:
            auth, scope = "DENIED", "blocked_by_scope"
        elif state == StageState.REQUIRES_AUTHORIZATION:
            auth = "REQUIRES_AUTHORIZATION"
        elif state == StageState.CANCELLED:
            auth = "CANCELLED"
        elif state == StageState.BLOCKED_BY_POLICY:
            auth = "DENIED"
        else:
            auth = "AUTHORIZED"
            if state == StageState.COMPLETED:
                scope = "in_scope"
        code = (result.error or {}).get("code", "") if result.error else ""
        spec = STAGE_BY_KEY.get(result.stage_key)
        if state == StageState.COMPLETED and spec is not None:
            evidence = ", ".join(spec.produces)
        else:
            evidence = code
        try:
            audit_operation(
                self.audit,
                operator="athena",
                action="STAGE_RUN",
                target=result.stage_key,
                result=state.value,
                engagement_id=self.engagement_id,
                module="orchestration",
                authorization_decision=auth,
                scope_decision=scope,
                evidence_ref=evidence,
                details=code,
            )
        except Exception:
            # audit failures must never break pipeline execution
            pass  # nosec B110

    # -- pipeline execution ---------------------------------------------------

    async def run_pipeline(
        self, runners: Dict[str, StageRunner],
        stages: Optional[List[str]] = None,
    ) -> Dict[str, StageResult]:
        """Run the pipeline in canonical order with failure isolation.

        A failed stage never aborts the pipeline: unrelated stages still run.
        Stages whose required artifacts are missing become
        ``BLOCKED_BY_POLICY``.
        """
        order = stages or [s.key for s in PIPELINE_STAGES]
        for key in order:
            spec = STAGE_BY_KEY.get(key)
            if spec is None:
                self.results[key] = StageResult(
                    stage_key=key,
                    state=StageState.FAILED,
                    error=StructuredError(
                        "INVALID_STAGE_KEY",
                        f"unknown stage {key!r}",
                        stage=key,
                    ).to_dict(),
                )
                self._audit_stage(self.results[key])
                continue
            missing = [
                r
                for r in (spec.requires if spec else ())
                if r not in self.artifacts
                and r not in ("engagement", "targets")
            ]
            if missing and key != "engagement":
                self.results[key] = StageResult(
                    stage_key=key,
                    state=StageState.BLOCKED_BY_POLICY,
                    error=StructuredError(
                        "MISSING_DEPENDENCY",
                        f"stage {key!r} requires artifact(s) {missing}",
                        stage=key,
                    ).to_dict(),
                )
                self._audit_stage(self.results[key])
                continue

            runner = runners.get(key)
            if runner is None:
                self.results[key] = StageResult(
                    stage_key=key,
                    state=StageState.FAILED,
                    error=StructuredError(
                        "NO_RUNNER",
                        f"no runner registered for stage {key!r}",
                        stage=key,
                    ).to_dict(),
                )
                self._audit_stage(self.results[key])
                continue
            result = await self.run_stage(key, runner)
        return self.results

    # -- reporting -----------------------------------------------------------

    def report(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for result in self.results.values():
            key = result.state.value
            counts[key] = counts.get(key, 0) + 1
        return {
            "engagement_id": self.engagement_id,
            "stages": {k: v.to_dict() for k, v in self.results.items()},
            "state_counts": counts,
            "artifacts": list(self.artifacts.keys()),
            "cancelled": self._cancel_event.is_set(),
        }

    def get_stage(self, stage_key: str) -> Optional[StageResult]:
        return self.results.get(stage_key)


def stage_list() -> List[Dict[str, Any]]:
    """Public registry view (for CLI/API stage enumeration)."""
    return [s.to_dict() for s in PIPELINE_STAGES]
