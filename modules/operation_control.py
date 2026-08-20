"""
Athena Safety & Operator Control
================================
Explicit operator controls for sensitive assessment operations.

An :class:`OperationGate` wraps an operation with:
* authorization requirement (engagement must exist and be valid)
* scope check (target must be provably in scope - fail closed)
* capability check (technique must be allowed by the engagement)
* confirmation requirement where appropriate (e.g. persistence,
  controlled validation, lateral assessment)
* audit logging (every decision is written to the compliance audit log)
* timeout enforcement
* rate limiting (per engagement / operator)
* cancellation
* cleanup hookup (temporary artifacts registered for verified cleanup)

Before anything runs, :meth:`OperationGate.explain` renders a visible
explanation of:

* WHAT Athena is about to do
* WHY it is doing it
* WHICH TARGET it will affect
* WHETHER that target is in scope
* WHAT EVIDENCE it expects to obtain

The gate never executes anything itself - it only decides and reports.
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .orchestration import StageState, StructuredError
from .logging_config import audit_operation

# ============================================================================
# OPERATION PLAN
# ============================================================================


@dataclass
class OperationPlan:
    """A preflight description of one sensitive operation."""

    action: str  # WHAT
    rationale: str  # WHY
    target: str  # WHICH TARGET
    expected_evidence: List[str] = field(default_factory=list)
    technique: str = ""  # Technique enum value
    requires_confirmation: bool = False
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    in_scope: Optional[bool] = None
    scope_reason: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def explain(self) -> str:
        """Human-readable preflight explanation (WHAT/WHY/TARGET/IN SCOPE/
        EXPECTED EVIDENCE)."""
        scope = (
            "YES (in scope)"
            if self.in_scope is True
            else (
                "NO (out of scope or unproven)"
                if self.in_scope is False
                else "UNVERIFIED"
            )
        )
        lines = [
            "PREFLIGHT OPERATION EXPLANATION",
            "  WHAT:              " + self.action,
            "  WHY:               " + self.rationale,
            "  TARGET:            " + self.target,
            "  TARGET IN SCOPE:   " + scope,
            "  EXPECTED EVIDENCE: " + (
                "; ".join(self.expected_evidence)
                if self.expected_evidence else "none"
            ),
        ]
        if self.scope_reason:
            lines.append("  SCOPE REASON:      " + self.scope_reason)
        if self.technique:
            lines.append("  TECHNIQUE:         " + self.technique)
        if self.requires_confirmation:
            lines.append("  CONFIRMATION:      REQUIRED (operator decision)")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "rationale": self.rationale,
            "target": self.target,
            "technique": self.technique,
            "requires_confirmation": self.requires_confirmation,
            "in_scope": self.in_scope,
            "scope_reason": self.scope_reason,
            "expected_evidence": list(self.expected_evidence),
            "created_at": self.created_at,
        }


# ============================================================================
# OPERATION GATE
# ============================================================================

GateDecision = StageState


@dataclass
class AuthorizationResult:
    """Outcome of an authorization attempt."""

    allowed: bool
    state: StageState
    reason: str = ""
    plan: Optional[OperationPlan] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "state": self.state.value,
            "reason": self.reason,
            "plan": self.plan.to_dict() if self.plan else None,
        }


class OperationGate:
    """Fail-closed gate enforcing safety and operator controls."""

    def __init__(
        self,
        engagement=None,
        operator: str = "",
        rate_limiter=None,
        audit=None,
        confirmation_policy=None,
        cleanup=None,
    ):
        self.engagement = engagement
        self.operator = operator or "operator"
        self.rate_limiter = rate_limiter
        self.audit = audit
        self.confirmation_policy = confirmation_policy
        self.cleanup = cleanup
        self.granted_confirmations: set = set()

    # -- planning -----------------------------------------------------------

    def plan(
        self,
        action: str,
        rationale: str,
        target: str,
        technique: str = "",
        expected_evidence: Optional[List[str]] = None,
        requires_confirmation: bool = False,
    ) -> OperationPlan:
        plan = OperationPlan(
            action=action,
            rationale=rationale,
            target=target,
            technique=technique,
            expected_evidence=list(expected_evidence or []),
            requires_confirmation=requires_confirmation,
        )
        if self.engagement is not None:
            check = self.engagement.check_target(target)
            plan.in_scope = check.allowed
            plan.scope_reason = check.reason
        return plan

    def explain(self, plan: OperationPlan) -> str:
        return plan.explain()

    # -- authorization --------------------------------------------------------

    def authorize(
        self, plan: OperationPlan, confirmation: bool = False
    ) -> AuthorizationResult:
        """Run the full gate chain; returns the first denial encountered.

        Chain: engagement → scope → capability → confirmation → rate limit.
        """
        self._audit("OPERATION_AUTHORIZE_ATTEMPT", plan, "INITIATED",
                    authorization_decision="PENDING")

        if self.engagement is None:
            return self._deny(
                plan,
                StageState.BLOCKED_BY_POLICY,
                "no engagement established; Athena fails closed",
            )
        if not self.engagement.active or self.engagement.is_expired:
            return self._deny(
                plan, StageState.BLOCKED_BY_POLICY,
                "engagement is inactive or expired")

        if plan.in_scope is not True:
            return self._deny(
                plan,
                StageState.BLOCKED_BY_SCOPE,
                plan.scope_reason or "target is not provably in scope",
            )

        if plan.technique:
            gate = self.engagement.can_use(plan.technique, plan.target)
            if not gate.allowed:
                return self._deny(
                    plan, StageState.BLOCKED_BY_POLICY, gate.reason)

        if plan.requires_confirmation:
            if not confirmation and plan.id not in self.granted_confirmations:
                self._audit("OPERATION_CONFIRMATION_REQUIRED", plan, "DENIED",
                            authorization_decision="REQUIRES_AUTHORIZATION")
                return AuthorizationResult(
                    allowed=False,
                    state=StageState.REQUIRES_AUTHORIZATION,
                    reason="operator confirmation required",
                    plan=plan,
                )
            self.granted_confirmations.add(plan.id)

        if self.rate_limiter is not None:
            check = self.rate_limiter.check(
                self.engagement.id, self.operator, plan.action
            )
            if not check.allowed:
                return self._deny(
                    plan, StageState.BLOCKED_BY_POLICY, check.reason)

        self._audit("OPERATION_AUTHORIZED", plan, "SUCCESS",
                    authorization_decision="AUTHORIZED")
        return AuthorizationResult(
            allowed=True, state=StageState.RUNNING, reason="authorized",
            plan=plan)

    def _deny(
        self, plan: OperationPlan, state: StageState, reason: str
    ) -> AuthorizationResult:
        self._audit("OPERATION_DENIED", plan, "DENIED", reason,
                    authorization_decision="DENIED")
        return AuthorizationResult(
            allowed=False, state=state, reason=reason, plan=plan)

    def _audit(
        self, action: str, plan: OperationPlan, status: str, detail: str = "",
        authorization_decision: str = "", scope_decision: str = "",
    ) -> None:
        if self.audit is None:
            return
        try:
            audit_operation(
                self.audit,
                operator=self.operator,
                action=action,
                target=plan.target,
                result=status,
                engagement_id=(self.engagement.id
                               if self.engagement is not None else ""),
                module="operation_control",
                authorization_decision=authorization_decision,
                scope_decision=scope_decision or self._scope_value(plan),
                evidence_ref=plan.id,
                details=f"{plan.action}; {detail}",
            )
        except Exception:
            # audit failures must never block an authorized operation
            pass  # nosec B110

    @staticmethod
    def _scope_value(plan: OperationPlan) -> str:
        if plan.in_scope is True:
            return "in_scope"
        if plan.in_scope is False:
            return "blocked_by_scope"
        return "unverified"

    # -- guarded execution ----------------------------------------------------

    async def execute(
        self,
        plan: OperationPlan,
        fn: Callable[[], Awaitable[Any]],
        timeout_seconds: float = 0,
        confirmation: bool = False,
        cleanup_registrations: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run ``fn`` under the full gate; returns a structured outcome.

        Never raises for operational failures: the outcome carries
        ``state`` + optional ``error`` (a ``StructuredError`` dict).
        """
        decision = self.authorize(plan, confirmation=confirmation)
        if not decision.allowed:
            return {
                "allowed": False,
                "state": decision.state.value,
                "reason": decision.reason,
                "plan": plan.to_dict(),
                "error": StructuredError(
                    "OPERATION_BLOCKED",
                    decision.reason,
                    details={"state": decision.state.value},
                ).to_dict(),
            }

        if self.cleanup is not None and cleanup_registrations:
            for path in cleanup_registrations:
                self.cleanup.register(path)

        started = time.monotonic()
        try:
            task = fn()
            if timeout_seconds and timeout_seconds > 0:
                task = asyncio.wait_for(task, timeout=timeout_seconds)
            output = await task
            self._audit("OPERATION_COMPLETED", plan, "SUCCESS",
                        authorization_decision="AUTHORIZED")
            return {
                "allowed": True,
                "state": StageState.COMPLETED.value,
                "output": output,
                "plan": plan.to_dict(),
                "duration_seconds": round(time.monotonic() - started, 3),
            }
        except asyncio.TimeoutError:
            state, code = StageState.TIMEOUT, "OPERATION_TIMEOUT"
        except asyncio.CancelledError:
            state, code = StageState.CANCELLED, "OPERATION_CANCELLED"
        except StructuredError as exc:
            state, code = StageState.FAILED, exc.code
        except Exception:
            state, code = StageState.FAILED, "INTERNAL_ERROR"

        self._audit("OPERATION_FAILED", plan, "FAILED", code,
                    authorization_decision="AUTHORIZED")
        return {
            "allowed": False,
            "state": state.value,
            "reason": f"operation did not complete ({code})",
            "plan": plan.to_dict(),
            "duration_seconds": round(time.monotonic() - started, 3),
            "error": StructuredError(
                code,
                "operation failed",
                stage=plan.action,
                details={"state": state.value},
            ).to_dict(),
        }


def create_operation_gate(engagement=None, operator: str = "",
                          rate_limiter=None, audit=None,
                          cleanup=None) -> OperationGate:
    """Convenience factory for an operation gate."""
    return OperationGate(
        engagement=engagement,
        operator=operator,
        rate_limiter=rate_limiter,
        audit=audit,
        cleanup=cleanup,
    )
