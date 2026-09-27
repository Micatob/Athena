"""
Athena Controlled Lateral-Assessment Model
==========================================
Determines whether an already-compromised (authorized foothold) asset
*potentially* provides access to additional in-scope assets, under an
explicit state machine.  Unrestricted autonomous propagation is never
implemented: each step requires its own recorded transition, and
**reachability is never treated as authorization**.

Explicit state model::

    DISCOVERED
        ↓  (explicit scope rule match)
    IN_SCOPE
        ↓  (deterministic reachability basis from the foothold)
    ASSESSABLE
        ↓  (explicit operator authorization for validation)
    AUTHORIZED_FOR_VALIDATION
        ↓  (validated evidence, e.g. confirmed credential)
    VALIDATED

Every transition is recorded with a timestamp, actor and reason.
A candidate that fails scope checking stays ``DISCOVERED`` with the
denial recorded as metadata; it cannot advance by reachability alone.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from modules.engagement import Engagement

# ============================================================================
# STATE MODEL
# ============================================================================


class LateralState(Enum):
    DISCOVERED = "discovered"
    IN_SCOPE = "in_scope"
    ASSESSABLE = "assessable"
    AUTHORIZED_FOR_VALIDATION = "authorized_for_validation"
    VALIDATED = "validated"


#: Legal forward transitions.  Anything not listed is rejected, mirroring
#: the finding lifecycle pattern in ``modules.findings.py``.
LATERAL_TRANSITIONS: Dict[LateralState, frozenset] = {
    LateralState.DISCOVERED: frozenset({LateralState.IN_SCOPE}),
    LateralState.IN_SCOPE: frozenset({LateralState.ASSESSABLE}),
    LateralState.ASSESSABLE: frozenset({LateralState.AUTHORIZED_FOR_VALIDATION}),
    LateralState.AUTHORIZED_FOR_VALIDATION: frozenset({LateralState.VALIDATED}),
    LateralState.VALIDATED: frozenset(),
}

VALID_LATERAL_STATES: Dict[str, LateralState] = {
    s.value: s for s in LateralState
}


@dataclass
class LateralCandidate:
    """One lateral-assessment candidate target discovered from a foothold."""

    engagement_id: str
    source_session_id: str      # foothold that surfaced the candidate
    target: str
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:16])
    state: LateralState = LateralState.DISCOVERED
    reachable: bool = False                 # reachability is evidence, NEVER authorization
    reachability_source: str = ""           # module that observed reachability
    scope_decision: str = ""                # recorded ScopeDecision value
    validation_evidence_id: str = ""
    timeline: List[Dict[str, str]] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = field(default_factory=dict)

    def _touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def transition(self, new_state: LateralState,
                   reason: str = "", actor: str = "") -> bool:
        """Attempt a state transition; returns False when invalid.

        Every accepted transition is recorded on the timeline.
        """
        allowed = LATERAL_TRANSITIONS.get(self.state, frozenset())
        if new_state not in allowed and new_state != self.state:
            return False
        previous = self.state
        self.state = new_state
        self.timeline.append({
            "at": datetime.now(timezone.utc).isoformat(),
            "from": previous.value,
            "to": new_state.value,
            "actor": actor,
            "reason": reason,
        })
        self._touch()
        return True

    @property
    def currently_authorized(self) -> bool:
        """An operator decision has authorized validation only at this state
        (and beyond).  Reachability or scope alone never authorize anything."""
        return self.state in (
            LateralState.AUTHORIZED_FOR_VALIDATION, LateralState.VALIDATED
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "source_session_id": self.source_session_id,
            "target": self.target,
            "state": self.state.value,
            "reachable": self.reachable,
            "reachability_source": self.reachability_source,
            "scope_decision": self.scope_decision,
            "validation_evidence_id": self.validation_evidence_id,
            "timeline": list(self.timeline),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LateralCandidate":
        return cls(
            id=data.get("id", str(uuid.uuid4())[:16]),
            engagement_id=data.get("engagement_id", ""),
            source_session_id=data.get("source_session_id", ""),
            target=data.get("target", ""),
            state=VALID_LATERAL_STATES.get(
                data.get("state", "discovered"), LateralState.DISCOVERED
            ),
            reachable=bool(data.get("reachable", False)),
            reachability_source=data.get("reachability_source", ""),
            scope_decision=data.get("scope_decision", ""),
            validation_evidence_id=data.get("validation_evidence_id", ""),
            timeline=[dict(t) for t in data.get("timeline", [])],
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            metadata=dict(data.get("metadata", {})),
        )


# ============================================================================
# ENGINE
# ============================================================================


class LateralAssessmentEngine:
    """Fail-closed registry driving the lateral-assessment state machine.

    Every candidate is bound to one engagement; scope and technique gates
    are re-checked at each advance so a revoked engagement stops the
    pipeline immediately.
    """

    def __init__(self, engagement: Optional[Engagement] = None):
        self.engagement = engagement
        self.candidates: Dict[str, LateralCandidate] = {}

    # -- candidate creation -------------------------------------------------

    def consider(self, source_session_id: str, target: str,
                 reachable: bool = False,
                 reachability_source: str = "") -> LateralCandidate:
        """Register a candidate target surfaced from a foothold.

        Fail-closed: without an engagement, ``consider`` denies creation.
        The candidate starts ``DISCOVERED``; a proven scope match advances
        it to ``IN_SCOPE``.  Reachability only records evidence - it never
        advances state on its own.
        """
        if self.engagement is None:
            raise ValueError(
                "cannot assess lateral target without an engagement "
                "(Athena fails closed)"
            )
        candidate = LateralCandidate(
            engagement_id=self.engagement.id,
            source_session_id=source_session_id,
            target=target,
            reachable=reachable,
            reachability_source=reachability_source,
        )
        check = self.engagement.check_target(target)
        candidate.scope_decision = check.decision.value
        if check.allowed:
            candidate.transition(
                LateralState.IN_SCOPE, reason=check.reason, actor="scope_engine"
            )
        else:
            candidate.metadata["scope_denial"] = check.to_dict()
        self.candidates[candidate.id] = candidate
        return candidate

    # -- explicit transitions ----------------------------------------------

    def mark_reachable(self, candidate_id: str,
                       reachability_source: str) -> Optional[LateralCandidate]:
        """Record reachability *evidence* without changing state.

        Deliberately a metadata-only operation: reachability never equals
        authorization in this model.
        """
        candidate = self.candidates.get(candidate_id)
        if candidate is None:
            return None
        candidate.reachable = True
        candidate.reachability_source = reachability_source
        candidate._touch()
        return candidate

    def transition_to_assessable(self, candidate_id: str,
                                 actor: str = "assessment",
                                 reason: str = "") -> bool:
        """Advance ``IN_SCOPE`` → ``ASSESSABLE``.

        Requires an in-scope candidate *and* a recorded reachability basis
        from the compromised asset.  Reachability alone is insufficient
        (scope is checked first); scope alone is insufficient (reachability
        evidence is required).
        """
        candidate = self.candidates.get(candidate_id)
        if candidate is None:
            return False
        if candidate.state != LateralState.IN_SCOPE:
            return False
        if not candidate.reachable:
            return False
        return candidate.transition(
            LateralState.ASSESSABLE,
            reason=reason or f"reachable from foothold ({candidate.reachability_source})",
            actor=actor,
        )

    def authorize_for_validation(self, candidate_id: str,
                                 operator: str = "",
                                 authorization_ref: str = "") -> bool:
        """Explicit operator authorization: ``ASSESSABLE`` →
        ``AUTHORIZED_FOR_VALIDATION``.

        This is the only way a candidate becomes authorized, re-checking
        the engagement's technique gate.  Reachability is never sufficient.
        """
        candidate = self.candidates.get(candidate_id)
        if candidate is None:
            return False
        if candidate.state != LateralState.ASSESSABLE:
            return False
        if not operator.strip():
            return False
        if self.engagement is not None:
            from modules.engagement import Technique
            gate = self.engagement.can_use(
                Technique.LATERAL_ASSESSMENT.value, candidate.target)
            if not gate.allowed:
                candidate.metadata["authorization_denial"] = gate.to_dict()
                candidate._touch()
                return False
        return candidate.transition(
            LateralState.AUTHORIZED_FOR_VALIDATION,
            reason=(f"operator {operator!r} authorized validation"
                    + (f" (ref {authorization_ref})" if authorization_ref else "")),
            actor=operator,
        )

    def validate(self, candidate_id: str,
                 evidence: Any, actor: str = "validation") -> bool:
        """``AUTHORIZED_FOR_VALIDATION`` → ``VALIDATED`` with validated evidence.

        Mirrors ``Finding.mark_confirmed``: only evidence whose
        ``validation_state`` is CONFIRMED may advance the candidate.
        """
        candidate = self.candidates.get(candidate_id)
        if candidate is None:
            return False
        if candidate.state != LateralState.AUTHORIZED_FOR_VALIDATION:
            return False
        from modules.findings import ValidationState
        if getattr(evidence, "validation_state", None) != ValidationState.CONFIRMED:
            candidate.metadata["validation_denial"] = {
                "reason": "evidence is not validation-state CONFIRMED",
                "evidence_id": getattr(evidence, "id", ""),
            }
            candidate._touch()
            return False
        if not candidate.transition(
                LateralState.VALIDATED,
                reason="validation evidence confirmed",
                actor=actor):
            return False
        candidate.validation_evidence_id = getattr(evidence, "id", "")
        return True

    # -- queries ------------------------------------------------------------

    def get(self, candidate_id: str) -> Optional[LateralCandidate]:
        return self.candidates.get(candidate_id)

    def list(self, state: Optional[LateralState] = None,
             engagement_id: str = "") -> List[LateralCandidate]:
        items = self.candidates.values()
        if engagement_id:
            items = (c for c in items if c.engagement_id == engagement_id)
        if state:
            items = (c for c in items if c.state == state)
        return sorted(items, key=lambda c: c.created_at)

    def summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {s.value: 0 for s in LateralState}
        for candidate in self.candidates.values():
            counts[candidate.state.value] += 1
        return {
            "engagement_id": self.engagement.id if self.engagement else "",
            "total": len(self.candidates),
            "states": counts,
            "authorized_for_validation": sum(
                1 for c in self.candidates.values() if c.currently_authorized
            ),
        }
