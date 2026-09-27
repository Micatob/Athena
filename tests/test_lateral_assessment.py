"""
tests/test_lateral_assessment.py – Controlled lateral-assessment state model
=============================================================================
Covers:
  * DISCOVERED → IN_SCOPE advance when a scope rule matches
  * out-of-scope candidates stay DISCOVERED with the denial recorded
  * reachability is evidence only — it never advances state on its own
  * ASSESSABLE requires scope AND a reachability basis
  * AUTHORIZED_FOR_VALIDATION requires explicit operator authorization
  * VALIDATED requires validation-state CONFIRMED evidence
  * every transition recorded on the timeline
  * fail-closed: no engagement → candidate creation denied
"""

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.engagement import Engagement
from modules.findings import Evidence, EvidenceKind, ValidationState
from modules.lateral_assessment import (
    LateralAssessmentEngine,
    LateralState,
)


@pytest.fixture()
def engagement() -> Engagement:
    return Engagement(
        name="Lateral Test",
        operator="tester",
        in_scope_targets=["10.0.0.0/24"],
        include_subdomains=True,
    )


class TestDiscoveryAndScope:
    def test_consider_in_scope_target_advances(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9")
        assert candidate.state == LateralState.IN_SCOPE
        assert candidate.scope_decision == "allowed"

    def test_consider_out_of_scope_stays_discovered(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "192.168.99.99")
        assert candidate.state == LateralState.DISCOVERED
        assert candidate.metadata["scope_denial"]["decision"] == "not_in_scope"

    def test_consider_without_engagement_denied(self):
        engine = LateralAssessmentEngine()
        with pytest.raises(ValueError):
            engine.consider("sess-1", "10.0.0.9")


class TestReachability:
    def test_reachable_does_not_advance_state(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9")
        engine.mark_reachable(candidate.id, "route_table")
        assert candidate.reachable
        assert candidate.state == LateralState.IN_SCOPE

    def test_assessable_requires_reachability(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9")
        assert not engine.transition_to_assessable(candidate.id)
        assert candidate.state == LateralState.IN_SCOPE

    def test_out_of_scope_never_assessable_even_if_reachable(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "192.168.99.99", reachable=True)
        assert not engine.transition_to_assessable(candidate.id)
        assert candidate.state == LateralState.DISCOVERED

    def test_assessable_when_scope_and_reachability(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9")
        engine.mark_reachable(candidate.id, "route_table")
        assert engine.transition_to_assessable(candidate.id)
        assert candidate.state == LateralState.ASSESSABLE


class TestAuthorization:
    def test_authorization_requires_operator(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9")
        engine.mark_reachable(candidate.id, "route_table")
        engine.transition_to_assessable(candidate.id)
        assert not engine.authorize_for_validation(candidate.id, operator="")
        assert candidate.state == LateralState.ASSESSABLE

    def test_authorization_from_assessable(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9")
        engine.mark_reachable(candidate.id, "route_table")
        engine.transition_to_assessable(candidate.id)
        assert engine.authorize_for_validation(candidate.id, operator="analyst")
        assert candidate.state == LateralState.AUTHORIZED_FOR_VALIDATION

    def test_authorization_without_assessable_rejected(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9")
        engine.mark_reachable(candidate.id, "route_table")
        assert not engine.authorize_for_validation(candidate.id, operator="analyst")
        assert candidate.state == LateralState.IN_SCOPE

    def test_reachable_never_equals_authorized(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9", reachable=True)
        assert not candidate.currently_authorized
        assert candidate.state != LateralState.AUTHORIZED_FOR_VALIDATION


class TestValidation:
    def test_validate_requires_confirmed_evidence(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9", reachable=True)
        engine.transition_to_assessable(candidate.id)
        engine.authorize_for_validation(candidate.id, operator="analyst")
        weak = Evidence(engagement_id=engagement.id, target=candidate.target,
                        module="test", kind=EvidenceKind.HOST_OBSERVATION,
                        validation_state=ValidationState.UNVERIFIED)
        assert not engine.validate(candidate.id, weak)
        assert candidate.state == LateralState.AUTHORIZED_FOR_VALIDATION

    def test_validate_with_confirmed_evidence(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9", reachable=True)
        engine.transition_to_assessable(candidate.id)
        engine.authorize_for_validation(candidate.id, operator="analyst")
        proof = Evidence(engagement_id=engagement.id, target=candidate.target,
                         module="test", kind=EvidenceKind.HOST_OBSERVATION,
                         validation_state=ValidationState.CONFIRMED)
        assert engine.validate(candidate.id, proof)
        assert candidate.state == LateralState.VALIDATED
        assert candidate.validation_evidence_id == proof.id

    def test_validate_without_authorization_rejected(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9", reachable=True)
        engine.transition_to_assessable(candidate.id)
        proof = Evidence(engagement_id=engagement.id, target=candidate.target,
                         module="test", kind=EvidenceKind.HOST_OBSERVATION,
                         validation_state=ValidationState.CONFIRMED)
        assert not engine.validate(candidate.id, proof)
        assert candidate.state == LateralState.ASSESSABLE


class TestTransitionsAndSerialization:
    def test_invalid_transition_rejected(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9")
        assert not candidate.transition(LateralState.VALIDATED)
        assert candidate.state == LateralState.IN_SCOPE

    def test_every_transition_recorded(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9")
        engine.mark_reachable(candidate.id, "route_table")
        engine.transition_to_assessable(candidate.id)
        engine.authorize_for_validation(candidate.id, operator="analyst")
        proof = Evidence(engagement_id=engagement.id, target=candidate.target,
                         module="test", kind=EvidenceKind.HOST_OBSERVATION,
                         validation_state=ValidationState.CONFIRMED)
        engine.validate(candidate.id, proof)
        states = [(t["from"], t["to"]) for t in candidate.timeline]
        assert states == [
            ("discovered", "in_scope"),
            ("in_scope", "assessable"),
            ("assessable", "authorized_for_validation"),
            ("authorized_for_validation", "validated"),
        ]
        assert all(t["at"] and t["actor"] and t["reason"]
                   for t in candidate.timeline)

    def test_serialization_roundtrip(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        candidate = engine.consider("sess-1", "10.0.0.9")
        engine.mark_reachable(candidate.id, "route_table")
        engine.transition_to_assessable(candidate.id)
        data = candidate.to_dict()
        restored = type(candidate).from_dict(data)
        assert restored.state == LateralState.ASSESSABLE
        assert restored.timeline == candidate.timeline
        assert restored.reachable is True

    def test_summary_counts(self, engagement):
        engine = LateralAssessmentEngine(engagement)
        a = engine.consider("s-1", "10.0.0.9")
        b = engine.consider("s-2", "10.0.0.10")
        engine.mark_reachable(a.id, "route")
        engine.transition_to_assessable(a.id)
        assert engine.get(b.id).state == LateralState.IN_SCOPE
        summary = engine.summary()
        assert summary["total"] == 2
        assert summary["states"]["in_scope"] == 1
        assert summary["states"]["assessable"] == 1
        assert summary["authorized_for_validation"] == 0
