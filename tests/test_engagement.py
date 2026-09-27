"""
tests/test_engagement.py – Engagement & Scope Engine
=====================================================
Covers:
  * fail-closed behavior (no engagement / unknown target → denied)
  * hostname / subdomain / IP / CIDR / URL scope matching
  * exclusion precedence
  * technique allow/restrict lists
  * ad-hoc CLI engagement
  * persistence round-trip (EngagementStore)
  * expiry and confirmation requirements
"""

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.engagement import (
    DEFAULT_ALLOWED_TECHNIQUES,
    Engagement,
    EngagementStore,
    ScopeDecision,
    Technique,
    ad_hoc_engagement,
    load_engagement_file,
    normalize_target,
)


@pytest.fixture()
def engagement() -> Engagement:
    return Engagement(
        name="Test Engagement",
        operator="pentester@example.org",
        in_scope_targets=["example.com", "10.0.0.0/24", "https://portal.example.net"],
        exclusions=["10.0.0.5", "admin.example.com"],
        include_subdomains=True,
    )


class TestNormalization:
    def test_hostname(self):
        assert normalize_target("Example.COM")["kind"] == "hostname"
        assert normalize_target("Example.COM")["host"] == "example.com"

    def test_ip(self):
        assert normalize_target("10.1.2.3")["kind"] == "ip"

    def test_cidr(self):
        assert normalize_target("192.168.1.0/24")["kind"] == "cidr"

    def test_url(self):
        n = normalize_target("https://Sub.Example.com:8443/path?q=1")
        assert n["kind"] == "url"
        assert n["host"] == "sub.example.com"
        assert n["port"] == 8443

    def test_garbage(self):
        assert normalize_target("not a target !!")["kind"] == "hostname"


class TestScopeEnforcement:
    def test_in_scope_hostname(self, engagement):
        check = engagement.check_target("example.com")
        assert check.allowed

    def test_out_of_scope_hostname(self, engagement):
        check = engagement.check_target("evil.com")
        assert check.decision == ScopeDecision.NOT_IN_SCOPE
        assert not check.allowed

    def test_subdomain_in_scope_when_enabled(self, engagement):
        assert engagement.check_target("api.example.com").allowed

    def test_subdomain_not_in_scope_when_disabled(self):
        eng = Engagement(name="t", operator="o",
                         in_scope_targets=["example.com"],
                         include_subdomains=False)
        assert not eng.check_target("api.example.com").allowed

    def test_cidr_cover(self, engagement):
        assert engagement.check_target("10.0.0.200").allowed

    def test_ip_outside_cidr(self, engagement):
        assert not engagement.check_target("10.1.0.1").allowed

    def test_exclusion_wins(self, engagement):
        check = engagement.check_target("10.0.0.5")
        assert check.decision == ScopeDecision.EXCLUDED

    def test_exclusion_wins_over_domain(self, engagement):
        check = engagement.check_target("admin.example.com")
        assert check.decision == ScopeDecision.EXCLUDED

    def test_url_in_scope(self, engagement):
        assert engagement.check_target("https://portal.example.net/").allowed

    def test_unknown_url_out_of_scope(self, engagement):
        assert not engagement.check_target("https://evil.net/").allowed

    def test_unparseable_target_denied(self, engagement):
        check = engagement.check_target("")
        assert not check.allowed


class TestFailClosed:
    def test_no_engagement_denies_target(self):
        # A bare target check with no engagement context must not be
        # assumed in scope: use ad_hoc to prove explicit scoping works.
        eng = ad_hoc_engagement(["demo.org"])
        assert eng.check_target("demo.org").allowed
        assert not eng.check_target("other.org").allowed

    def test_ad_hoc_restricted_to_listed_targets(self):
        eng = ad_hoc_engagement(["a.com", "b.com"])
        assert eng.check_target("a.com").allowed
        assert eng.check_target("b.com").allowed
        assert not eng.check_target("c.com").allowed

    def test_empty_targets_engagement_invalid(self):
        eng = ad_hoc_engagement([])
        errors = eng.validate()
        assert any("in-scope" in e for e in errors)


class TestTechniqueGating:
    def test_allowed_technique(self, engagement):
        check = engagement.can_use(Technique.HOST_ASSESSMENT.value, "example.com")
        assert check.allowed

    def test_restricted_technique_denied(self):
        eng = Engagement(name="t", operator="o",
                         in_scope_targets=["example.com"],
                         restricted_techniques=[Technique.PERSISTENCE.value])
        check = eng.can_use(Technique.PERSISTENCE.value, "example.com")
        assert not check.allowed
        assert "restricted" in check.reason

    def test_restricted_beats_allowed_list(self):
        eng = Engagement(name="t", operator="o",
                         in_scope_targets=["example.com"],
                         allowed_techniques=["scanning"],
                         restricted_techniques=["scanning"])
        assert not eng.can_use("scanning", "example.com").allowed

    def test_technique_denied_when_not_listed(self):
        eng = Engagement(name="t", operator="o",
                         in_scope_targets=["example.com"],
                         allowed_techniques=["recon"])
        assert not eng.can_use(Technique.EXPLOITATION.value, "example.com").allowed

    def test_technique_allowed_without_target(self, engagement):
        check = engagement.can_use(Technique.RECON.value)
        assert check.allowed

    def test_out_of_scope_target_denied_with_technique(self, engagement):
        check = engagement.can_use(Technique.HOST_ASSESSMENT.value, "evil.com")
        assert not check.allowed
        assert check.decision == ScopeDecision.NOT_IN_SCOPE

    def test_confirmation_required_techniques(self, engagement):
        assert engagement.requires_confirmation(Technique.CLEANUP.value)
        assert engagement.requires_confirmation(Technique.PERSISTENCE.value)
        assert not engagement.requires_confirmation(Technique.RECON.value)

    def test_default_allowed_techniques_cover_assessment(self):
        for tech in (Technique.POST_EXPLOITATION.value,
                     Technique.HOST_ASSESSMENT.value,
                     Technique.PRIVILEGE_ASSESSMENT.value):
            assert tech in DEFAULT_ALLOWED_TECHNIQUES


class TestValidationAndExpiry:
    def test_valid_engagement_passes(self, engagement):
        assert engagement.validate() == []

    def test_missing_operator_invalid(self):
        eng = Engagement(name="t", operator="", in_scope_targets=["x.com"])
        assert any("operator" in e for e in eng.validate())

    def test_end_before_start_invalid(self):
        eng = Engagement(name="t", operator="o", in_scope_targets=["x.com"],
                         start_time="2026-01-02T00:00:00",
                         end_time="2026-01-01T00:00:00")
        assert any("end_time" in e for e in eng.validate())

    def test_expired_engagement(self):
        eng = Engagement(name="t", operator="o", in_scope_targets=["x.com"],
                         end_time="2020-01-01T00:00:00")
        assert eng.is_expired

    def test_future_engagement_not_expired(self):
        eng = Engagement(name="t", operator="o", in_scope_targets=["x.com"],
                         end_time="2099-01-01T00:00:00")
        assert not eng.is_expired


class TestStore:
    def test_round_trip(self, tmp_path):
        store = EngagementStore(str(tmp_path / "engagements.json"))
        eng = Engagement(name="t", operator="o", in_scope_targets=["x.com"])
        store.add(eng)
        loaded = EngagementStore(str(tmp_path / "engagements.json"))
        assert loaded.get(eng.id) is not None
        assert loaded.get(eng.id).name == "t"

    def test_add_rejects_invalid(self, tmp_path):
        store = EngagementStore(str(tmp_path / "engagements.json"))
        with pytest.raises(ValueError):
            store.add(Engagement(name="", operator="", in_scope_targets=[]))

    def test_remove(self, tmp_path):
        store = EngagementStore(str(tmp_path / "engagements.json"))
        eng = store.add(Engagement(name="t", operator="o",
                                   in_scope_targets=["x.com"]))
        assert store.remove(eng.id)
        assert store.get(eng.id) is None

    def test_active_filter(self, tmp_path):
        store = EngagementStore(str(tmp_path / "engagements.json"))
        store.add(Engagement(name="active", operator="o",
                             in_scope_targets=["a.com"]))
        expired = Engagement(name="expired", operator="o",
                             in_scope_targets=["b.com"],
                             end_time="2020-01-01T00:00:00")
        store.add(expired)
        active = store.list(active_only=True)
        assert [e.name for e in active] == ["active"]

    def test_load_engagement_file(self, tmp_path):
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps({
            "name": "file engagement",
            "operator": "op",
            "in_scope_targets": ["target.example"],
        }), encoding="utf-8")
        eng = load_engagement_file(str(scope_file))
        assert eng.check_target("target.example").allowed
        assert not eng.check_target("elsewhere.example").allowed

    def test_load_engagement_file_invalid(self, tmp_path):
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps({"name": "", "operator": "",
                                          "in_scope_targets": []}),
                              encoding="utf-8")
        with pytest.raises(ValueError):
            load_engagement_file(str(scope_file))
