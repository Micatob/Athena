"""
tests/test_finding_correlation.py – Finding Correlation Module Tests
====================================================================
Covers:
  * Deduplication logic
  * Relationship detection
  * Causal relationship detection
  * Impact aggregation
  * Filtering by severity/asset/module
"""

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.finding_correlation import (
    CorrelationType,
    FindingCorrelator,
    FindingRelationship,
    ImpactLevel,
)


@pytest.fixture()
def correlator():
    return FindingCorrelator()


@pytest.fixture()
def sample_findings():
    return [
        {
            "id": "f1",
            "title": "SQL Injection in login",
            "severity": "critical",
            "affected_asset": "https://example.com/login",
            "detection_module": "scanner",
            "type": "sql_injection",
        },
        {
            "id": "f2",
            "title": "SQL Injection in login",
            "severity": "critical",
            "affected_asset": "https://example.com/login",
            "detection_module": "scanner",
            "type": "sql_injection",
        },
        {
            "id": "f3",
            "title": "XSS in search",
            "severity": "medium",
            "affected_asset": "https://example.com/search",
            "detection_module": "scanner",
            "type": "xss",
        },
        {
            "id": "f4",
            "title": "SSH private key found",
            "severity": "critical",
            "affected_asset": "10.0.0.1",
            "detection_module": "post_exploitation",
            "type": "ssh_private_key",
        },
        {
            "id": "f5",
            "title": "Credentials extracted",
            "severity": "critical",
            "affected_asset": "10.0.0.1",
            "detection_module": "post_exploitation",
            "type": "credentials_extracted",
        },
    ]


class TestDeduplication:
    def test_removes_exact_duplicates(self, correlator, sample_findings):
        result = correlator.correlate(sample_findings)
        # f1 and f2 are exact duplicates
        assert result.duplicates_found >= 1
        assert result.findings_output < result.findings_input

    def test_preserves_unique_findings(self, correlator, sample_findings):
        result = correlator.correlate(sample_findings)
        # Should have at least 4 unique findings
        assert result.findings_output >= 4

    def test_dedup_groups_contain_ids(self, correlator, sample_findings):
        result = correlator.correlate(sample_findings)
        for key, ids in result.dedup_groups.items():
            assert len(ids) >= 1
            assert all(isinstance(fid, str) for fid in ids)

    def test_empty_findings(self, correlator):
        result = correlator.correlate([])
        assert result.findings_input == 0
        assert result.findings_output == 0
        assert result.duplicates_found == 0


class TestRelationshipDetection:
    def test_finds_related_findings(self, correlator, sample_findings):
        result = correlator.correlate(sample_findings)
        # f4 (ssh_private_key) and f5 (credentials_extracted) are related
        related = [
            r for r in result.relationships
            if r.correlation_type == CorrelationType.RELATED
        ]
        assert len(related) >= 1

    def test_finds_duplicate_relationship(self, correlator, sample_findings):
        result = correlator.correlate(sample_findings)
        # f1 and f2 should have duplicate relationship
        duplicates = [
            r for r in result.relationships
            if r.correlation_type == CorrelationType.DUPLICATE
        ]
        assert len(duplicates) >= 1

    def test_relationship_to_dict(self):
        rel = FindingRelationship(
            source_id="f1",
            target_id="f2",
            correlation_type=CorrelationType.RELATED,
            confidence=0.8,
            description="Test relationship",
        )
        data = rel.to_dict()
        assert data["source_id"] == "f1"
        assert data["correlation_type"] == "related"


class TestCausalRelationships:
    def test_readable_shadow_causes_credential_theft(self, correlator):
        findings = [
            {
                "id": "f1",
                "title": "Readable shadow",
                "severity": "critical",
                "type": "readable_shadow",
                "affected_asset": "host1",
            },
            {
                "id": "f2",
                "title": "Credential theft",
                "severity": "critical",
                "type": "credential_theft",
                "affected_asset": "host1",
            },
        ]
        result = correlator.correlate(findings)
        causal = [
            r for r in result.relationships
            if r.correlation_type == CorrelationType.CAUSAL
        ]
        assert len(causal) >= 1

    def test_docker_socket_causes_privesc(self, correlator):
        findings = [
            {
                "id": "f1",
                "title": "Docker socket",
                "severity": "critical",
                "type": "docker_socket",
                "affected_asset": "host1",
            },
            {
                "id": "f2",
                "title": "Privilege escalation",
                "severity": "critical",
                "type": "privilege_escalation",
                "affected_asset": "host1",
            },
        ]
        result = correlator.correlate(findings)
        causal = [
            r for r in result.relationships
            if r.correlation_type == CorrelationType.CAUSAL
        ]
        assert len(causal) >= 1


class TestImpactAggregation:
    def test_critical_aggregate(self, correlator):
        findings = [
            {"severity": "critical", "affected_asset": "h1"},
            {"severity": "critical", "affected_asset": "h2"},
            {"severity": "high", "affected_asset": "h3"},
        ]
        result = correlator.aggregate_impact(findings)
        assert result["overall_impact"] == "critical"
        assert result["severity_breakdown"]["critical"] == 2

    def test_high_aggregate(self, correlator):
        findings = [
            {"severity": "high", "affected_asset": "h1"},
            {"severity": "high", "affected_asset": "h1"},
            {"severity": "medium", "affected_asset": "h2"},
        ]
        result = correlator.aggregate_impact(findings)
        assert result["overall_impact"] == "high"

    def test_medium_aggregate(self, correlator):
        findings = [
            {"severity": "medium", "affected_asset": "h1"},
            {"severity": "low", "affected_asset": "h2"},
        ]
        result = correlator.aggregate_impact(findings)
        assert result["overall_impact"] == "medium"

    def test_no_findings(self, correlator):
        result = correlator.aggregate_impact([])
        assert result["overall_impact"] == "none"
        assert result["total_findings"] == 0

    def test_unique_assets_count(self, correlator):
        findings = [
            {"severity": "high", "affected_asset": "h1"},
            {"severity": "high", "affected_asset": "h1"},
            {"severity": "high", "affected_asset": "h2"},
        ]
        result = correlator.aggregate_impact(findings)
        assert result["unique_assets"] == 2


class TestFiltering:
    def test_filter_by_severity(self, correlator, sample_findings):
        critical = correlator.get_findings_by_severity(sample_findings, "critical")
        assert len(critical) == 4  # f1, f2, f4, f5

    def test_filter_by_asset(self, correlator, sample_findings):
        login_findings = correlator.get_findings_by_asset(
            sample_findings, "https://example.com/login"
        )
        assert len(login_findings) == 2  # f1, f2

    def test_filter_by_module(self, correlator, sample_findings):
        post_findings = correlator.get_findings_by_module(
            sample_findings, "post_exploitation"
        )
        assert len(post_findings) == 2  # f4, f5


class TestEngagementFilter:
    def test_filter_by_engagement(self, correlator):
        findings = [
            {"id": "f1", "engagement_id": "eng1", "severity": "high", "type": "x"},
            {"id": "f2", "engagement_id": "eng2", "severity": "high", "type": "x"},
            {"id": "f3", "engagement_id": "eng1", "severity": "high", "type": "x"},
        ]
        result = correlator.correlate(findings, engagement_id="eng1")
        assert result.findings_input == 2
