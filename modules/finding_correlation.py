"""
Athena Finding Correlation Module
=================================
Cross-module finding correlation, deduplication, and relationship mapping.

This module provides:
1. Deterministic deduplication across modules
2. Finding relationship detection
3. Impact aggregation
4. Finding lifecycle automation

Design principle: All correlation is deterministic. AI enhancement is optional
and never overrides deterministic results.
"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("athena.correlation")


class CorrelationType(Enum):
    """Types of correlation between findings."""
    DUPLICATE = "duplicate"
    RELATED = "related"
    CAUSAL = "causal"
    AGGREGATED = "aggregated"


class ImpactLevel(Enum):
    """Impact levels for aggregated findings."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FindingRelationship:
    """A relationship between two findings."""
    source_id: str
    target_id: str
    correlation_type: CorrelationType
    confidence: float
    description: str = ""
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "correlation_type": self.correlation_type.value,
            "confidence": self.confidence,
            "description": self.description,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass
class CorrelationResult:
    """Result of a correlation operation."""
    findings_input: int
    findings_output: int
    duplicates_found: int
    relationships_found: int
    relationships: List[FindingRelationship]
    dedup_groups: Dict[str, List[str]]  # dedup_key -> finding IDs
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings_input": self.findings_input,
            "findings_output": self.findings_output,
            "duplicates_found": self.duplicates_found,
            "relationships_found": self.relationships_found,
            "relationships": [r.to_dict() for r in self.relationships],
            "dedup_groups": dict(self.dedup_groups),
            "timestamp": self.timestamp,
        }


class FindingCorrelator:
    """Cross-module finding correlation engine.
    
    Provides deterministic correlation with optional AI enhancement.
    """
    
    # Patterns for detecting related findings
    RELATED_PATTERNS = {
        "credential_theft": [
            "ssh_private_key",
            "password_in_history",
            "credentials_extracted",
            "sam_dump",
        ],
        "privilege_escalation": [
            "suid_gtfobins",
            "sudo_policy",
            "seimpersonate",
            "always_install_elevated",
            "unquoted_service_path",
        ],
        "persistence": [
            "persistence",
            "ssh_key",
            "cron",
            "systemd",
            "scheduled_task",
        ],
        "network_exposure": [
            "listening_services",
            "open_ports",
            "network_context_established",
        ],
    }
    
    # Causal relationships (finding A causes finding B)
    CAUSAL_PATTERNS = {
        "readable_shadow": ["credential_theft"],
        "docker_socket": ["privilege_escalation"],
        "writable_passwd": ["privilege_escalation"],
        "seimpersonate": ["privilege_escalation"],
        "always_install_elevated": ["privilege_escalation"],
    }
    
    def __init__(self):
        self.logger = logging.getLogger("athena.correlation")
    
    def correlate(
        self,
        findings: List[Dict[str, Any]],
        engagement_id: str = ""
    ) -> CorrelationResult:
        """Perform deterministic correlation on findings.
        
        Args:
            findings: List of finding dictionaries
            engagement_id: Optional engagement ID for filtering
            
        Returns:
            CorrelationResult with deduplication and relationship info
        """
        # Filter by engagement if specified
        if engagement_id:
            findings = [
                f for f in findings
                if f.get("engagement_id") == engagement_id
            ]
        
        # Step 1: Deduplication
        dedup_groups = self._deduplicate(findings)
        
        # Step 2: Relationship detection
        relationships = self._detect_relationships(findings)
        
        # Step 3: Calculate output count (after dedup)
        unique_ids = set()
        for group_key, finding_ids in dedup_groups.items():
            # Keep the first finding from each group
            if finding_ids:
                unique_ids.add(finding_ids[0])
        
        return CorrelationResult(
            findings_input=len(findings),
            findings_output=len(unique_ids),
            duplicates_found=len(findings) - len(unique_ids),
            relationships_found=len(relationships),
            relationships=relationships,
            dedup_groups=dedup_groups,
        )
    
    def _deduplicate(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """Group findings by dedup key."""
        groups: Dict[str, List[str]] = {}
        
        for finding in findings:
            key = self._compute_dedup_key(finding)
            if key not in groups:
                groups[key] = []
            groups[key].append(finding.get("id", ""))
        
        return groups
    
    def _compute_dedup_key(self, finding: Dict[str, Any]) -> str:
        """Compute a stable dedup key for a finding."""
        # Use existing dedup_key if present
        if finding.get("dedup_key"):
            return finding["dedup_key"]
        
        # Compute from finding attributes — use type + payload as discriminator
        title = (finding.get("title") or finding.get("type") or "").strip().lower()
        asset = (finding.get("affected_asset") or finding.get("url") or "").strip().lower()
        module = (finding.get("detection_module") or "").strip().lower()
        finding_type = (finding.get("type") or "").strip().lower()
        payload = (finding.get("payload") or "").strip().lower()
        
        # Normalize common variations
        title = self._normalize_title(title)
        asset = self._normalize_asset(asset)
        
        return f"{module}|{asset}|{finding_type}|{payload}"
    
    def _normalize_title(self, title: str) -> str:
        """Normalize a finding title for dedup."""
        # Remove common prefixes/suffixes
        prefixes = ["potential ", "possible ", "confirmed ", "detected "]
        for prefix in prefixes:
            if title.startswith(prefix):
                title = title[len(prefix):]
        
        # Normalize whitespace
        title = " ".join(title.split())
        
        return title
    
    def _normalize_asset(self, asset: str) -> str:
        """Normalize an asset identifier for dedup."""
        # Remove protocol
        asset = asset.replace("https://", "").replace("http://", "")
        
        # Remove trailing slash
        asset = asset.rstrip("/")
        
        # Remove port if standard
        asset = asset.replace(":443", "").replace(":80", "")
        
        return asset.lower()
    
    def _detect_relationships(
        self, findings: List[Dict[str, Any]]
    ) -> List[FindingRelationship]:
        """Detect relationships between findings."""
        relationships = []
        findings_by_id = {f.get("id", ""): f for f in findings}
        
        # Check each pair of findings
        for i, f1 in enumerate(findings):
            for j, f2 in enumerate(findings):
                if i >= j:
                    continue
                
                rel = self._check_relationship(f1, f2)
                if rel:
                    relationships.append(rel)
        
        return relationships
    
    def _check_relationship(
        self,
        f1: Dict[str, Any],
        f2: Dict[str, Any]
    ) -> Optional[FindingRelationship]:
        """Check if two findings have a relationship."""
        f1_type = f1.get("type", "")
        f2_type = f2.get("type", "")
        f1_id = f1.get("id", "")
        f2_id = f2.get("id", "")
        
        # Check for related findings
        for category, related_types in self.RELATED_PATTERNS.items():
            if f1_type in related_types and f2_type in related_types:
                return FindingRelationship(
                    source_id=f1_id,
                    target_id=f2_id,
                    correlation_type=CorrelationType.RELATED,
                    confidence=0.8,
                    description=f"Both findings relate to {category}",
                )
        
        # Check for causal relationships
        for cause, effects in self.CAUSAL_PATTERNS.items():
            if f1_type == cause and f2_type in effects:
                return FindingRelationship(
                    source_id=f1_id,
                    target_id=f2_id,
                    correlation_type=CorrelationType.CAUSAL,
                    confidence=0.85,
                    description=f"{f1_type} may enable {f2_type}",
                )
            if f2_type == cause and f1_type in effects:
                return FindingRelationship(
                    source_id=f2_id,
                    target_id=f1_id,
                    correlation_type=CorrelationType.CAUSAL,
                    confidence=0.85,
                    description=f"{f2_type} may enable {f1_type}",
                )
        
        # Check for same asset + similar type
        f1_asset = (f1.get("affected_asset") or f1.get("url") or "").lower()
        f2_asset = (f2.get("affected_asset") or f2.get("url") or "").lower()
        
        if f1_asset and f2_asset and f1_asset == f2_asset:
            if f1_type == f2_type and f1_id != f2_id:
                return FindingRelationship(
                    source_id=f1_id,
                    target_id=f2_id,
                    correlation_type=CorrelationType.DUPLICATE,
                    confidence=0.9,
                    description=f"Same finding type on same asset",
                )
        
        return None
    
    def aggregate_impact(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Aggregate impact across related findings."""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate overall impact
        if severity_counts["critical"] > 0:
            overall_impact = ImpactLevel.CRITICAL
        elif severity_counts["high"] > 2:
            overall_impact = ImpactLevel.CRITICAL
        elif severity_counts["high"] > 0:
            overall_impact = ImpactLevel.HIGH
        elif severity_counts["medium"] > 2:
            overall_impact = ImpactLevel.HIGH
        elif severity_counts["medium"] > 0:
            overall_impact = ImpactLevel.MEDIUM
        elif severity_counts["low"] > 0:
            overall_impact = ImpactLevel.LOW
        else:
            overall_impact = ImpactLevel.NONE
        
        return {
            "severity_breakdown": severity_counts,
            "overall_impact": overall_impact.value,
            "total_findings": len(findings),
            "unique_assets": len(set(
                f.get("affected_asset") or f.get("url") or ""
                for f in findings
                if f.get("affected_asset") or f.get("url")
            )),
        }
    
    def get_findings_by_severity(
        self,
        findings: List[Dict[str, Any]],
        severity: str
    ) -> List[Dict[str, Any]]:
        """Filter findings by severity."""
        return [
            f for f in findings
            if f.get("severity", "").lower() == severity.lower()
        ]
    
    def get_findings_by_asset(
        self,
        findings: List[Dict[str, Any]],
        asset: str
    ) -> List[Dict[str, Any]]:
        """Filter findings by affected asset."""
        asset_lower = asset.lower()
        return [
            f for f in findings
            if (f.get("affected_asset") or f.get("url") or "").lower() == asset_lower
        ]
    
    def get_findings_by_module(
        self,
        findings: List[Dict[str, Any]],
        module: str
    ) -> List[Dict[str, Any]]:
        """Filter findings by detection module."""
        return [
            f for f in findings
            if f.get("detection_module", "") == module
        ]


# ============================================================================
# FACTORY FUNCTION
# ============================================================================


def create_correlator() -> FindingCorrelator:
    """Create a finding correlator instance."""
    return FindingCorrelator()
