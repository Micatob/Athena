"""
Athena Engagement & Scope Engine
================================
A fail-closed engagement abstraction for authorized security assessments.

Every target operation carried out by Athena must be associated with an
engagement.  When no engagement can be established, or when a proposed
target cannot be proven to be in scope, the engine denies the operation
(``BLOCKED``).  Reachability is never treated as authorization.

Scope rule conventions (all explicit, never inferred):

* A hostname matches an in-scope hostname exactly (case-insensitive).
* A hostname matches an in-scope *domain* only when the engagement
  explicitly enables ``include_subdomains`` for that domain.
* An IP matches an in-scope IP exactly or an in-scope CIDR prefix.
* A URL is judged by its host (and, when the rule carries a port, by the
  port).  Paths are not evaluated.
* Exclusions always win over inclusions.
"""

import ipaddress
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

# ============================================================================
# TECHNIQUE REGISTRY
# ============================================================================


class Technique(Enum):
    """Categories of assessment technique Athena modules may request.

    ``can_use`` enforces the engagement's allow/deny list; nothing else.

    RESTRICTED inherent techniques (e.g. active privilege escalation after
    an authorized foothold) additionally carry a ``confirmation`` flag so
    the orchestrator can require an explicit operator decision before the
    module executes.
    """

    RECON = "recon"
    SCANNING = "scanning"
    BRUTEFORCE = "bruteforce"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    HOST_ASSESSMENT = "host_assessment"
    PRIVILEGE_ASSESSMENT = "privilege_assessment"
    CONTROLLED_VALIDATION = "controlled_validation"  # active privesc / validation
    LATERAL_ASSESSMENT = "lateral_assessment"
    DATA_COLLECTION = "data_collection"
    PERSISTENCE = "persistence"
    CLEANUP = "cleanup"
    EVIDENCE = "evidence"
    IDENTITY_ASSESSMENT = "identity_assessment"
    PROCESS_SERVICE_ASSESSMENT = "process_service_assessment"
    SECURITY_CONTROL_ASSESSMENT = "security_control_assessment"
    CONFIGURATION_ASSESSMENT = "configuration_assessment"
    APPLICATION_CONTEXT_ASSESSMENT = "application_context_assessment"
    ACCESSIBLE_RESOURCE_ASSESSMENT = "accessible_resource_assessment"
    ATTACK_PATH_CORRELATION = "attack_path_correlation"
    RISK_IMPACT_ASSESSMENT = "risk_impact_assessment"


#: Techniques that must never run without explicit operator confirmation.
#: Kept outside the enum body: Python 3.14 treats in-body assignments
#: (even underscore-prefixed ones) as members.
_CONFIRMATION_REQUIRED: frozenset = frozenset(
    {Technique.PERSISTENCE, Technique.CONTROLLED_VALIDATION,
     Technique.LATERAL_ASSESSMENT, Technique.CLEANUP}
)


#: Everything permitted when an engagement does not restrict techniques.
DEFAULT_ALLOWED_TECHNIQUES: List[str] = [
    t.value for t in Technique
    if t not in (Technique.PERSISTENCE,)
]


# ============================================================================
# SCOPE MATCHING
# ============================================================================


class ScopeDecision(Enum):
    """Outcome of a target scope check."""

    ALLOWED = "allowed"
    NOT_IN_SCOPE = "not_in_scope"
    EXCLUDED = "excluded"
    NO_ENGAGEMENT = "no_engagement_established"


@dataclass(frozen=True)
class ScopeCheck:
    """Result of evaluating one target against one engagement's scope."""

    target: str
    decision: ScopeDecision
    engagement_id: Optional[str] = None
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == ScopeDecision.ALLOWED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "decision": self.decision.value,
            "engagement_id": self.engagement_id,
            "reason": self.reason,
        }


def normalize_target(value: str) -> Dict[str, Any]:
    """Normalize a target string into its structured components.

    Returns a dict with ``kind`` (``hostname`` | ``ip`` | ``cidr`` | ``url``),
    ``raw``, ``host``, and (for URLs) ``scheme`` / ``port`` / ``path``.
    """
    value = (value or "").strip()
    # empty input is never valid
    parsed: Dict[str, Any] = {"raw": value}
    if not value:
        parsed["kind"] = "invalid"
        return parsed

    # explicit URL
    if "://" in value:
        try:
            from urllib.parse import urlparse

            u = urlparse(value)
            host = (u.hostname or "").lower().rstrip(".")
            parsed.update(kind="url", host=host, scheme=u.scheme,
                          port=u.port, path=u.path or "/")
            return parsed
        except Exception:
            parsed["kind"] = "invalid"
            return parsed

    # CIDR
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            parsed["kind"] = "cidr"
            parsed["host"] = value
            return parsed
        except ValueError:
            pass

    # IP
    try:
        ipaddress.ip_address(value)
        parsed["kind"] = "ip"
        parsed["host"] = value
        return parsed
    except ValueError:
        pass

    # hostname
    parsed["kind"] = "hostname"
    parsed["host"] = value.lower().rstrip(".")
    return parsed


def _host_in_scope(host: str, rule: str, include_subdomains: bool) -> bool:
    """Match a normalized host against a scope rule.

    A rule may be an IP (exact), a CIDR, a hostname (exact), or a domain
    with subdomains when ``include_subdomains`` is enabled.
    """
    n = normalize_target(rule)
    kind = n.get("kind")
    if kind in ("ip", "cidr"):
        try:
            addr = ipaddress.ip_address(host)
            if kind == "ip":
                return host == rule
            return addr in ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return False
    if kind in ("hostname", "url"):
        rule_host = n.get("host", rule.lower().rstrip("."))
        if host == rule_host:
            return True
        if include_subdomains and host.endswith("." + rule_host):
            return True
    return False


# ============================================================================
# ENGAGEMENT MODEL
# ============================================================================


@dataclass
class OperatorIdentity:
    """Structured identity of the human operator running the engagement."""

    operator_id: str = ""
    name: str = ""
    team: str = ""
    role: str = ""
    contact: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operator_id": self.operator_id,
            "name": self.name,
            "team": self.team,
            "role": self.role,
            "contact": self.contact,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "OperatorIdentity":
        if not data:
            return cls()
        return cls(
            operator_id=str(data.get("operator_id", "")),
            name=str(data.get("name", "")),
            team=str(data.get("team", "")),
            role=str(data.get("role", "")),
            contact=str(data.get("contact", "")),
        )


@dataclass
class AuthorizationMetadata:
    """Provenance for the written authorization of the engagement."""

    reference: str = ""
    issuing_authority: str = ""
    authorized_from: str = ""
    authorized_until: str = ""
    file: str = ""
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reference": self.reference,
            "issuing_authority": self.issuing_authority,
            "authorized_from": self.authorized_from,
            "authorized_until": self.authorized_until,
            "file": self.file,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "AuthorizationMetadata":
        if not data:
            return cls()
        return cls(
            reference=str(data.get("reference", "")),
            issuing_authority=str(data.get("issuing_authority", "")),
            authorized_from=str(data.get("authorized_from", "")),
            authorized_until=str(data.get("authorized_until", "")),
            file=str(data.get("file", "")),
            notes=str(data.get("notes", "")),
        )


def _as_utc(value: datetime) -> datetime:
    """Interpret naive datetimes as UTC; convert aware ones without
    corrupting their zone (the old ``replace(tzinfo=...)`` re-tagged
    aware values instead of converting)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass
class Engagement:
    """Authorization and scope definition for one assessment engagement."""

    name: str
    operator: str
    in_scope_targets: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    applications: List[str] = field(default_factory=list)
    operator_identity: Optional[OperatorIdentity] = None
    authorization: Optional[AuthorizationMetadata] = None
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    description: str = ""
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    allowed_techniques: Optional[List[str]] = None   # None = defaults
    restricted_techniques: List[str] = field(default_factory=list)
    include_subdomains: bool = False
    rate_limits: Dict[str, Any] = field(default_factory=dict)
    max_concurrency: int = 5
    evidence_retention_days: int = 365
    authorization_ref: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    active: bool = True

    # -- validation ---------------------------------------------------------

    def validate(self) -> List[str]:
        """Return a list of configuration errors (empty when valid)."""
        errors: List[str] = []
        if not self.name.strip():
            errors.append("engagement name is required")
        if not self.operator.strip():
            errors.append("operator identity is required")
        if not self.in_scope_targets:
            errors.append("at least one in-scope target is required")
        for t in self.in_scope_targets:
            if normalize_target(t).get("kind") == "invalid":
                errors.append(f"invalid scope target: {t}")
        for t in self.exclusions:
            if normalize_target(t).get("kind") == "invalid":
                errors.append(f"invalid exclusion target: {t}")
        if self.start_time and self.end_time:
            try:
                start = datetime.fromisoformat(self.start_time)
                end = datetime.fromisoformat(self.end_time)
                if end < start:
                    errors.append("end_time precedes start_time")
            except ValueError:
                errors.append("invalid start_time/end_time format (ISO 8601)")
        return errors

    @property
    def is_expired(self) -> bool:
        if not self.end_time:
            return False
        try:
            end = datetime.fromisoformat(self.end_time)
        except ValueError:
            return False
        return datetime.now(timezone.utc) > _as_utc(end)

    def _authorization_valid(self) -> bool:
        """Authorization window must still cover today (fail-closed)."""
        auth = self.authorization
        if auth is None or not auth.authorized_until:
            return True  # no explicit window = no explicit restriction
        try:
            until = _as_utc(datetime.fromisoformat(auth.authorized_until))
        except ValueError:
            return False
        return datetime.now(timezone.utc) <= until

    # -- scope checking -----------------------------------------------------

    def check_target(self, target: str) -> ScopeCheck:
        """Evaluate one target; exclusions win; unknown scope is denied."""
        n = normalize_target(target)
        kind = n.get("kind")
        if kind == "invalid":
            return ScopeCheck(
                target, ScopeDecision.NOT_IN_SCOPE, self.id,
                f"cannot parse target {target!r}",
            )

        if kind == "url":
            host = n.get("host", "")
            port = n.get("port")
        else:
            host = n.get("host", "")
            port = None

        for ex in self.exclusions:
            exn = normalize_target(ex)
            if exn.get("kind") == "url":
                if _host_in_scope(host, exn.get("host", ""), True) and (
                    exn.get("port") in (None, port)
                ):
                    return ScopeCheck(target, ScopeDecision.EXCLUDED, self.id,
                                      f"excluded by rule {ex!r}")
            elif _host_in_scope(host, ex, False):
                return ScopeCheck(target, ScopeDecision.EXCLUDED, self.id,
                                  f"excluded by rule {ex!r}")

        for rule in self.in_scope_targets:
            rn = normalize_target(rule)
            if rn.get("kind") == "url" and kind == "url":
                if _host_in_scope(host, rn.get("host", ""), self.include_subdomains) and (
                    rn.get("port") in (None, port)
                ):
                    return ScopeCheck(target, ScopeDecision.ALLOWED, self.id,
                                      "matches in-scope URL rule")
            elif _host_in_scope(host, rule, self.include_subdomains):
                return ScopeCheck(target, ScopeDecision.ALLOWED, self.id,
                                  f"matches in-scope rule {rule!r}")

        return ScopeCheck(
            target, ScopeDecision.NOT_IN_SCOPE, self.id,
            "target is not covered by any in-scope rule",
        )

    # -- technique gating ---------------------------------------------------

    def can_use(self, technique: str, target: str = "") -> ScopeCheck:
        """Combine scope and technique authorization into one gate.

        Returns ``ScopeCheck`` with decision ``ALLOWED`` only when both the
        technique is permitted for this engagement AND (if a target was
        supplied) the target is in scope.
        """
        # technique check
        tech = technique
        restricted = set(self.restricted_techniques)
        allowed = self.allowed_techniques or DEFAULT_ALLOWED_TECHNIQUES
        if tech in restricted:
            return ScopeCheck(
                target, ScopeDecision.NOT_IN_SCOPE, self.id,
                f"technique {tech!r} is restricted by the engagement",
            )
        if tech not in allowed:
            return ScopeCheck(
                target, ScopeDecision.NOT_IN_SCOPE, self.id,
                f"technique {tech!r} is not allowed by the engagement",
            )

        # scope check on the target
        if target:
            scope = self.check_target(target)
            if not scope.allowed:
                return scope
            return ScopeCheck(target, ScopeDecision.ALLOWED, self.id,
                              f"technique {tech!r} allowed; target in scope")

        return ScopeCheck(target, ScopeDecision.ALLOWED, self.id,
                          f"technique {tech!r} allowed")

    def requires_confirmation(self, technique: str) -> bool:
        try:
            return Technique(technique) in _CONFIRMATION_REQUIRED
        except ValueError:
            return False

    # -- serialization ------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "operator": self.operator,
            "operator_identity": (self.operator_identity.to_dict()
                                  if self.operator_identity else None),
            "authorization": (self.authorization.to_dict()
                              if self.authorization else None),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "in_scope_targets": list(self.in_scope_targets),
            "exclusions": list(self.exclusions),
            "applications": list(self.applications),
            "include_subdomains": self.include_subdomains,
            "allowed_techniques": (list(self.allowed_techniques)
                                   if self.allowed_techniques else None),
            "restricted_techniques": list(self.restricted_techniques),
            "rate_limits": dict(self.rate_limits),
            "max_concurrency": self.max_concurrency,
            "evidence_retention_days": self.evidence_retention_days,
            "authorization_ref": self.authorization_ref,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "active": self.active,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Engagement":
        return cls(
            id=data.get("id", str(uuid.uuid4())[:12]),
            name=data.get("name", ""),
            description=data.get("description", ""),
            operator=data.get("operator", ""),
            operator_identity=OperatorIdentity.from_dict(
                data.get("operator_identity")),
            authorization=AuthorizationMetadata.from_dict(
                data.get("authorization")),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            in_scope_targets=list(data.get("in_scope_targets", [])),
            exclusions=list(data.get("exclusions", [])),
            applications=list(data.get("applications", [])),
            include_subdomains=data.get("include_subdomains", False),
            allowed_techniques=(
                list(data["allowed_techniques"])
                if data.get("allowed_techniques") else None
            ),
            restricted_techniques=list(data.get("restricted_techniques", [])),
            rate_limits=dict(data.get("rate_limits", {})),
            max_concurrency=int(data.get("max_concurrency", 5)),
            evidence_retention_days=int(data.get("evidence_retention_days", 365)),
            authorization_ref=data.get("authorization_ref", ""),
            metadata=dict(data.get("metadata", {})),
            created_at=data.get("created_at", ""),
            active=data.get("active", True),
        )


# ============================================================================
# ENGAGEMENT STORE
# ============================================================================


class EngagementStore:
    """File-backed engagement registry (JSON, matching Athena's storage).

    The default file is ``engagements.json`` in the project root, mirroring
    the existing ``sessions.json`` pattern.
    """

    def __init__(self, path: Optional[str] = None):
        self._path = path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "engagements.json",
        )
        self.engagements: Dict[str, Engagement] = {}
        self.load()

    # -- persistence --------------------------------------------------------

    def load(self) -> int:
        self.engagements = {}
        if not os.path.exists(self._path):
            return 0
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            records = data if isinstance(data, list) else data.get("engagements", [])
            for record in records:
                eng = Engagement.from_dict(record)
                if eng.id:
                    self.engagements[eng.id] = eng
            return len(self.engagements)
        except (OSError, ValueError, TypeError):
            return 0

    def save(self) -> None:
        payload = {
            "engagements": [e.to_dict() for e in self.engagements.values()],
        }
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, self._path)

    # -- registry API -------------------------------------------------------

    def add(self, engagement: Engagement) -> Engagement:
        errors = engagement.validate()
        if errors:
            raise ValueError(f"invalid engagement: {'; '.join(errors)}")
        self.engagements[engagement.id] = engagement
        self.save()
        return engagement

    def get(self, engagement_id: str) -> Optional[Engagement]:
        return self.engagements.get(engagement_id)

    def list(self, active_only: bool = False) -> List[Engagement]:
        items = list(self.engagements.values())
        if active_only:
            items = [e for e in items if e.active and not e.is_expired]
        return sorted(items, key=lambda e: e.created_at)

    def remove(self, engagement_id: str) -> bool:
        removed = self.engagements.pop(engagement_id, None)
        if removed is not None:
            self.save()
            return True
        return False

    def update(self, engagement: Engagement) -> None:
        self.engagements[engagement.id] = engagement
        self.save()

    def from_dict(self, data: Dict[str, Any]) -> Engagement:
        eng = Engagement.from_dict(data)
        errors = eng.validate()
        if errors:
            raise ValueError(f"invalid engagement: {'; '.join(errors)}")
        return eng

    def clear(self) -> None:
        """Drop all engagements (used by tests; not persisted)."""
        self.engagements = {}


def load_engagement_file(path: str) -> Engagement:
    """Load a single engagement definition from a JSON scope file."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    eng = Engagement.from_dict(data)
    errors = eng.validate()
    if errors:
        raise ValueError(f"invalid engagement file {path}: {'; '.join(errors)}")
    return eng


AD_HOC_TECHNIQUES = [
    Technique.POST_EXPLOITATION.value,
    Technique.HOST_ASSESSMENT.value,
    Technique.PRIVILEGE_ASSESSMENT.value,
    Technique.IDENTITY_ASSESSMENT.value,
    Technique.PROCESS_SERVICE_ASSESSMENT.value,
    Technique.SECURITY_CONTROL_ASSESSMENT.value,
    Technique.CONFIGURATION_ASSESSMENT.value,
    Technique.APPLICATION_CONTEXT_ASSESSMENT.value,
    Technique.ACCESSIBLE_RESOURCE_ASSESSMENT.value,
    Technique.ATTACK_PATH_CORRELATION.value,
    Technique.RISK_IMPACT_ASSESSMENT.value,
    Technique.EVIDENCE.value,
]


def ad_hoc_engagement(targets: List[str], operator: str = "cli",
                      technique: Optional[str] = None,
                      **extra: Any) -> Engagement:
    """Build an explicit, minimal, fail-closed engagement for CLI use.

    Only the targets passed on the command line are in scope.  Required to
    preserve backwards compatibility with Athena's ``--post*`` flags while
    guaranteeing that anything not explicitly listed is denied.

    By default all assessment techniques are allowed; when a single
    ``technique`` is supplied the engagement is restricted to it alone.
    """
    techniques = extra.pop("techniques", None)
    if not techniques:
        techniques = ([technique] if technique
                      else AD_HOC_TECHNIQUES)
    elif isinstance(techniques, str):
        techniques = [techniques]
    return Engagement(
        name="ad-hoc CLI engagement",
        operator=operator,
        in_scope_targets=[t.strip() for t in targets if t.strip()],
        description="Explicit CLI targets; nothing beyond them is in scope.",
        allowed_techniques=list(techniques),
        **extra,
    )