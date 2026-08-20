"""
Athena Findings, Evidence & Secret Handling
===========================================
Standardized finding lifecycle, evidence objects with integrity metadata,
and conservative secret redaction.

Principles implemented here:

* An AI hypothesis or a raw scan indicator is NEVER a confirmed finding.
  Findings move through an explicit lifecycle (DISCOVERED → … → CONFIRMED)
  and only *validated* evidence may carry ``CONFIRMED``.
* Evidence hashes (SHA-256) make assessment results reproducible; raw
  artifacts are stored on disk under ``evidence/<engagement>/<finding>/``
  rather than inside relational/JSON files.
* Secrets are not printed to logs, not persisted by default, and never
  exposed in evidence.  Discovered secrets are recorded as *metadata*
  (``SECRET_DISCOVERED``) with provenance, distinct from validated secrets.
"""

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

# ============================================================================
# ENUMS
# ============================================================================


class FindingState(Enum):
    DISCOVERED = "discovered"
    TRIAGED = "triaged"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    REMEDIATED = "remediated"
    REVALIDATED = "revalidated"


#: Valid lifecycle transitions.  Anything not listed is rejected.
FINDING_STATE_TRANSITIONS: Dict[FindingState, frozenset] = {
    FindingState.DISCOVERED: frozenset({
        FindingState.TRIAGED, FindingState.VALIDATING,
        FindingState.FALSE_POSITIVE, FindingState.DUPLICATE,
    }),
    FindingState.TRIAGED: frozenset({
        FindingState.VALIDATING, FindingState.CONFIRMED,
        FindingState.FALSE_POSITIVE, FindingState.DUPLICATE,
        FindingState.REMEDIATED,
    }),
    FindingState.VALIDATING: frozenset({
        FindingState.CONFIRMED, FindingState.DISCOVERED,
        FindingState.FALSE_POSITIVE, FindingState.DUPLICATE,
    }),
    FindingState.CONFIRMED: frozenset({
        FindingState.REMEDIATED, FindingState.REVALIDATED,
        FindingState.FALSE_POSITIVE, FindingState.DUPLICATE,
    }),
    FindingState.FALSE_POSITIVE: frozenset({
        FindingState.TRIAGED, FindingState.DISCOVERED,
    }),
    FindingState.DUPLICATE: frozenset({FindingState.TRIAGED}),
    FindingState.REMEDIATED: frozenset({FindingState.REVALIDATED}),
    FindingState.REVALIDATED: frozenset({
        FindingState.CONFIRMED, FindingState.REMEDIATED,
    }),
}

VALID_STATES: Dict[str, FindingState] = {s.value: s for s in FindingState}


class EvidenceKind(Enum):
    HTTP = "http"
    DNS = "dns"
    NETWORK = "network"
    HOST_OBSERVATION = "host_observation"
    SCREENSHOT = "screenshot"
    LOG = "log"
    TOOL_OUTPUT = "tool_output"
    CONFIGURATION = "configuration"
    VULNERABILITY_VALIDATION = "vulnerability_validation"


class ValidationState(Enum):
    UNVERIFIED = "unverified"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    PARTIAL = "partial"


class AssessmentStage(Enum):
    """Athena's five assessment concepts (kept strictly separate).

    A finding must never skip ahead solely because of a hypothesis: an
    AI-generated or automated hypothesis is *detection* at best and only
    becomes *validation* with evidence, then *impact* with consequences.
    """

    DISCOVERY = "discovery"                       # something exists
    DETECTION = "detection"                       # potential weakness identified
    VALIDATION = "validation"                     # weakness proven with evidence
    IMPACT_ASSESSMENT = "impact_assessment"       # what the weakness enables
    POST_EXPLOITATION_ASSESSMENT = "post_exploitation_assessment"  # post-foothold impact


# ============================================================================
# EVIDENCE
# ============================================================================


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", errors="replace"))


@dataclass
class Evidence:
    """One reproducible observation supporting a finding."""

    engagement_id: str
    target: str
    module: str
    kind: EvidenceKind
    observation: str = ""
    technique: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:16])
    finding_id: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    structured: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    validation_state: ValidationState = ValidationState.UNVERIFIED
    raw_ref: str = ""            # on-disk artifact path relative to store
    sha256: str = ""
    encrypted: bool = False      # artifact encrypted at rest (Fernet)

    def finalize(self, artifact: Optional[bytes] = None) -> "Evidence":
        """Compute integrity metadata (and artifact hash when supplied)."""
        if artifact is not None:
            self.sha256 = sha256_bytes(artifact)
        elif self.observation:
            self.sha256 = sha256_text(self.observation)
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "finding_id": self.finding_id,
            "target": self.target,
            "timestamp": self.timestamp,
            "module": self.module,
            "technique": self.technique,
            "kind": self.kind.value,
            "observation": self.observation,
            "structured": self.structured,
            "confidence": self.confidence,
            "validation_state": self.validation_state.value,
            "raw_ref": self.raw_ref,
            "sha256": self.sha256,
            "encrypted": self.encrypted,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        return cls(
            id=data.get("id", ""),
            engagement_id=data.get("engagement_id", ""),
            finding_id=data.get("finding_id", ""),
            target=data.get("target", ""),
            timestamp=data.get("timestamp", ""),
            module=data.get("module", ""),
            technique=data.get("technique", ""),
            kind=EvidenceKind(data.get("kind", "tool_output")),
            observation=data.get("observation", ""),
            structured=dict(data.get("structured", {})),
            confidence=float(data.get("confidence", 0.5)),
            validation_state=ValidationState(
                data.get("validation_state", "unverified")
            ),
            raw_ref=data.get("raw_ref", ""),
            sha256=data.get("sha256", ""),
            encrypted=bool(data.get("encrypted", False)),
        )


class EvidenceStore:
    """Stores structured evidence and raw artifacts on disk.

    Layout::

        evidence/<engagement_id>/<finding_id>/<evidence_id>.<ext>
        evidence/index.jsonl      <- one Evidence.to_dict() per line
    """

    def __init__(self, base_dir: Optional[str] = None,
                 encryption_key: Optional[str] = None):
        root = base_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "evidence",
        )
        self._root = root
        self._index = os.path.join(root, "index.jsonl")
        self._records: Dict[str, Evidence] = {}
        self._fernet = None
        self._configure_encryption(encryption_key)
        self._load_index()

    def _configure_encryption(self,
                              encryption_key: Optional[str] = None) -> None:
        """Enable Fernet encryption of raw artifacts when requested.

        Gated by ``ATHENA_ENCRYPT_EVIDENCE=1`` (or an explicit key passed to
        the constructor). The key comes from ``ATHENA_EVIDENCE_KEY`` when set;
        otherwise a key is generated once and stored next to the store
        (``evidence/.evidence.key``). Without a key nothing is encrypted, so
        existing deployments are unaffected.
        """
        flag = os.getenv("ATHENA_ENCRYPT_EVIDENCE", "").strip().lower()
        if encryption_key is None and flag not in ("1", "true", "yes", "on"):
            return
        key = encryption_key or os.getenv("ATHENA_EVIDENCE_KEY", "")
        if not key:
            key_path = os.path.join(self._root, ".evidence.key")
            if os.path.exists(key_path):
                try:
                    with open(key_path, "r", encoding="utf-8") as fh:
                        key = fh.read().strip()
                except OSError:
                    return
            else:
                try:
                    from cryptography.fernet import Fernet
                    key = Fernet.generate_key().decode()
                    os.makedirs(self._root, exist_ok=True)
                    with open(key_path, "w", encoding="utf-8") as fh:
                        fh.write(key)
                except (OSError, ImportError):
                    return
        try:
            from cryptography.fernet import Fernet
            self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
        except (ImportError, ValueError, TypeError):
            self._fernet = None

    def _load_index(self) -> None:
        if not os.path.exists(self._index):
            return
        try:
            with open(self._index, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = Evidence.from_dict(json.loads(line))
                        self._records[rec.id] = rec
                    except (ValueError, TypeError, KeyError):
                        continue
        except OSError:
            pass

    def add(self, evidence: Evidence,
            artifact: Optional[bytes] = None,
            artifact_name: str = "") -> Evidence:
        """Register evidence; persist artifact bytes when provided."""
        evidence.finalize(artifact)
        if artifact is not None:
            if not artifact_name:
                ext = "bin"
                if evidence.kind == EvidenceKind.TOOL_OUTPUT:
                    ext = "txt"
                elif evidence.kind == EvidenceKind.HTTP:
                    ext = "http"
                elif evidence.kind == EvidenceKind.LOG:
                    ext = "log"
                elif evidence.kind == EvidenceKind.CONFIGURATION:
                    ext = "cfg"
                artifact_name = f"{evidence.id}.{ext}"
            rel = os.path.join(
                evidence.engagement_id, evidence.finding_id or "_", artifact_name
            )
            abs_path = os.path.join(self._root, rel)
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            payload = artifact
            if self._fernet is not None:
                try:
                    payload = self._fernet.encrypt(artifact)
                    evidence.encrypted = True
                except Exception:
                    payload = artifact
            with open(abs_path, "wb") as fh:
                fh.write(payload)
            evidence.raw_ref = rel.replace(os.sep, "/")
            evidence.sha256 = sha256_bytes(artifact)
        self._records[evidence.id] = evidence
        self._append_index(evidence)
        return evidence

    def _append_index(self, evidence: Evidence) -> None:
        os.makedirs(self._root, exist_ok=True)
        with open(self._index, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(evidence.to_dict()) + "\n")

    def get(self, evidence_id: str) -> Optional[Evidence]:
        return self._records.get(evidence_id)

    def list(self, engagement_id: str = "",
             finding_id: str = "") -> List[Evidence]:
        items = self._records.values()
        if engagement_id:
            items = (e for e in items if e.engagement_id == engagement_id)
        if finding_id:
            items = (e for e in items if e.finding_id == finding_id)
        return sorted(items, key=lambda e: e.timestamp)

    def artifact_path(self, evidence: Evidence) -> Optional[str]:
        if not evidence.raw_ref:
            return None
        path = os.path.join(self._root, evidence.raw_ref)
        return path if os.path.exists(path) else None

    def artifact_bytes(self, evidence: Evidence) -> Optional[bytes]:
        """Read the artifact, decrypting when it was stored encrypted.

        Fails closed: an encrypted artifact whose key is unavailable
        yields ``None`` rather than ciphertext.
        """
        if evidence.encrypted and self._fernet is None:
            return None
        path = self.artifact_path(evidence)
        if not path:
            return None
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            return None
        if not evidence.encrypted:
            return data
        try:
            return self._fernet.decrypt(data)
        except Exception:
            return None

    def verify(self, evidence: Evidence) -> bool:
        """Re-hash the artifact and compare with the recorded SHA-256."""
        path = self.artifact_path(evidence)
        if not path:
            return bool(evidence.sha256) and (
                evidence.sha256 == sha256_text(evidence.observation)
            )
        data = self.artifact_bytes(evidence)
        if data is None:
            return False
        return sha256_bytes(data) == evidence.sha256


# ============================================================================
# FINDINGS
# ============================================================================


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def normalize_severity(severity: str) -> str:
    s = (severity or "info").strip().lower()
    if s in SEVERITY_RANK:
        return s
    if s in ("5", "4", "3.75"):
        return "critical"
    return "info"


@dataclass
class Finding:
    """Structured security finding with a full lifecycle."""

    engagement_id: str
    title: str
    severity: str = "info"
    confidence: float = 0.5
    affected_asset: str = ""
    description: str = ""
    root_cause: str = ""
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:16])
    state: FindingState = FindingState.DISCOVERED
    detection_module: str = ""
    validation_module: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    reproduction: str = ""
    dedup_key: str = ""
    stage: AssessmentStage = AssessmentStage.DISCOVERY
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

    def format_dedup_key(self) -> str:
        """Stable dedup identity: module + asset + title (normalized)."""
        return f"{self.detection_module or ''}|{self.affected_asset or ''}|{self.title.strip().lower()}"

    def transition(self, new_state: FindingState,
                   reason: str = "", actor: str = "") -> bool:
        """Attempt a lifecycle transition; returns False when invalid."""
        allowed = FINDING_STATE_TRANSITIONS.get(self.state, frozenset())
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

    def mark_confirmed(self, evidence: List[Evidence],
                       actor: str = "") -> bool:
        """Confirm only when supporting *validated* evidence exists.

        An AI hypothesis or a raw scan indicator is never sufficient: only
        evidence whose ``validation_state == CONFIRMED`` may carry a
        finding to CONFIRMED (see module principles).
        """
        valid_evidence = [
            e for e in evidence
            if e.validation_state == ValidationState.CONFIRMED
        ]
        if not valid_evidence:
            return False
        confirmed = self.transition(FindingState.CONFIRMED,
                                    reason="validated evidence attached",
                                    actor=actor)
        if confirmed:
            self.record_stage(AssessmentStage.VALIDATION, actor=actor)
        return confirmed

    def record_stage(self, stage: AssessmentStage,
                     actor: str = "", reason: str = "") -> None:
        """Advance the assessment stage; DISCOVERY may be re-entered."""
        previous = self.stage
        self.stage = stage
        self.timeline.append({
            "at": datetime.now(timezone.utc).isoformat(),
            "from": f"stage:{previous.value}",
            "to": f"stage:{stage.value}",
            "actor": actor,
            "reason": reason,
        })
        self._touch()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "title": self.title,
            "description": self.description,
            "severity": normalize_severity(self.severity),
            "confidence": self.confidence,
            "affected_asset": self.affected_asset,
            "root_cause": self.root_cause,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": list(self.references),
            "state": self.state.value,
            "detection_module": self.detection_module,
            "validation_module": self.validation_module,
            "evidence_ids": list(self.evidence_ids),
            "reproduction": self.reproduction,
            "dedup_key": self.dedup_key or self.format_dedup_key(),
            "stage": self.stage.value,
            "timeline": list(self.timeline),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        state = VALID_STATES.get(data.get("state", "discovered"),
                                 FindingState.DISCOVERED)
        return cls(
            id=data.get("id", ""),
            engagement_id=data.get("engagement_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=data.get("severity", "info"),
            confidence=float(data.get("confidence", 0.5)),
            affected_asset=data.get("affected_asset", ""),
            root_cause=data.get("root_cause", ""),
            impact=data.get("impact", ""),
            remediation=data.get("remediation", ""),
            references=list(data.get("references", [])),
            state=state,
            stage=AssessmentStage(
                data.get("stage", "discovery")
            ) if data.get("stage") else AssessmentStage.DISCOVERY,
            detection_module=data.get("detection_module", ""),
            validation_module=data.get("validation_module", ""),
            evidence_ids=list(data.get("evidence_ids", [])),
            reproduction=data.get("reproduction", ""),
            dedup_key=data.get("dedup_key", ""),
            timeline=[dict(t) for t in data.get("timeline", [])],
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            metadata=dict(data.get("metadata", {})),
        )


class FindingRegistry:
    """In-memory + JSONL finding store with deduplication."""

    def __init__(self, path: Optional[str] = None):
        self._path = path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "findings.jsonl",
        )
        self.findings: Dict[str, Finding] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        f = Finding.from_dict(json.loads(line))
                        if f.id:
                            self.findings[f.id] = f
                    except (ValueError, TypeError, KeyError):
                        continue
        except OSError:
            pass

    def add(self, finding: Finding,
            replace: bool = False) -> "Finding":
        """Register a finding; ``replace`` allows upserting the same id.

        Without ``replace``, an equivalent finding (same dedup key) is
        returned instead of inserting a duplicate object.
        """
        if finding.id in self.findings and not replace:
            return self.findings[finding.id]
        if not finding.dedup_key:
            finding.dedup_key = finding.format_dedup_key()
        if not replace:
            existing = self.find_by_dedup(finding.dedup_key)
            if existing is not None:
                return existing
        self.findings[finding.id] = finding
        self._append(finding)
        return finding

    def _append(self, finding: Finding) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(finding.to_dict()) + "\n")

    def get(self, finding_id: str) -> Optional[Finding]:
        return self.findings.get(finding_id)

    def find_by_dedup(self, dedup_key: str) -> Optional[Finding]:
        for f in self.findings.values():
            if (f.dedup_key or f.format_dedup_key()) == dedup_key:
                return f
        return None

    def list(self, engagement_id: str = "",
             state: Optional[FindingState] = None) -> List[Finding]:
        items = self.findings.values()
        if engagement_id:
            items = (f for f in items if f.engagement_id == engagement_id)
        if state:
            items = (f for f in items if f.state == state)
        return sorted(items, key=lambda f: f.created_at)

    def transition(self, finding_id: str, new_state: str,
                   reason: str = "", actor: str = "") -> bool:
        finding = self.get(finding_id)
        if not finding:
            return False
        try:
            target = VALID_STATES[new_state]
        except KeyError:
            return False
        if not finding.transition(target, reason=reason, actor=actor):
            return False
        self._append(finding)
        return True

    def attach_evidence(self, finding_id: str,
                        evidence: Evidence) -> bool:
        finding = self.get(finding_id)
        if not finding:
            return False
        if evidence.id not in finding.evidence_ids:
            finding.evidence_ids.append(evidence.id)
            evidence.finding_id = finding_id
            finding._touch()
            self._append(finding)
        return True


# ============================================================================
# SECRET REDACTION
# ============================================================================


#: Metadata event marker used in place of exposing a secret value: the system
#: reports ``SECRET_DISCOVERED`` with provenance, never the secret itself.
SECRET_DISCOVERED = "SECRET_DISCOVERED"  # nosec B105


SECRET_PATTERNS: List[tuple] = [
    ("ssh_private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----.*?"
        r"-----END (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----", re.S)),
    ("pgp_private_key", re.compile(
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----.*?"
        r"-----END PGP PRIVATE KEY BLOCK-----", re.S)),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("github_token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("stripe_key", re.compile(r"(?i)(sk|pk)_(test|live)_[0-9a-zA-Z]{16,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"
                       r"(\.[A-Za-z0-9_-]{5,})?")),
    ("basic_auth_url", re.compile(r"(?i)(https?://)[^/:\s@]+:[^@\s/]+@")),
    ("password_assignment", re.compile(
        r"(?i)(?<![a-z0-9])(password|passwd|pwd|pass|secret|api[_-]?key|token|credential)"
        r"\s*[=:]\s*['\"]?[^\s'\"{}]{4,}['\"]?")),
    ("connection_string", re.compile(
        r"(?i)(mysql|postgres|mssql|redis|amqp|mongodb)[a-z+]*://"
        r"[^/\s:@]+:[^@\s/]+@")),
]


class SecretRedactor:
    """Redacts secret-like values and reports what was found (metadata)."""

    REDACTION_TAG = "[REDACTED:{}]"

    _SECRET_KEY_RE = re.compile(
        r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|credential|auth|cookie)")

    @classmethod
    def detect(cls, text: str) -> List[str]:
        """List secret kinds present in ``text`` (values never returned)."""
        if not text:
            return []
        found: List[str] = []
        for kind, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                found.append(kind)
        return found

    @classmethod
    def redact(cls, text: str) -> str:
        """Return ``text`` with secret-bearing substrings replaced by tags."""
        if not text:
            return text
        for kind, pattern in SECRET_PATTERNS:
            text = pattern.sub(cls.REDACTION_TAG.format(kind), text)
        return text

    @classmethod
    def redact_dict(cls, data: Any, depth: int = 4) -> Any:
        """Redact scalar leaves of nested dicts/lists; keys never removed."""
        if depth < 0:
            return data
        if isinstance(data, list):
            return [cls.redact_dict(v, depth - 1) for v in data]
        if not isinstance(data, dict):
            return data
        result: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, dict):
                result[key] = cls.redact_dict(value, depth - 1)
            elif isinstance(value, list):
                result[key] = [cls.redact_dict(v, depth - 1)
                               if isinstance(v, dict)
                               else (cls.redact(v) if isinstance(v, str) else v)
                               for v in value]
            elif isinstance(value, str):
                if cls._SECRET_KEY_RE.search(key) and value:
                    result[key] = cls.REDACTION_TAG.format("secret_key")
                else:
                    result[key] = cls.redact(value)
            else:
                result[key] = value
        return result


@dataclass
class CredentialMeta:
    """Metadata about a discovered credential — never the value itself."""

    engagement_id: str
    kind: str                 # e.g. password, api_key, ssh_key, token, cookie
    source: str               # where it was found (module + target)
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:16])
    location: str = ""        # file / url / service
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    validated: bool = False
    validated_at: str = ""
    validation_evidence_id: str = ""
    provenance: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "event": SECRET_DISCOVERED,
            "kind": self.kind,
            "source": self.source,
            "location": self.location,
            "discovered_at": self.discovered_at,
            "validated": self.validated,
            "validated_at": self.validated_at,
            "validation_evidence_id": self.validation_evidence_id,
            "provenance": self.provenance,
            "metadata": dict(self.metadata),
        }

    def to_metadata(self) -> Dict[str, Any]:
        """Metadata-only view for UIs, logs and LLM payloads.

        Always keyed by the ``SECRET_DISCOVERED`` marker with provenance
        fields; the secret value itself is never part of this object.
        """
        return {
            "event": SECRET_DISCOVERED,
            "kind": self.kind,
            "source": self.source,
            "location": self.location,
            "validated": self.validated,
            "provenance": self.provenance,
        }

    @classmethod
    def discovered(cls, engagement_id: str, kind: str, source: str,
                   location: str = "") -> "CredentialMeta":
        return cls(engagement_id=engagement_id, kind=kind, source=source,
                   location=location)

    def mark_validated(self, evidence_id: str = "") -> None:
        self.validated = True
        self.validated_at = datetime.now(timezone.utc).isoformat()
        self.validation_evidence_id = evidence_id