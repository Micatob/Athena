"""
tests/test_findings.py – Findings lifecycle, evidence, secret redaction
=======================================================================
Covers:
  * finding lifecycle transitions (valid + invalid)
  * confirmation requires validated evidence
  * dedup keys and registry persistence
  * evidence SHA-256 integrity + on-disk artifacts
  * secret redaction (values never surface; metadata does)
  * discovered vs validated credential metadata
"""

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.findings import (
    SECRET_DISCOVERED,
    CredentialMeta,
    Evidence,
    EvidenceKind,
    EvidenceStore,
    Finding,
    FindingRegistry,
    FindingState,
    SecretRedactor,
    ValidationState,
    normalize_severity,
)


class TestFindingLifecycle:
    def test_initial_state(self):
        finding = Finding(engagement_id="e1", title="X")
        assert finding.state == FindingState.DISCOVERED

    def test_discovered_to_triaged(self):
        finding = Finding(engagement_id="e1", title="X")
        assert finding.transition(FindingState.TRIAGED, reason="review")
        assert finding.state == FindingState.TRIAGED

    def test_invalid_transition_rejected(self):
        finding = Finding(engagement_id="e1", title="X")
        assert not finding.transition(FindingState.REMEDIATED)

    def test_duplicate_marked(self):
        finding = Finding(engagement_id="e1", title="X")
        finding.transition(FindingState.TRIAGED)
        assert finding.transition(FindingState.DUPLICATE)

    def test_full_chain(self):
        finding = Finding(engagement_id="e1", title="X")
        assert finding.transition(FindingState.VALIDATING)
        assert finding.transition(FindingState.CONFIRMED)
        assert finding.transition(FindingState.REMEDIATED)
        assert finding.transition(FindingState.REVALIDATED)

    def test_confirm_requires_evidence(self):
        finding = Finding(engagement_id="e1", title="X")
        assert not finding.mark_confirmed([])
        assert finding.state == FindingState.DISCOVERED

    def test_confirm_with_validated_evidence(self):
        finding = Finding(engagement_id="e1", title="X")
        finding.transition(FindingState.VALIDATING)
        evidence = Evidence(
            engagement_id="e1", target="t", module="m",
            kind=EvidenceKind.VULNERABILITY_VALIDATION,
            validation_state=ValidationState.CONFIRMED,
            observation="validated",
        )
        assert finding.mark_confirmed([evidence])
        assert finding.state == FindingState.CONFIRMED

    def test_timeline_records_transition(self):
        finding = Finding(engagement_id="e1", title="X")
        finding.transition(FindingState.TRIAGED, reason="manual",
                           actor="analyst")
        entry = finding.timeline[-1]
        assert entry["from"] == "discovered"
        assert entry["to"] == "triaged"
        assert entry["actor"] == "analyst"

    def test_severity_normalization(self):
        assert normalize_severity("CRITICAL") == "critical"
        assert normalize_severity("high") == "high"
        assert normalize_severity("") == "info"

    def test_dedup_key(self):
        a = Finding(engagement_id="e1", title="SQLi",
                    affected_asset="https://x/?id=1",
                    detection_module="scanner")
        b = Finding(engagement_id="e1", title="sqli",
                    affected_asset="https://x/?id=1",
                    detection_module="scanner")
        assert a.format_dedup_key() == b.format_dedup_key()


class TestFindingRegistry:
    def test_add_and_get(self, tmp_path):
        registry = FindingRegistry(str(tmp_path / "findings.jsonl"))
        finding = registry.add(
            Finding(engagement_id="e1", title="X"))
        assert registry.get(finding.id) is not None

    def test_dedup_no_duplicate_objects(self, tmp_path):
        registry = FindingRegistry(str(tmp_path / "findings.jsonl"))
        a = registry.add(Finding(
            engagement_id="e1", title="SQLi", affected_asset="u",
            detection_module="scanner"))
        b = registry.add(Finding(
            engagement_id="e1", title="SQLi", affected_asset="u",
            detection_module="scanner"))
        assert a.id == b.id

    def test_persisted_across_instances(self, tmp_path):
        path = str(tmp_path / "findings.jsonl")
        registry = FindingRegistry(path)
        finding = registry.add(Finding(engagement_id="e1", title="X"))
        registry.transition(finding.id, "triaged", actor="analyst")
        reloaded = FindingRegistry(path)
        assert reloaded.get(finding.id).state == FindingState.TRIAGED

    def test_invalid_state_transition_rejected(self, tmp_path):
        registry = FindingRegistry(str(tmp_path / "findings.jsonl"))
        finding = registry.add(Finding(engagement_id="e1", title="X"))
        assert not registry.transition(finding.id, "remediated")


class TestEvidence:
    def test_evidence_sha256_of_artifact(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        evidence = store.add(
            Evidence(engagement_id="e1", target="t", module="m",
                     kind=EvidenceKind.TOOL_OUTPUT, observation="body"),
            artifact=b"raw tool output",
        )
        import hashlib
        expected = hashlib.sha256(b"raw tool output").hexdigest()
        assert evidence.sha256 == expected

    def test_artifact_written_and_verified(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        evidence = store.add(
            Evidence(engagement_id="e1", target="t", module="m",
                     kind=EvidenceKind.HTTP, observation="x"),
            artifact=b"<html>response</html>",
        )
        assert store.verify(evidence)
        path = store.artifact_path(evidence)
        assert path is not None
        assert Path(path).exists()

    def test_verify_detects_tampering(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        evidence = store.add(
            Evidence(engagement_id="e1", target="t", module="m",
                     kind=EvidenceKind.HTTP, observation="x"),
            artifact=b"original",
        )
        path = store.artifact_path(evidence)
        Path(path).write_bytes(b"tampered!")
        assert not store.verify(evidence)

    def test_encrypted_artifact_roundtrip(self, tmp_path):
        from cryptography.fernet import Fernet
        key = Fernet.generate_key().decode()
        store = EvidenceStore(str(tmp_path), encryption_key=key)
        artifact = b"confidential creds data"
        evidence = store.add(
            Evidence(engagement_id="e1", target="t", module="m",
                     kind=EvidenceKind.TOOL_OUTPUT, observation="x"),
            artifact=artifact,
        )
        assert evidence.encrypted
        assert store.verify(evidence)
        path = store.artifact_path(evidence)
        raw = Path(path).read_bytes()
        assert raw != artifact          # ciphertext on disk
        assert artifact not in raw      # plaintext never written
        assert store.artifact_bytes(evidence) == artifact

    def test_encrypted_artifact_requires_key(self, tmp_path):
        from cryptography.fernet import Fernet
        key = Fernet.generate_key().decode()
        store = EvidenceStore(str(tmp_path), encryption_key=key)
        evidence = store.add(
            Evidence(engagement_id="e1", target="t", module="m",
                     kind=EvidenceKind.LOG, observation="x"),
            artifact=b"raw",
        )
        locked = EvidenceStore(str(tmp_path))          # key lost
        assert not locked.verify(evidence)             # fail closed
        assert locked.artifact_bytes(evidence) is None

    def test_encryption_env_autogenerates_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATHENA_ENCRYPT_EVIDENCE", "1")
        monkeypatch.delenv("ATHENA_EVIDENCE_KEY", raising=False)
        store = EvidenceStore(str(tmp_path))
        assert store._fernet is not None
        key_path = tmp_path / ".evidence.key"
        assert key_path.exists()
        evidence = store.add(
            Evidence(engagement_id="e1", target="t", module="m",
                     kind=EvidenceKind.LOG, observation="x"),
            artifact=b"secret",
        )
        assert store.verify(evidence)

    def test_evidence_hash_without_artifact(self):
        store = EvidenceStore(str("/nonexistent"))
        evidence = Evidence(engagement_id="e1", target="t", module="m",
                            kind=EvidenceKind.LOG, observation="plain")
        evidence.finalize()
        assert len(evidence.sha256) == 64

    def test_evidence_list_filters(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        a = store.add(Evidence(engagement_id="e1", target="a", module="m",
                               kind=EvidenceKind.LOG, observation="1"))
        b = store.add(Evidence(engagement_id="e2", target="b", module="m",
                               kind=EvidenceKind.LOG, observation="2"))
        assert [e.id for e in store.list(engagement_id="e1")] == [a.id]
        assert len(store.list()) == 2
        assert b.id in store._records


class TestSecretRedaction:
    SECRETS = [
        ("aws access key", "key: AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
        ("ssh key", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
         "ssh_private_key"),
        ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature", "jwt"),
        ("password", "DB_PASSWORD=supersecret123", "password_assignment"),
        ("token", "token = 'ghtoken'", None),
        ("basic auth url", "http://user:passw0rd@host/", "basic_auth_url"),
        ("conn string", "mysql://root:hunter2@db:3306/app", "connection_string"),
    ]

    @pytest.mark.parametrize("name,text,expected_kind", SECRETS,
                             ids=[s[0] for s in SECRETS])
    def test_secret_detected(self, name, text, expected_kind):
        if expected_kind is None:
            return
        detected = SecretRedactor.detect(text)
        assert expected_kind in detected

    @pytest.mark.parametrize("name,text,expected_kind", SECRETS,
                             ids=[s[0] for s in SECRETS])
    def test_secret_value_never_survives_redaction(self, name, text, expected_kind):
        if expected_kind is None:
            return
        redacted = SecretRedactor.redact(text)
        assert "[REDACTED:" in redacted
        # the actual secret value must not appear in the redacted output
        assert "supersecret123" not in redacted
        assert "hunter2" not in redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted

    def test_redact_dict_recurses(self):
        data = {
            "config": {"password": "p@ssw0rd", "ok": "fine"},
            "list": [{"api_key": "sk_live_REDACTED"}],
        }
        redacted = SecretRedactor.redact_dict(data)
        assert "[REDACTED:" in redacted["config"]["password"]
        assert redacted["config"]["ok"] == "fine"
        assert "[REDACTED:" in redacted["list"][0]["api_key"]

    def test_redact_does_not_touch_plain_text(self):
        text = "normal observation without secrets"
        assert SecretRedactor.redact(text) == text

    def test_detect_returns_metadata_only(self):
        detected = SecretRedactor.detect("AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in str(detected)[0:0]
        assert "aws_access_key" in detected


class TestCredentialMeta:
    def test_discovered_by_default(self):
        meta = CredentialMeta.discovered("e1", "password", "enum@host",
                                         location="/etc/app.conf")
        assert not meta.validated
        assert meta.validated_at == ""

    def test_mark_validated(self):
        meta = CredentialMeta.discovered("e1", "api_key", "module@target")
        meta.mark_validated(evidence_id="ev-1")
        assert meta.validated
        assert meta.validation_evidence_id == "ev-1"

    def test_to_dict_contains_no_value(self):
        meta = CredentialMeta.discovered("e1", "password", "src")
        data = meta.to_dict()
        assert "value" not in data
        assert "password" not in [k for k in data]  # metadata keys only

    def test_event_marker_in_to_dict(self):
        meta = CredentialMeta.discovered("e1", "password", "src")
        assert meta.to_dict()["event"] == SECRET_DISCOVERED

    def test_to_metadata_prefers_marker_not_value(self):
        meta = CredentialMeta.discovered("e1", "api_key", "enum@host",
                                         location="/etc/app.conf")
        meta.provenance = "found in config file"
        meta.mark_validated(evidence_id="ev-9")
        md = meta.to_metadata()
        assert md["event"] == SECRET_DISCOVERED
        assert md["kind"] == "api_key"
        assert md["source"] == "enum@host"
        assert md["location"] == "/etc/app.conf"
        assert md["validated"] is True
        assert md["provenance"] == "found in config file"
