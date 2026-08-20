"""
tests/test_post_assessment.py – Post-exploitation assessment integration
========================================================================
Covers:
  * engagement-bound session creation + unauthorized target rejection
  * session termination
  * structured host / privilege / network assessment via a fake target
  * fail-closed assessment without an engagement
  * failed-module recovery (one module fails, others complete)
  * phase timeout handling in the orchestrator
  * secret redaction in phase logs
  * verified cleanup (success only when removal is confirmed)
"""

import asyncio
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.engagement import Engagement
from modules.findings import EvidenceStore


# ---------------------------------------------------------------------------
# Fake remote target
# ---------------------------------------------------------------------------


class FakeTarget:
    """Simulates a compromised Linux host with canned command output."""

    def __init__(self):
        self.files = {"/tmp/atn_test", "/tmp/.bash_history"}
        self.calls = []

    async def exec(self, command: str, timeout: int = 30) -> str:
        self.calls.append(command)
        cmd = command
        if cmd.startswith("whoami") or cmd == "whoami":
            return "webuser"
        if cmd.startswith("id"):
            return "uid=1001(webuser) gid=1001(webuser) groups=1001(webuser),27(sudo)"
        if "sudo -l" in cmd:
            return ("Matching Defaults entries for webuser:\n"
                    "User webuser may run the following commands on web01:\n"
                    "(root) NOPASSWD: /usr/bin/vim")
        if "shadow" in cmd:
            return "[!] Access denied"
        if "passwd" in cmd:
            return "root:x:0:0:root:/root:/bin/bash\nwebuser:x:1001:1001::/home/webuser:/bin/bash"
        if "uname" in cmd:
            return "Linux web01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
        if "os-release" in cmd:
            return 'PRETTY_NAME="Ubuntu 22.04.3 LTS"'
        if cmd == "hostname":
            return "web01"
        if "groups" in cmd:
            return "webuser sudo"
        if "env" in cmd:
            return ("PATH=/usr/bin\nTERM=xterm\n"
                    "DB_PASSWORD=Sup3rSecretValue12")
        if "find / -perm -4000" in cmd:
            return "/usr/bin/passwd\n/usr/bin/vim.basic\n/usr/bin/find"
        if "find / -writable" in cmd:
            return "/tmp\n/var/tmp\n/opt/backup"
        if "ip -o addr" in cmd or "ifconfig" in cmd:
            return ("2: eth0: <BROADCAST> mtu 1500 inet 10.0.0.9/24 brd 10.0.0.255\n"
                    "3: eth1: inet 192.168.5.4/24")
        if "ip route" in cmd or "route -n" in cmd:
            return "default via 10.0.0.1 dev eth0\n10.0.0.0/24 dev eth0 proto kernel"
        if "iptables" in cmd:
            return "MASQUERADE all --"
        if "crontab" in cmd or "ls -la /etc/cron" in cmd:
            return "[!] Access denied"
        if "cat /etc/hosts" in cmd:
            return "127.0.0.1 localhost\n10.0.0.9 web01"
        if "resolv" in cmd:
            return "nameserver 10.0.0.2"
        if "ss -tulpn" in cmd or "netstat -tulpn" in cmd:
            return "LISTEN 0 128 0.0.0.0:80 users:((nginx))\nLISTEN 0 128 127.0.0.1:3306 users:((mysqld))"
        if "ps aux" in cmd:
            return "root 1 init\nwww-data 42 nginx: master"
        if "ssh" in cmd and ("id_rsa" in cmd or "authorized_keys" in cmd):
            return "[!] No keys"
        if "docker" in cmd:
            return "[!] Docker not available"
        if "mount" in cmd or "fstab" in cmd or "df -h" in cmd:
            return "overlay on / type overlay (rw)\n/dev/sda1 on / type ext4 (rw)"
        if "getcap" in cmd or "cap_setuid" in cmd:
            return ""
        if "test -e /tmp/atn_test" in cmd:
            return "EXISTS" if "/tmp/atn_test" in self.files else "GONE"
        if "test -s ~/.bash_history" in cmd or "test -e ~/.bash_history" in cmd:
            return "EMPTY_OR_GONE"
        if "rm -f /tmp/atn_test" in cmd or "shred" in cmd:
            self.files.discard("/tmp/atn_test")
            return ""
        if "ls -d /tmp/atn_" in cmd or "ls /tmp/atn_" in cmd:
            remaining = " ".join(f for f in self.files if f.startswith("/tmp/atn"))
            return remaining + "\n" if remaining else ""
        if "ls /tmp/exploit_" in cmd:
            return ""
        if "ls /tmp/pwnkit" in cmd:
            return ""
        if "echo atn_banner" in cmd:
            return "atn_banner"
        return ""


class _FakeTransport:
    """Minimal transport adapter so PostSession.exec() reaches FakeTarget."""

    def __init__(self, target):
        self._target = target

    async def execute(self, command, timeout=30):
        return await self._target.exec(command, timeout)

    async def upload(self, local_path, remote_path):
        return True

    async def download(self, remote_path, local_path):
        return True

    async def close(self):
        pass


def attach_target(session, target) -> None:
    session.transport = _FakeTransport(target)


@pytest.fixture()
def engagement() -> Engagement:
    return Engagement(
        name="Assessment Test",
        operator="tester",
        in_scope_targets=["10.0.0.0/24"],
        include_subdomains=True,
    )


@pytest.fixture()
def fake_target() -> FakeTarget:
    return FakeTarget()


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------


class TestSessionLifecycle:
    def test_create_for_engagement(self, fake_target, engagement):
        from modules.post_exploitation.session import SessionManager
        mgr = SessionManager()
        session = mgr.create_for_engagement("10.0.0.9", engagement,
                                            execution_context="manual")
        assert session.engagement_id == engagement.id
        assert session.scope_decision == "allowed"
        assert mgr.get(session.id) is session

    def test_unauthorized_target_rejected(self, fake_target, engagement):
        from modules.post_exploitation.session import SessionManager
        mgr = SessionManager()
        with pytest.raises(ValueError):
            mgr.create_for_engagement("192.168.99.99", engagement)

    def test_no_engagement_rejected(self, fake_target):
        from modules.post_exploitation.session import SessionManager
        mgr = SessionManager()
        with pytest.raises(ValueError):
            mgr.create_for_engagement("10.0.0.9", None)

    def test_termination_sets_dead(self, fake_target, engagement):
        from modules.post_exploitation import SessionState
        from modules.post_exploitation.session import SessionManager
        mgr = SessionManager()
        session = mgr.create_for_engagement("10.0.0.9", engagement)

        async def _kill():
            return await mgr.kill(session.id)

        asyncio.run(_kill())
        assert mgr.get(session.id).state == SessionState.DEAD


# ---------------------------------------------------------------------------
# Structured assessment
# ---------------------------------------------------------------------------


class TestHostAssessment:
    @pytest.mark.asyncio
    async def test_host_assessment_structured(self, fake_target, engagement,
                                              tmp_path):
        from modules.post_exploitation import Platform, PostSession
        from modules.post_exploitation.assessment import HostAssessor
        store = EvidenceStore(str(tmp_path / "evidence"))

        session = PostSession(id="s1", target="10.0.0.9",
                              platform=Platform.LINUX)
        attach_target(session, fake_target)

        config = {"engagement": engagement, "evidence_store": store}
        result = await HostAssessor().run(session, config)
        assert result.success
        host = result.details["host"]
        assert host["hostname"] == "web01"
        assert host["os"]["platform"] == "linux"
        assert host["os"]["kernel"].startswith("5.15")
        assert host["execution_context"]["user"] == "webuser"
        assert host["privilege_level"] == "non_privileged"
        assert host["listening_services"]

        evidence = store.get(result.details["evidence_id"])
        assert evidence is not None
        assert store.verify(evidence)
        # secrets from `env` output must not appear in evidence
        assert "Sup3rSecretValue12" not in evidence.observation

    @pytest.mark.asyncio
    async def test_assessment_denied_without_engagement(self, fake_target):
        from modules.post_exploitation import Platform, PostSession
        from modules.post_exploitation.assessment import (
            AssessmentGateError, HostAssessor,
        )
        session = PostSession(id="s1", target="10.0.0.9",
                              platform=Platform.LINUX)
        attach_target(session, fake_target)
        with pytest.raises(AssessmentGateError):
            await HostAssessor().run(session, {})


class TestPrivilegeAssessment:
    @pytest.mark.asyncio
    async def test_privilege_detection_only(self, fake_target, engagement,
                                            tmp_path):
        from modules.post_exploitation import Platform, PostSession
        from modules.post_exploitation.assessment import PrivilegeAssessor
        store = EvidenceStore(str(tmp_path / "evidence"))

        session = PostSession(id="s1", target="10.0.0.9",
                              platform=Platform.LINUX)
        attach_target(session, fake_target)

        result = await PrivilegeAssessor().run(
            session, {"engagement": engagement, "evidence_store": store})
        assert result.success
        details = result.details["privilege"]
        assert details["privilege_level"] == "non_privileged"
        weakness_types = {w["type"] for w in details["weaknesses"]}
        assert "sudo_policy" in weakness_types  # NOPASSWD vim detected
        assert "suid_gtfobins" in weakness_types
        # active escalation is classified as CONTROLLED_VALIDATION
        assert any(v["technique"] == "controlled_validation"
                   for v in details["validation_required"])


class TestNetworkAssessment:
    @pytest.mark.asyncio
    async def test_network_relationships(self, fake_target, engagement,
                                         tmp_path):
        from modules.post_exploitation import Platform, PostSession
        from modules.post_exploitation.assessment import NetworkContextAssessor
        store = EvidenceStore(str(tmp_path / "evidence"))

        session = PostSession(id="s1", target="10.0.0.9",
                              platform=Platform.LINUX)
        attach_target(session, fake_target)

        result = await NetworkContextAssessor().run(
            session, {"engagement": engagement, "evidence_store": store})
        assert result.success
        net = result.details["network"]
        segments = {s["cidr"] for s in net["segments"]}
        assert "10.0.0.0/24" in segments
        assert "192.168.5.0/24" in segments
        rels = net["relationships"]
        assert any(r["relation"] == "connected_to" for r in rels)
        assert any(r["relation"] == "default_route_via" for r in rels)
        assert any(r["relation"] == "exposes" for r in rels)
        # host straddles two segments -> boundary detected
        assert any(b["type"] == "segment_boundary"
                   for b in net["security_boundaries"])


class TestFullAssessmentFlow:
    @pytest.mark.asyncio
    async def test_assess_session_all_modules(self, fake_target, engagement,
                                              tmp_path):
        from modules.post_exploitation import Platform, PostSession
        from modules.post_exploitation.assessment import assess_session
        store = EvidenceStore(str(tmp_path / "evidence"))

        session = PostSession(id="s1", target="10.0.0.9",
                              platform=Platform.LINUX)
        attach_target(session, fake_target)

        results = await assess_session(session, engagement,
                                       evidence_store=store)
        assert results["engagement_id"] == engagement.id
        modules = results["modules"]
        assert all(m["status"] == "completed"
                   for m in modules.values())
        assert results["modules"]["host_assessment"]["success"]

    @pytest.mark.asyncio
    async def test_failed_module_recovery(self, fake_target, engagement,
                                          tmp_path):
        """One broken module must not destroy the engagement assessment."""
        from modules.post_exploitation import Platform, PostSession
        from modules.post_exploitation.assessment import (
            AssessmentModule, assess_session,
        )
        store = EvidenceStore(str(tmp_path / "evidence"))

        class ExplodingModule(AssessmentModule):
            module_id = "exploding"
            name = "Exploding"
            description = "always raises"
            async def run(self, session, config):
                raise RuntimeError("boom")

        session = PostSession(id="s1", target="10.0.0.9",
                              platform=Platform.LINUX)
        attach_target(session, fake_target)

        results = await assess_session(session, engagement,
                                       evidence_store=store)
        assert results["modules"]["host_assessment"]["status"] == "completed"
        assert results["modules"]["privilege_assessment"]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_assess_session_denied_out_of_scope(self, fake_target,
                                                      tmp_path):
        from modules.post_exploitation import Platform, PostSession
        from modules.post_exploitation.assessment import assess_session
        store = EvidenceStore(str(tmp_path / "evidence"))
        out_scope = Engagement(name="t", operator="o",
                               in_scope_targets=["internal.corp"])
        session = PostSession(id="s1", target="10.0.0.9",
                              platform=Platform.LINUX)
        attach_target(session, fake_target)
        results = await assess_session(session, out_scope,
                                       evidence_store=store)
        assert all(
            m["status"] == "denied"
            for m in results["modules"].values())


# ---------------------------------------------------------------------------
# Orchestrator behavior
# ---------------------------------------------------------------------------


class TestOrchestrator:
    @pytest.mark.asyncio
    async def test_phase_timeout(self, fake_target, engagement, tmp_path):
        from modules.post_exploitation import PostModule, PostPhase
        from modules.post_exploitation.orchestrator import PostOrchestrator

        class SlowModule(PostModule):
            name = "slow"
            phase = PostPhase.ENUMERATION
            async def run(self, session, config):
                await asyncio.sleep(5)
                return None

        orchestrator = PostOrchestrator(engagement=engagement)
        orchestrator._log_file = str(tmp_path / "post.log")
        session = orchestrator.session_mgr.create_for_engagement(
            "10.0.0.9", engagement)
        attach_target(session, fake_target)

        result = await orchestrator._run_phase_with_timeout(
            SlowModule(), session, PostPhase.ENUMERATION, timeout=1)
        assert not result.success
        assert "Timeout" in (result.error or "")

    @pytest.mark.asyncio
    async def test_failed_phase_returns_structured_error(
            self, fake_target, engagement, tmp_path):
        from modules.post_exploitation import PostModule, PostPhase
        from modules.post_exploitation.orchestrator import PostOrchestrator

        class BrokenModule(PostModule):
            name = "broken"
            phase = PostPhase.ENUMERATION
            async def run(self, session, config):
                raise RuntimeError("module exploded")

        orchestrator = PostOrchestrator(engagement=engagement)
        orchestrator._log_file = str(tmp_path / "post.log")
        session = orchestrator.session_mgr.create_for_engagement(
            "10.0.0.9", engagement)
        attach_target(session, fake_target)

        result = await orchestrator._run_phase_with_timeout(
            BrokenModule(), session, PostPhase.ENUMERATION, timeout=30)
        assert not result.success
        assert "module exploded" in (result.error or "")

    @pytest.mark.asyncio
    async def test_phase_log_redacts_secrets(self, fake_target, engagement,
                                             tmp_path):
        from modules.post_exploitation import PostModule, PostPhase, PostResult
        from modules.post_exploitation.orchestrator import PostOrchestrator

        class LeakyModule(PostModule):
            name = "leaky"
            phase = PostPhase.ENUMERATION
            async def run(self, session, config):
                return PostResult(
                    phase=self.phase, success=True, session_id=session.id,
                    target=session.target,
                    details={"secret": "DB_PASSWORD=Sup3rSecretValue12",
                             "ok": "plain"},
                    findings=[{"type": "x", "severity": "info",
                               "description": "token=AIzaSyDummyKey1234567890abcdefghijklmnopq"}],
                )

        log_path = tmp_path / "post.jsonl"
        orchestrator = PostOrchestrator(engagement=engagement)
        orchestrator._log_file = str(log_path)
        session = orchestrator.session_mgr.create_for_engagement(
            "10.0.0.9", engagement)
        attach_target(session, fake_target)

        result = await LeakyModule().run(session, {})
        orchestrator._log_result(result)

        content = log_path.read_text(encoding="utf-8")
        assert "Sup3rSecretValue12" not in content
        assert "AIzaSyDummyKey1234567890abcdefghijklmnopq" not in content
        assert "[REDACTED:" in content
        assert "plain" in content

    @pytest.mark.asyncio
    async def test_auto_assess_attaches_results(self, fake_target, engagement,
                                                tmp_path):
        from modules.post_exploitation import Platform
        from modules.post_exploitation.orchestrator import PostOrchestrator
        orchestrator = PostOrchestrator(engagement=engagement)
        orchestrator._log_file = str(tmp_path / "post.log")
        orchestrator.config["auto_assess"] = True
        orchestrator.config["only_phases"] = ["cleanup"]  # skip real phases
        orchestrator.config["skip_phases"] = ["foothold", "enumeration",
                                              "privesc", "lateral",
                                              "data_collection",
                                              "persistence", "cleanup"]
        from modules.findings import EvidenceStore
        orchestrator.config["evidence_store"] = EvidenceStore(
            str(tmp_path / "evidence"))

        session = orchestrator.session_mgr.create_for_engagement(
            "10.0.0.9", engagement, platform=Platform.LINUX)
        attach_target(session, fake_target)

        await orchestrator.run_full_chain(session)
        assert session.assessment_results
        assert "host_assessment" in session.assessment_results["modules"]
        assert "assessment" in orchestrator._phase_results


# ---------------------------------------------------------------------------
# Cleanup verification
# ---------------------------------------------------------------------------


class TestCleanupVerification:
    @pytest.mark.asyncio
    async def test_cleanup_verified_when_removed(self, fake_target, tmp_path):
        from modules.post_exploitation import Platform, PostSession
        from modules.post_exploitation.cleanup import CleanupModule
        session = PostSession(id="s1", target="10.0.0.9",
                              platform=Platform.LINUX)
        attach_target(session, fake_target)

        result = await CleanupModule().run(session, {
            "cleanup_timeout": 60, "clean_logs": False,
        })
        assert "test -e /tmp/atn_test" in fake_target.calls[-1] or \
               any("rm -f /tmp/atn_test" in c for c in fake_target.calls)
        assert result.details["cleanup_verified"] is True

    @pytest.mark.asyncio
    async def test_cleanup_not_verified_when_artifact_remains(self, tmp_path):
        from modules.post_exploitation import Platform, PostSession
        from modules.post_exploitation.cleanup import CleanupModule

        class StubbornTarget:
            async def exec(self, command, timeout=30):
                if "rm -f /tmp/atn_test" in command or "shred" in command:
                    return ""  # removal silently fails
                if "test -e /tmp/atn_test" in command or "ls -d /tmp/atn_" in command or "ls /tmp/atn_" in command:
                    return "/tmp/atn_test"
                if "ls /tmp/exploit_" in command or "ls /tmp/pwnkit" in command:
                    return ""
                if "test -s" in command:
                    return "EMPTY_OR_GONE"
                return ""

        session = PostSession(id="s1", target="10.0.0.9",
                              platform=Platform.LINUX)
        attach_target(session, StubbornTarget())

        result = await CleanupModule().run(session, {
            "cleanup_timeout": 60, "clean_logs": False,
        })
        assert result.details["cleanup_verified"] is False
        assert result.details["final_sweep"]["status"] == "failed"
        assert not result.success

    @pytest.mark.asyncio
    async def test_cleanup_requires_confirmation_when_configured(
            self, fake_target):
        from modules.post_exploitation import Platform, PostSession
        from modules.post_exploitation.cleanup import CleanupModule
        session = PostSession(id="s1", target="10.0.0.9",
                              platform=Platform.LINUX)
        attach_target(session, fake_target)
        result = await CleanupModule().run(session, {
            "require_cleanup_confirmation": True, "cleanup_confirmed": False,
        })
        assert not result.success
        assert "confirmation" in (result.error or "")