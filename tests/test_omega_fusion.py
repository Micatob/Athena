"""Omega fusion - no-degradation + power tests."""
import asyncio
import sys
from pathlib import Path

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.graph_lite import GraphLite
from modules.settings_registry import get, as_dict, describe
from modules.hard_guardrail import is_hard_blocked, hard_guardrail_reason, RoE
from modules.operation_control import OperationGate, ToolConfirmationPolicy
from modules.engagement import Engagement
from modules.serialized_scan import scan_response
from modules.supply_chain_recon import harvest_packages, verdict_packages
from modules.tls_scan import tls_grab


class TestGraphLite:
    def test_merge_not_duplicate(self):
        g = GraphLite(engagement_id="t1", path=":memory:")
        g.add_node("Host", "h", {"a": 1})
        g.add_node("Host", "h", {"a": 2})
        assert g.stats()["node_total"] == 1
        g.add_edge("Target", "t", "HAS_PORT", "Port", "t:80")
        g.add_edge("Target", "t", "HAS_PORT", "Port", "t:80")
        assert g.stats()["edge_total"] == 1
        g.close()

    def test_ingest_discovery(self):
        g = GraphLite(engagement_id="t2", path=":memory:")
        s = g.ingest_discovery({"urls": ["https://a/"], "subdomains": ["x.a"],
                                "ports": [{"port": 80}], "technologies": ["nginx"]}, "a")
        assert s["node_total"] >= 4
        g.close()


class TestRegistry:
    def test_bounds_and_stealth_cap(self):
        assert get("SCANNING_THREADS", stealth=True) <= 20
        assert get("HTTP_TIMEOUT") >= 2
        assert len(describe()) >= 10
        assert "SCANNING_THREADS" in as_dict()


class TestGuardrail:
    def test_hard_blocked(self):
        assert is_hard_blocked("https://whitehouse.gov")
        assert is_hard_blocked("army.mil")
        assert is_hard_blocked("un.int")
        assert not is_hard_blocked("https://example.com")
        assert not is_hard_blocked("1.2.3.4")
        assert hard_guardrail_reason("https://example.com") == ""

    def test_roe_exclusion_wins(self):
        roe = RoE(targets=["*.example.com"], exclusions=["bad.example.com"])
        assert not roe.check("https://bad.example.com").get("allowed")
        assert roe.check("https://good.example.com").get("allowed")
        roe2 = RoE(targets=["*.example.com"])
        assert not roe2.check("https://other.com").get("allowed")


class TestGateExtension:
    def test_old_behaviour_preserved(self):
        eng = Engagement(name="t", operator="o", in_scope_targets=["example.com"])
        gate = OperationGate(engagement=eng, operator="tester")
        plan = gate.plan(action="scan", rationale="r", target="example.com", technique="recon")
        res = gate.authorize(plan)
        assert res.allowed

    def test_hard_guardrail_denies_even_in_scope(self):
        eng = Engagement(name="t", operator="o", in_scope_targets=["whitehouse.gov"])
        gate = OperationGate(engagement=eng, operator="tester")
        plan = gate.plan(action="scan", rationale="r", target="whitehouse.gov", technique="recon")
        res = gate.authorize(plan)
        assert not res.allowed

    def test_tool_confirmation(self):
        pol = ToolConfirmationPolicy(require_confirmation=True)
        assert not pol.check("nuclei", "example.com")["allowed"]
        assert pol.check("query_graph", "example.com")["allowed"]
        pol.grant("nuclei", "example.com")
        assert pol.check("nuclei", "example.com")["allowed"]


class TestPassiveScans:
    def test_serialized_never_deserializes(self):
        out = scan_response({"X-Data": "rO0AB blah"}, ["O:8:\"User\":1:{s:4:\"name\";}"], ["?x=1"])
        assert out["findings"]
        assert all(f["severity"] == "info" and f["needs_agent_confirmation"] for f in out["findings"])

    def test_supply_chain_offline(self):
        pkgs = harvest_packages(['import x from "react"; require("lodash")'], ["nginx"])
        assert "react" in pkgs and "lodash" in pkgs
        v = verdict_packages(pkgs)
        assert v["offline"] and v["sbom_components"] >= 2

    def test_tls_never_raises(self):
        out = tls_grab("https://127.0.0.1:9")
        assert "host" in out  # error path still structured


class TestOrchestrator:
    def test_omega_blocked_target(self):
        from modules.recon_orchestrator import omega_recon
        out = asyncio.run(omega_recon("https://whitehouse.gov", {}))
        assert out.get("blocked") is True
        assert out.get("findings") == []

    def test_omega_empty_never_raises(self):
        from modules.recon_orchestrator import omega_recon
        out = asyncio.run(omega_recon("https://example.com", {}, enabled=["serialized", "supply_chain"]))
        assert "tools" in out and "findings" in out
