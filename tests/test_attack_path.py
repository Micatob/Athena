"""
tests/test_attack_path.py – Attack-path engine
==============================================
Covers:
  * node/edge creation, missing-endpoint rejection (fail-closed)
  * edge dedup / upsert
  * BFS path discovery and confirmed-only reachability
  * serialization round-trip
  * graph factory materialization from findings + sessions
"""

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.attack_path import (
    AttackGraph,
    EdgeRelation,
    NodeType,
    PathEdge,
    PathNode,
    PathState,
    build_graph,
)


@pytest.fixture()
def graph() -> AttackGraph:
    g = AttackGraph("eng-1")
    g.add_node(PathNode(id="h1", type=NodeType.HOST, label="web01",
                        state=PathState.CONFIRMED))
    g.add_node(PathNode(id="h2", type=NodeType.HOST, label="db01",
                        state=PathState.INFERRED))
    g.add_node(PathNode(id="u1", type=NodeType.USER, label="alice",
                        state=PathState.CONFIRMED))
    g.add_node(PathNode(id="n1", type=NodeType.NETWORK, label="10.0.0.0/24",
                        state=PathState.INFERRED))
    return g


class TestGraphBuilding:
    def test_add_edge_valid(self, graph):
        assert graph.upsert_edge(
            "h1", "u1", EdgeRelation.RUNS,
            state=PathState.CONFIRMED) is not None
        assert len(graph.edges) == 1

    def test_add_edge_unknown_endpoint_rejected(self, graph):
        assert graph.upsert_edge("h1", "ghost", EdgeRelation.RUNS) is None
        assert len(graph.edges) == 0

    def test_upsert_dedups(self, graph):
        graph.upsert_edge("h1", "u1", EdgeRelation.RUNS)
        graph.upsert_edge("h1", "u1", EdgeRelation.RUNS)
        assert len(graph.edges) == 1

    def test_neighbors(self, graph):
        graph.upsert_edge("h1", "u1", EdgeRelation.RUNS)
        graph.upsert_edge("h1", "n1", EdgeRelation.CAN_REACH,
                          state=PathState.INFERRED)
        labels = {n.label for n in graph.neighbors("h1")}
        assert labels == {"alice", "10.0.0.0/24"}


class TestPaths:
    def test_find_path(self, graph):
        graph.upsert_edge("h1", "h2", EdgeRelation.CAN_REACH,
                          state=PathState.INFERRED)
        graph.upsert_edge("h2", "u1", EdgeRelation.RUNS,
                          state=PathState.CONFIRMED)
        paths = graph.find_paths("h1", "u1")
        assert len(paths) == 1
        assert [n.label for n in paths[0]] == ["web01", "db01", "alice"]

    def test_find_path_none(self, graph):
        assert graph.find_paths("h1", "u1") == []

    def test_reachable(self, graph):
        graph.upsert_edge("h1", "h2", EdgeRelation.CAN_REACH,
                          state=PathState.INFERRED)
        labels = {n.label for n in graph.reachable("h1")}
        assert labels == {"db01"}

    def test_confirmed_paths_exclude_inferred(self, graph):
        graph.upsert_edge("h1", "u1", EdgeRelation.RUNS,
                          state=PathState.INFERRED)
        graph.upsert_edge("h1", "h2", EdgeRelation.CAN_REACH,
                          state=PathState.CONFIRMED)
        labels = {n.label for n in graph.confirmed_paths("h1")}
        # u1 is connected but only via an INFERRED edge -> excluded
        assert labels == {"db01"}

    def test_impact_summary_counts(self, graph):
        graph.upsert_edge("h1", "u1", EdgeRelation.RUNS,
                          state=PathState.CONFIRMED)
        summary = graph.impact_summary()
        assert summary["nodes"] == 4
        assert summary["confirmed"]["nodes"] == 2
        assert summary["inferred"]["nodes"] == 2
        assert summary["edges"] == 1


class TestSerialization:
    def test_round_trip(self, tmp_path):
        g = AttackGraph("eng-1")
        g.add_node(PathNode(id="a", type=NodeType.HOST, label="A",
                            state=PathState.CONFIRMED))
        g.add_node(PathNode(id="b", type=NodeType.SERVICE, label="ssh",
                            state=PathState.INFERRED))
        g.upsert_edge("a", "b", EdgeRelation.EXPOSES,
                      state=PathState.INFERRED)
        path = str(tmp_path / "graph.json")
        g.to_json(path)
        loaded = AttackGraph.load(path)
        assert loaded.engagement_id == "eng-1"
        assert len(loaded.nodes) == 2
        assert len(loaded.edges) == 1
        assert loaded.get_node("a").label == "A"

    def test_to_dict_structure(self, graph):
        data = graph.to_dict()
        assert set(data) >= {"engagement_id", "nodes", "edges"}
        assert all("state" in n and "type" in n for n in data["nodes"])


class TestFactory:
    def test_findings_become_vuln_nodes(self):
        graph = build_graph("eng-1", [
            {"title": "Remote Code Execution", "affected_asset": "web01",
             "severity": "critical", "state": "discovered",
             "detection_module": "scanner"},
            {"title": "SQLi", "affected_asset": "web01",
             "severity": "high", "state": "confirmed",
             "detection_module": "scanner"},
        ])
        vuln_nodes = [n for n in graph.nodes.values()
                      if n.type == NodeType.VULNERABILITY]
        assert len(vuln_nodes) == 2
        confirmed = [n for n in vuln_nodes
                     if n.state == PathState.CONFIRMED]
        assert [n.label for n in confirmed] == ["SQLi"]
        # vulnerability edge exists
        assert any(e.relation == EdgeRelation.VULNERABLE_TO
                   for e in graph.edges)

    def test_sessions_become_access_paths(self):
        graph = build_graph("eng-1", [], sessions=[{
            "id": "s-1", "target": "10.0.0.9", "state": "active",
            "platform": "linux", "shell_type": "reverse_tcp",
            "user": {"username": "root", "is_root": True},
        }])
        sessions = [n for n in graph.nodes.values()
                    if n.type == NodeType.ACCESS_SESSION]
        users = [n for n in graph.nodes.values()
                 if n.type == NodeType.USER]
        assert len(sessions) == 1
        assert [u.data.get("is_root") for u in users] == [True]
        assert any(e.relation == EdgeRelation.AUTHENTICATES
                   for e in graph.edges)
        assert any(e.relation == EdgeRelation.HAS_ACCESS_TO
                   for e in graph.edges)

    def test_dead_session_is_potential_not_confirmed(self):
        graph = build_graph("eng-1", [], sessions=[{
            "id": "s-1", "target": "10.0.0.9", "state": "dead",
            "user": {},
        }])
        sessions = [n for n in graph.nodes.values()
                    if n.type == NodeType.ACCESS_SESSION]
        assert sessions[0].state == PathState.POTENTIAL

    def test_network_nodes_inferred(self):
        graph = build_graph("eng-1", [], networks=[{
            "name": "dmz", "cidr": "10.0.0.0/24",
            "hosts": ["10.0.0.9", "10.0.0.10"],
        }])
        networks = [n for n in graph.nodes.values()
                    if n.type == NodeType.NETWORK]
        assert networks[0].state == PathState.INFERRED
        assert any(e.relation == EdgeRelation.CAN_REACH
                   for e in graph.edges)