"""
Athena Attack-Path Engine
=========================
A deterministic relationship graph connecting users, hosts, services,
applications, networks, credentials, vulnerabilities, security boundaries
and access sessions.

Every node and edge carries an explicit state so that the graph never
presents an inferred path as a confirmed compromise:

* ``CONFIRMED`` – supported by validated evidence (e.g. a validated
  foothold or verified credential).
* ``POTENTIAL`` – supported by an unverified finding/hypothesis.
* ``INFERRED`` – derived from reachability/segmentation assumptions.
* ``UNKNOWN``  – no evidence either way.

The engine performs no actions; it only records and correlates what the
rest of Athena already established.
"""

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

# ============================================================================
# ENUMS
# ============================================================================


class PathState(Enum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class NodeType(Enum):
    USER = "user"
    HOST = "host"
    SERVICE = "service"
    APPLICATION = "application"
    NETWORK = "network"
    CREDENTIAL = "credential"
    VULNERABILITY = "vulnerability"
    SECURITY_BOUNDARY = "security_boundary"
    ACCESS_SESSION = "access_session"


class EdgeRelation(Enum):
    RUNS = "runs"
    AUTHENTICATES = "authenticates"
    CAN_REACH = "can_reach"
    EXPOSES = "exposes"
    TRUSTS = "trusts"
    DEPENDS_ON = "depends_on"
    HAS_ACCESS_TO = "has_access_to"
    VULNERABLE_TO = "vulnerable_to"
    LEADS_TO = "leads_to"


#: Only these relations may carry CONFIRMED from non-session evidence.
CONFIRMED_RELATIONS = frozenset({
    EdgeRelation.RUNS, EdgeRelation.AUTHENTICATES, EdgeRelation.EXPOSES,
    EdgeRelation.DEPENDS_ON, EdgeRelation.LEADS_TO,
})


@dataclass
class PathNode:
    type: NodeType
    label: str
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    state: PathState = PathState.UNKNOWN
    data: Dict[str, Any] = field(default_factory=dict)
    source: str = ""          # module / finding id that created this node

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "state": self.state.value,
            "data": dict(self.data),
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PathNode":
        return cls(
            id=data.get("id", str(uuid.uuid4())[:12]),
            type=NodeType(data.get("type", "host")),
            label=data.get("label", ""),
            state=PathState(data.get("state", "unknown")),
            data=dict(data.get("data", {})),
            source=data.get("source", ""),
        )


@dataclass
class PathEdge:
    source_id: str
    target_id: str
    relation: EdgeRelation
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    state: PathState = PathState.UNKNOWN
    data: Dict[str, Any] = field(default_factory=dict)
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source_id,
            "target": self.target_id,
            "relation": self.relation.value,
            "state": self.state.value,
            "data": dict(self.data),
            "source_module": self.source,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PathEdge":
        return cls(
            id=data.get("id", str(uuid.uuid4())[:12]),
            source_id=data.get("source", ""),
            target_id=data.get("target", ""),
            relation=EdgeRelation(data.get("relation", "leads_to")),
            state=PathState(data.get("state", "unknown")),
            data=dict(data.get("data", {})),
            source=data.get("source_module", ""),
        )


class AttackGraph:
    """Directed relationship graph with state-labeled nodes and edges."""

    def __init__(self, engagement_id: str = ""):
        self.engagement_id = engagement_id
        self.nodes: Dict[str, PathNode] = {}
        self.edges: List[PathEdge] = []

    # -- mutation -----------------------------------------------------------

    def add_node(self, node: PathNode) -> PathNode:
        """Upsert a node by id."""
        self.nodes[node.id] = node
        return node

    def get_node(self, node_id: str) -> Optional[PathNode]:
        return self.nodes.get(node_id)

    def add_edge(self, edge: PathEdge) -> bool:
        """Add an edge; both endpoints must exist (fail-closed)."""
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            return False
        self.edges.append(edge)
        return True

    def upsert_edge(self, source_id: str, target_id: str,
                    relation: EdgeRelation,
                    state: PathState = PathState.UNKNOWN,
                    data: Optional[Dict[str, Any]] = None,
                    source: str = "") -> Optional[PathEdge]:
        """Add an edge unless an equivalent one already exists."""
        for edge in self.edges:
            if (edge.source_id == source_id
                    and edge.target_id == target_id
                    and edge.relation == relation):
                return edge
        edge = PathEdge(source_id=source_id, target_id=target_id,
                        relation=relation, state=state,
                        data=data or {}, source=source)
        if not self.add_edge(edge):
            return None
        return edge

    # -- queries ------------------------------------------------------------

    def neighbors(self, node_id: str) -> List[PathNode]:
        targets = [e.target_id for e in self.edges if e.source_id == node_id]
        return [self.nodes[t] for t in targets if t in self.nodes]

    def find_paths(self, start_id: str, end_id: str,
                   max_depth: int = 10) -> List[List[PathNode]]:
        """BFS from ``start_id`` to ``end_id``; returns node sequences."""
        if start_id not in self.nodes or end_id not in self.nodes:
            return []
        paths: List[List[PathNode]] = []
        visited: set = set()

        def _walk(current: str, trail: List[str]):
            if len(trail) > max_depth:
                return
            if current == end_id:
                paths.append([self.nodes[n] for n in trail])
                return
            for nxt in [e.target_id for e in self.edges
                        if e.source_id == current and e.target_id not in visited]:
                visited.add(nxt)
                _walk(nxt, trail + [nxt])
                visited.discard(nxt)

        visited.add(start_id)
        _walk(start_id, [start_id])
        return paths

    def reachable(self, start_id: str) -> List[PathNode]:
        """All nodes reachable from ``start_id`` (BFS)."""
        seen: set = {start_id}
        queue = [start_id]
        while queue:
            cur = queue.pop(0)
            for nxt in [e.target_id for e in self.edges
                        if e.source_id == cur and e.target_id not in seen]:
                seen.add(nxt)
                queue.append(nxt)
        return [self.nodes[n] for n in seen if n in self.nodes and n != start_id]

    def confirmed_paths(self, start_id: str) -> List[PathNode]:
        """Reachable nodes connected exclusively by CONFIRMED edges."""
        seen: set = {start_id}
        queue = [start_id]
        while queue:
            cur = queue.pop(0)
            for edge in self.edges:
                if (edge.source_id == cur and edge.state == PathState.CONFIRMED
                        and edge.target_id not in seen):
                    seen.add(edge.target_id)
                    queue.append(edge.target_id)
        return [self.nodes[n] for n in seen if n in self.nodes and n != start_id]

    def impact_summary(self) -> Dict[str, Any]:
        """High-level impact view: per-node confirmed reachability."""
        summary: Dict[str, Any] = {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "confirmed": {"nodes": 0, "edges": 0},
            "potential": {"nodes": 0, "edges": 0},
            "inferred": {"nodes": 0, "edges": 0},
            "unknown": {"nodes": 0, "edges": 0},
            "access_sessions": [],
            "reachable_hosts": [],
        }
        for node in self.nodes.values():
            key = node.state.value
            if key in summary:
                summary[key]["nodes"] += 1
            if node.type == NodeType.ACCESS_SESSION:
                summary["access_sessions"].append(node.to_dict())
            if node.type == NodeType.HOST and node.state == PathState.CONFIRMED:
                summary["reachable_hosts"].append(node.to_dict())
        for edge in self.edges:
            key = edge.state.value
            if key in summary:
                summary[key]["edges"] += 1
        return summary

    # -- serialization ------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackGraph":
        graph = cls(engagement_id=data.get("engagement_id", ""))
        for node in data.get("nodes", []):
            graph.add_node(PathNode.from_dict(node))
        for edge in data.get("edges", []):
            graph.add_edge(PathEdge.from_dict(edge))
        return graph

    @classmethod
    def load(cls, path: str) -> "AttackGraph":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


# ============================================================================
# GRAPH FACTORY – materialize from findings + post-exploitation sessions
# ============================================================================


def build_graph(engagement_id: str, findings: List[Dict[str, Any]],
                sessions: Optional[List[Dict[str, Any]]] = None,
                networks: Optional[List[Dict[str, Any]]] = None) -> AttackGraph:
    """Deterministically materialize an attack graph from Athena records.

    ``findings``   – list of finding dicts (Finding.to_dict() or raw
                     scanner findings with type/severity/url).
    ``sessions``   – list of session dicts with ``id``, ``target``,
                     ``user``, ``system``, ``network``, ``state``.
    ``networks``   – optional pre-built network nodes.

    States: findings referencing ``confirmed`` findings become CONFIRMED;
    everything else starts as POTENTIAL or INFERRED.
    """
    graph = AttackGraph(engagement_id=engagement_id)

    # -- hosts / vulnerabilities from findings ------------------------------
    for finding in findings:
        affected = finding.get("affected_asset") or finding.get("url") or ""
        severity = normalize_impact(finding.get("severity", "info"))
        is_confirmed = finding.get("state") == "confirmed"

        host_id = _stable_id("host", affected)
        if affected:
            graph.add_node(PathNode(
                id=host_id, type=NodeType.HOST, label=affected,
                state=PathState.CONFIRMED if is_confirmed else PathState.POTENTIAL,
                source=finding.get("detection_module", ""),
            ))

        vuln_id = _stable_id("vuln", finding.get("title") or finding.get("type", ""))
        graph.add_node(PathNode(
            id=vuln_id, type=NodeType.VULNERABILITY,
            label=finding.get("title") or finding.get("type", "finding"),
            state=PathState.CONFIRMED if is_confirmed else PathState.POTENTIAL,
            data={"severity": severity,
                  "confidence": finding.get("confidence", 0.5)},
            source=finding.get("detection_module", ""),
        ))
        if affected:
            graph.upsert_edge(
                host_id, vuln_id, EdgeRelation.VULNERABLE_TO,
                state=PathState.CONFIRMED if is_confirmed else PathState.POTENTIAL,
                source="findings",
            )

    # -- session-derived nodes ----------------------------------------------
    for session in sessions or []:
        target = session.get("target", "")
        session_state = session.get("state", "dead")
        active = session_state == "active"

        session_id = _stable_id("session", session.get("id", target))
        host_id = _stable_id("host", target)
        user_id = _stable_id("user",
                             f"{session.get('user', {}).get('username', '')}@{target}")

        graph.add_node(PathNode(
            id=host_id, type=NodeType.HOST, label=target,
            state=PathState.CONFIRMED if active else PathState.POTENTIAL,
            source="session",
        ))
        graph.add_node(PathNode(
            id=session_id, type=NodeType.ACCESS_SESSION, label=session_id,
            state=PathState.CONFIRMED if active else PathState.POTENTIAL,
            data={"platform": session.get("platform", ""),
                  "shell": session.get("shell_type", "")},
            source="session",
        ))
        username = session.get("user", {}).get("username", "")
        if username:
            graph.add_node(PathNode(
                id=user_id, type=NodeType.USER, label=username,
                state=PathState.CONFIRMED if active else PathState.POTENTIAL,
                data={"is_root": session.get("user", {}).get("is_root", False)},
                source="session",
            ))
            graph.upsert_edge(
                session_id, user_id, EdgeRelation.AUTHENTICATES,
                state=PathState.CONFIRMED if active else PathState.POTENTIAL,
                source="session",
            )
        graph.upsert_edge(
            session_id, host_id, EdgeRelation.HAS_ACCESS_TO,
            state=PathState.CONFIRMED if active else PathState.POTENTIAL,
            source="session",
        )

    # -- networks -----------------------------------------------------------
    for network in networks or []:
        net_id = _stable_id("network", network.get("name", ""))
        graph.add_node(PathNode(
            id=net_id, type=NodeType.NETWORK, label=network.get("name", ""),
            state=PathState.INFERRED,
            data={"cidr": network.get("cidr", "")},
            source="network_context",
        ))
        for host in network.get("hosts", []):
            hid = _stable_id("host", host)
            if hid not in graph.nodes:
                graph.add_node(PathNode(
                    id=hid, type=NodeType.HOST, label=host,
                    state=PathState.INFERRED, source="network_context",
                ))
            graph.upsert_edge(
                net_id, hid, EdgeRelation.CAN_REACH,
                state=PathState.INFERRED, source="network_context",
            )

    return graph


def _stable_id(prefix: str, value: str) -> str:
    import hashlib
    digest = hashlib.sha256((value or "?").encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def normalize_impact(severity: str) -> int:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return rank.get((severity or "info").strip().lower(), 0)