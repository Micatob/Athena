"""
Athena Omega - Lightweight Attack Graph (RedAmon port, no Neo4j)
===============================================================
SQLite-backed MERGE graph: duplicate writes update, never duplicate.
Tenant key = engagement_id. Single source of truth for recon findings.

Why SQLite, not Neo4j: Athena must stay `pip install` with zero Docker.
API mirrors the subset the agent/recon actually need: add_node/add_edge/
query/stats/to_json.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
  engagement_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  data TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (engagement_id, kind, key)
);
CREATE TABLE IF NOT EXISTS edges (
  engagement_id TEXT NOT NULL,
  src_kind TEXT NOT NULL,
  src_key TEXT NOT NULL,
  rel TEXT NOT NULL,
  dst_kind TEXT NOT NULL,
  dst_key TEXT NOT NULL,
  data TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (engagement_id, src_kind, src_key, rel, dst_kind, dst_key)
);
CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(engagement_id, kind);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(engagement_id, src_kind, src_key);
"""


def _default_path() -> str:
    base = os.getenv("ATHENA_GRAPH_PATH") or os.path.join(
        os.path.expanduser("~"), ".athena", "graph.db"
    )
    try:
        os.makedirs(os.path.dirname(base), exist_ok=True)
    except Exception:
        pass
    return base


class GraphLite:
    """Thread-safe SQLite MERGE graph."""

    def __init__(self, engagement_id: str = "default", path: str = ""):
        self.engagement_id = engagement_id or "default"
        self.path = path or _default_path()
        # :memory: must share one connection; file DB can use check_same_thread=False + lock
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def add_node(self, kind: str, key: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        kind = (kind or "Unknown").strip() or "Unknown"
        key = (key or "").strip()
        if not key:
            return {"merged": False, "reason": "empty key"}
        payload = json.dumps(data or {}, default=str)
        with self._lock:
            self._conn.execute(
                """INSERT INTO nodes (engagement_id, kind, key, data, updated_at)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(engagement_id, kind, key)
                   DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at""",
                (self.engagement_id, kind, key, payload, self._now()),
            )
            self._conn.commit()
        return {"merged": True, "kind": kind, "key": key}

    def add_edge(
        self,
        src_kind: str,
        src_key: str,
        rel: str,
        dst_kind: str,
        dst_key: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        for v in (src_key, dst_key, rel):
            if not (v or "").strip():
                return {"merged": False, "reason": "empty edge endpoint"}
        payload = json.dumps(data or {}, default=str)
        with self._lock:
            # ensure endpoints exist (MERGE semantics)
            for k, kk in ((src_kind, src_key), (dst_kind, dst_key)):
                self._conn.execute(
                    """INSERT INTO nodes (engagement_id, kind, key, data, updated_at)
                       VALUES (?,?,?,?,?)
                       ON CONFLICT(engagement_id, kind, key) DO NOTHING""",
                    (self.engagement_id, k, kk, "{}", self._now()),
                )
            self._conn.execute(
                """INSERT INTO edges (engagement_id, src_kind, src_key, rel, dst_kind, dst_key, data, updated_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(engagement_id, src_kind, src_key, rel, dst_kind, dst_key)
                   DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at""",
                (self.engagement_id, src_kind, src_key, rel, dst_kind, dst_key, payload, self._now()),
            )
            self._conn.commit()
        return {"merged": True}

    def query(self, kind: str = "", limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            if kind:
                cur.execute(
                    "SELECT kind, key, data FROM nodes WHERE engagement_id=? AND kind=? LIMIT ?",
                    (self.engagement_id, kind, limit),
                )
            else:
                cur.execute(
                    "SELECT kind, key, data FROM nodes WHERE engagement_id=? LIMIT ?",
                    (self.engagement_id, limit),
                )
            rows = cur.fetchall()
        out = []
        for k, kk, data in rows:
            try:
                d = json.loads(data or "{}")
            except Exception:
                d = {}
            out.append({"kind": k, "key": kk, "data": d})
        return out

    def neighbors(self, kind: str, key: str, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """SELECT src_kind, src_key, rel, dst_kind, dst_key, data FROM edges
                   WHERE engagement_id=? AND ((src_kind=? AND src_key=?) OR (dst_kind=? AND dst_key=?))
                   LIMIT ?""",
                (self.engagement_id, kind, key, kind, key, limit),
            )
            rows = cur.fetchall()
        out = []
        for sk, skey, rel, dk, dkey, data in rows:
            try:
                d = json.loads(data or "{}")
            except Exception:
                d = {}
            out.append({"src": f"{sk}:{skey}", "rel": rel, "dst": f"{dk}:{dkey}", "data": d})
        return out

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT kind, COUNT(*) FROM nodes WHERE engagement_id=? GROUP BY kind", (self.engagement_id,))
            nodes = dict(cur.fetchall())
            cur.execute("SELECT COUNT(*) FROM edges WHERE engagement_id=?", (self.engagement_id,))
            edge_count = cur.fetchone()[0]
        return {"engagement_id": self.engagement_id, "nodes": nodes, "node_total": sum(nodes.values()), "edge_total": edge_count}

    def to_json(self) -> Dict[str, Any]:
        return {"engagement_id": self.engagement_id, "stats": self.stats(), "nodes": self.query(limit=2000)}

    def ingest_discovery(self, discovery: Dict[str, Any], target: str = "") -> Dict[str, Any]:
        """Fold a discovery.py result dict into the graph. Never raises."""
        try:
            target = target or str((discovery or {}).get("target", "target"))
            self.add_node("Target", target, {"target": target})
            for url in (discovery or {}).get("urls", []) or []:
                u = url if isinstance(url, str) else str(url.get("url", ""))
                if u:
                    self.add_node("URL", u, {"url": u})
                    self.add_edge("Target", target, "HOSTS", "URL", u)
            for sub in (discovery or {}).get("subdomains", []) or []:
                s = sub if isinstance(sub, str) else str(sub.get("subdomain", sub))
                if s:
                    self.add_node("Domain", s, {})
                    self.add_edge("Target", target, "CONTAINS", "Domain", s)
            for p in (discovery or {}).get("ports", []) or []:
                try:
                    port = str(p.get("port", p) if isinstance(p, dict) else p)
                    self.add_node("Port", f"{target}:{port}", {"port": port})
                    self.add_edge("Target", target, "HAS_PORT", "Port", f"{target}:{port}")
                except Exception:
                    continue
            for t in (discovery or {}).get("technologies", []) or []:
                name = str(t)
                self.add_node("Technology", name, {})
                self.add_edge("Target", target, "USES_TECH", "Technology", name)
            return self.stats()
        except Exception:
            return self.stats()

    def close(self) -> None:
        try:
            with self._lock:
                self._conn.close()
        except Exception:
            pass
