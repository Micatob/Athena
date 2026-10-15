"""
Athena Omega - TLS scan (RedAmon tlsx concept, pure Python)
Captures issuer/SAN/validity without extra deps. Never raises.
"""
import socket
import ssl
from typing import Any, Dict, List
from urllib.parse import urlparse


def _host_port(target: str) -> tuple:
    t = (target or "").strip()
    if "://" in t:
        try:
            u = urlparse(t)
            return (u.hostname or t, u.port or 443)
        except Exception:
            pass
    if ":" in t and t.count(":") == 1:
        h, _, p = t.partition(":")
        try:
            return (h, int(p))
        except Exception:
            return (h, 443)
    return (t, 443)


def tls_grab(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    host, port = _host_port(target)
    out: Dict[str, Any] = {"host": host, "port": port, "tls": False}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
                out["tls"] = True
                out["version"] = getattr(ssock, "version", lambda: "?")()
                out["cipher"] = str((ssock.cipher() or ("?",))[0])
                sans: List[str] = []
                for typ, val in cert.get("subjectAltName", []) or []:
                    if typ == "DNS":
                        sans.append(val)
                out["sans"] = sans[:50]
                out["issuer"] = str(cert.get("issuer", ""))
                out["subject"] = str(cert.get("subject", ""))
                out["notAfter"] = str(cert.get("notAfter", ""))
                # in-scope SAN feedback (apex-scoped by caller)
                out["san_targets"] = [s for s in sans if s and "*" not in s][:20]
    except Exception as exc:
        out["error"] = str(exc)[:200]
    return out
