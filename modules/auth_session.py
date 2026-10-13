"""Authenticated sessions for the scan pipeline (Prompt B - Coverage).

Unauthenticated scans only see the public surface.  When the operator
supplies credentials, this module performs ONE form login, verifies the
session (logged-in markers present, password field gone - the same proof
standard as the bruteforce session re-check), and returns an
:class:`AuthContext` carrying cookies + headers.  Pipeline modules seed
their own ``aiohttp`` sessions from it, so every later stage (headless
crawl, vuln scan, exploitation) transparently reuses the login.

Security model (fail closed, secret-safe):

* The password lives only in the login call arguments - it is never stored
  on the context, never logged, and never checkpointed.
* :meth:`AuthContext.summary` (the only checkpoint-safe form) carries the
  login URL, verification method and cookie *names* - never values.
* No credential brute-forcing here: exactly one login attempt.  Spraying
  stays in ``modules/bruteforce.py`` behind its own gates.
* Any failure (network, unexpected form, dead host) returns an
  unauthenticated context - login never raises and never kills a scan.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("athena.auth")

#: Markers that indicate a page is rendered for a logged-in user.
LOGGED_IN_MARKERS = (
    "logout", "log out", "sign out", "dashboard", "my account",
    "welcome back", "authenticated",
)

#: Substrings that identify username fields (mirrors bruteforce naming).
USER_FIELD_HINTS = ("user", "email", "login", "username", "account")

#: Substrings that identify password fields.
PASS_FIELD_HINTS = ("pass", "pwd", "password")


@dataclass
class AuthContext:
    """Proven login session shared across pipeline stages."""

    login_url: str = ""
    username: str = ""
    authenticated: bool = False
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookie_url: str = ""
    verified_by: str = ""
    detail: str = ""

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return ("AuthContext(login_url=%r, username=%r, authenticated=%r)" %
                (self.login_url, self.username, self.authenticated))

    def seed_session(self, session: Any, url: str = "") -> int:
        """Copy cookies (and only cookies) into an ``aiohttp`` session jar.

        Returns the number of cookies actually stored (verified by
        re-reading the jar - a safe-mode jar on an IP target stores
        nothing, and the caller deserves ``0`` instead of a lie).
        Header auth (e.g. Bearer tokens) is applied separately: modules
        merge :attr:`headers` into their session defaults at creation.
        """
        if not self.authenticated or not self.cookies:
            return 0
        jar = getattr(session, "cookie_jar", None)
        if jar is None:
            return 0
        scope = url or self.cookie_url or self.login_url
        if not scope:
            return 0
        try:
            from yarl import URL
            scope_url = URL(str(scope))
            jar.update_cookies(dict(self.cookies), scope_url)
            try:
                stored = jar.filter_cookies(scope_url)
                return sum(1 for k in self.cookies if k in stored)
            except Exception:
                return len(self.cookies)
        except Exception as exc:  # pragma: no cover - never break a scan
            logger.debug("auth cookie seeding failed: %s", exc)
            return 0

    def summary(self) -> Dict[str, Any]:
        """Checkpoint/report-safe form.  No secrets: names only, no values."""
        return {
            "login_url": self.login_url,
            "username": self.username,
            "authenticated": bool(self.authenticated),
            "verified_by": self.verified_by,
            "cookie_names": sorted(self.cookies),
            "detail": self.detail,
        }


def _field_name(attrs: Dict[str, str], hints) -> Optional[str]:
    blob = " ".join(str(attrs.get(k, "")) for k in ("name", "id", "type",
                                                    "placeholder",
                                                    "aria-label")).lower()
    if any(h in blob for h in hints):
        return attrs.get("name") or None
    return None


def pick_login_fields(html: str) -> Optional[Dict[str, str]]:
    """Find the login form's field names: ``{'user': ..., 'pass': ...}``.

    Parses the first ``<form>`` containing a password input.  Returns None
    when no usable login form exists.  Pure function - unit-testable.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:  # pragma: no cover - bs4 is a hard dep
        return None
    try:
        soup = BeautifulSoup(html or "", "html.parser")
    except Exception:
        return None
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        pass_name = None
        user_name = None
        for tag in inputs:
            attrs = {k: str(v) for k, v in tag.attrs.items()
                     if isinstance(v, str)}
            kind = attrs.get("type", "text").lower()
            if kind == "password" and attrs.get("name"):
                pass_name = attrs["name"]
            elif kind in ("text", "email", "") and not user_name:
                candidate = _field_name(attrs, USER_FIELD_HINTS)
                if candidate:
                    user_name = candidate
        if pass_name:
            if not user_name:
                # Fall back to the first text-like input with a name.
                for tag in inputs:
                    name = tag.attrs.get("name")
                    if name and tag.attrs.get("type", "text").lower() in (
                            "text", "email", ""):
                        user_name = str(name)
                        break
            if user_name:
                action = form.attrs.get("action") or ""
                method = str(form.attrs.get("method", "post")).lower()
                return {"user": user_name, "pass": pass_name,
                        "action": str(action), "method": method or "post"}
    return None


def looks_logged_in(html: str, extra_markers=()) -> bool:
    """True when the page shows a logged-in state (no password field)."""
    body = (html or "").lower()
    if 'type="password"' in body or "type='password'" in body:
        return False
    markers = list(LOGGED_IN_MARKERS) + [str(m).lower() for m in
                                         (extra_markers or ())]
    return any(m in body for m in markers)


# Transport: swapping this keeps every test offline.  The default uses
# short-timeout aiohttp sessions.  ``fetch`` takes optional cookies so the
# verify pass replays the POST-login jar (a throwaway session would look
# logged out even after a good login).
FetchPage = Callable[..., Awaitable[Any]]  # (url, cookies?) -> (status, html, jar)
PostForm = Callable[[str, Dict[str, str]], Awaitable[Any]]


async def _default_fetch(url: str, cookies: Optional[Dict[str, str]] = None):
    import aiohttp
    timeout = aiohttp.ClientTimeout(total=15)
    # unsafe jar: targets are routinely bare IPs and aiohttp's default
    # jar silently drops all cookies set by IP hosts.
    jar = aiohttp.CookieJar(unsafe=True)
    async with aiohttp.ClientSession(timeout=timeout,
                                     cookie_jar=jar) as sess:
        if cookies:
            try:
                sess.cookie_jar.update_cookies(dict(cookies), url)
            except Exception:
                pass
        async with sess.get(url, ssl=False,
                            allow_redirects=True) as resp:
            body = await resp.text(errors="replace")
            jar = {c.key: c.value for c in sess.cookie_jar}
            return resp.status, body, jar


async def _default_post(url: str, data: Dict[str, str]):
    import aiohttp
    timeout = aiohttp.ClientTimeout(total=15)
    # unsafe jar: see _default_fetch (IP targets).
    jar = aiohttp.CookieJar(unsafe=True)
    async with aiohttp.ClientSession(timeout=timeout,
                                     cookie_jar=jar) as sess:
        async with sess.post(url, data=data, ssl=False,
                             allow_redirects=True) as resp:
            body = await resp.text(errors="replace")
            jar = {c.key: c.value for c in sess.cookie_jar}
            return resp.status, body, jar


async def login_with_credentials(
    login_url: str,
    username: str,
    password: str,
    verify_markers=(),
    verify_url: str = "",
    fetch: FetchPage = None,
    post: PostForm = None,
) -> AuthContext:
    """Perform ONE login and return the session context.  Never raises.

    ``password`` is used for the single POST only - it is never stored,
    logged, or returned.  ``fetch``/``post`` are injectable so tests stay
    offline (fakes should accept ``(url, cookies=None)``); the defaults
    use short-timeout aiohttp sessions.

    Proof order: the POST response body first (many apps render the
    landing page directly), then a cookie-replaying GET of the login
    page, then ``verify_url`` (e.g. the site homepage) when given.
    """
    ctx = AuthContext(login_url=login_url or "", username=username or "")
    if not login_url or not username or not password:
        ctx.detail = "auth skipped: login URL, username and password required"
        return ctx
    do_fetch = fetch or _default_fetch
    do_post = post or _default_post
    try:
        status, page, _ = await do_fetch(login_url)
        if status is None and page is None:
            ctx.detail = "auth failed: login page unreachable"
            return ctx
        fields = pick_login_fields(page or "")
        if not fields:
            ctx.detail = "auth failed: no password form on login page"
            logger.info("auth: no login form at %s", login_url)
            return ctx
        action = fields["action"] or login_url
        target = action if bool(urlparse(action).netloc) else urljoin(
            login_url, action)
        data = {fields["user"]: username, fields["pass"]: password}
        # Preserve common hidden fields (CSRF tokens) from the login form.
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(page or "", "html.parser")
            for tag in soup.find_all("input", {"type": "hidden"}):
                name = tag.attrs.get("name")
                if name and name not in data:
                    data[str(name)] = str(tag.attrs.get("value", ""))
        except Exception:
            pass
        if fields["method"] == "get":
            ctx.detail = "auth failed: login form uses GET (refusing to send credentials in URL)"
            logger.info("auth: refusing GET-form login at %s", login_url)
            return ctx
        _, post_body, jar = await do_post(target, data)
        ctx.cookies = {str(k): str(v) for k, v in (jar or {}).items()}
        ctx.cookie_url = login_url
        # Proof 1: the POST response itself (apps often render the
        # landing page directly instead of redirecting).
        if looks_logged_in(post_body or "", verify_markers):
            ctx.authenticated = True
            ctx.verified_by = "post_response"
            ctx.detail = ("authenticated as %s (session verified: POST "
                          "response shows logged-in state)" % username)
            logger.info("auth: session verified for %s at %s",
                        username, login_url)
            return ctx
        # Proof 2: cookie-replaying GETs - login page, then the verify
        # URL (usually the site homepage).  A cookieless re-fetch would
        # look logged out even after a good login.
        candidates = [u for u in (login_url, verify_url or "") if u]
        seen_pages = []
        for candidate in dict.fromkeys(candidates):
            try:
                _, page, extra_jar = await do_fetch(candidate,
                                                    dict(ctx.cookies))
            except Exception:
                continue
            if isinstance(extra_jar, dict) and extra_jar:
                for k, v in extra_jar.items():
                    ctx.cookies.setdefault(str(k), str(v))
            seen_pages.append(candidate)
            if looks_logged_in(page or "", verify_markers):
                ctx.authenticated = True
                ctx.verified_by = "markers:%s" % candidate
                ctx.detail = ("authenticated as %s (session verified: login "
                              "markers present, password field gone)" % username)
                logger.info("auth: session verified for %s at %s",
                            username, login_url)
                return ctx
        if not seen_pages:
            ctx.detail = "auth failed: verify pages unreachable"
            ctx.cookies = {}
            return ctx
        ctx.detail = ("login posted but session NOT verified "
                      "(still looks logged out)")
        logger.info("auth: unverified login for %s at %s",
                    username, login_url)
        ctx.cookies = {}
        return ctx
    except Exception as exc:
        logger.debug("auth login failed for %s: %s", login_url, exc)
        ctx.authenticated = False
        ctx.cookies = {}
        ctx.detail = "auth failed: %s" % (exc,)
        return ctx


def resolve_auth_args(args: Any) -> Dict[str, str]:
    """Read auth settings from CLI args with ``ATHENA_AUTH_*`` fallback."""
    import os

    def _get(name: str, env: str) -> str:
        try:
            value = getattr(args, name, "") if args is not None else ""
        except Exception:
            value = ""
        return str(value or os.getenv(env, "") or "")

    return {
        "login_url": _get("auth_login_url", "ATHENA_AUTH_LOGIN_URL"),
        "username": _get("auth_user", "ATHENA_AUTH_USER"),
        "password": _get("auth_pass", "ATHENA_AUTH_PASS"),
        "verify": _get("auth_verify", "ATHENA_AUTH_VERIFY"),
    }
