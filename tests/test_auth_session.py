"""Prompt B: authenticated-session units.  No network, no browser."""

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.auth_session import (
    AuthContext,
    login_with_credentials,
    looks_logged_in,
    pick_login_fields,
    resolve_auth_args,
)

LOGIN_PAGE = """<html><body>
<form action="/login" method="post">
<input type="text" name="username" placeholder="Username"/>
<input type="password" name="password"/>
<input type="hidden" name="csrf" value="tok123"/>
<button type="submit">Sign in</button>
</form></body></html>"""

DASHBOARD_PAGE = """<html><body>
<h1>Welcome back, operator</h1>
<a href="/logout">Log out</a>
</body></html>"""


def _transports(verify_page, posted=None):
    async def fetch(url, cookies=None):
        if cookies:
            return 200, verify_page, dict(cookies)
        return 200, LOGIN_PAGE, {}

    async def post(url, data):
        (posted if posted is not None else {}).update(data)
        return 200, "ok", {"sessionid": "abc123"}

    return fetch, post


class TestPickLoginFields:
    def test_standard_form_fields_found(self):
        fields = pick_login_fields(LOGIN_PAGE)
        assert fields is not None
        assert fields["user"] == "username"
        assert fields["pass"] == "password"

    def test_no_form_returns_none(self):
        assert pick_login_fields("<html><body>hello</body></html>") is None

    def test_form_without_password_returns_none(self):
        html = ('<html><body><form action="/s"><input type="text" name="q"/>'
                "</form></body></html>")
        assert pick_login_fields(html) is None


class TestLooksLoggedIn:
    def test_dashboard_counts(self):
        assert looks_logged_in(DASHBOARD_PAGE) is True

    def test_password_field_vetoes_markers(self):
        html = DASHBOARD_PAGE + '<input type="password" name="pw"/>'
        assert looks_logged_in(html) is False

    def test_custom_markers(self):
        assert looks_logged_in("<html>member area</html>",
                               extra_markers=["member area"]) is True
        assert looks_logged_in("<html>member area</html>") is False


class TestLoginFlow:
    pytestmark = pytest.mark.asyncio

    async def test_successful_login_verifies_session(self):
        posted = {}
        fetch, post = _transports(DASHBOARD_PAGE, posted)
        ctx = await login_with_credentials(
            "http://target.test/login", "op", "s3cret",
            fetch=fetch, post=post)

        assert ctx.authenticated is True
        assert str(ctx.verified_by).startswith("markers")
        assert ctx.cookies.get("sessionid") == "abc123"
        # Hidden CSRF field preserved, credentials posted exactly once.
        assert posted == {"username": "op", "password": "s3cret",
                          "csrf": "tok123"}

    async def test_post_response_logged_in_verifies_immediately(self):
        fetches = []

        async def fetch(url, cookies=None):
            fetches.append((url, dict(cookies or {})))
            return 200, LOGIN_PAGE, {}

        async def post(url, data):
            return 200, DASHBOARD_PAGE, {"sessionid": "direct"}

        ctx = await login_with_credentials(
            "http://target.test/login", "op", "s3cret",
            fetch=fetch, post=post)

        assert ctx.authenticated is True
        assert ctx.verified_by == "post_response"
        # Only the initial form load fetched; no verify round-trip needed.
        assert len(fetches) == 1

    async def test_unverified_login_keeps_no_cookies(self):
        fetch, post = _transports(LOGIN_PAGE)
        ctx = await login_with_credentials(
            "http://target.test/login", "op", "wrong", fetch=fetch, post=post)

        assert ctx.authenticated is False
        assert ctx.cookies == {}
        assert "NOT verified" in ctx.detail

    async def test_missing_fields_never_posts(self):
        called = {}

        async def fetch(url, cookies=None):
            called["fetch"] = True
            return 200, "<html><body>no form here</body></html>", {}

        async def post(url, data):
            called["post"] = True
            return 200, "", {}

        ctx = await login_with_credentials(
            "http://target.test/login", "op", "s3cret",
            fetch=fetch, post=post)

        assert ctx.authenticated is False
        assert "no password form" in ctx.detail
        assert "post" not in called

    async def test_blank_credentials_skip(self):
        ctx = await login_with_credentials("", "", "")
        assert ctx.authenticated is False
        assert "required" in ctx.detail

    async def test_transport_error_never_raises(self):
        async def fetch(url, cookies=None):
            raise ConnectionError("dead host")

        async def post(url, data):
            raise AssertionError("must not post when fetch fails")

        ctx = await login_with_credentials(
            "http://target.test/login", "op", "s3cret",
            fetch=fetch, post=post)

        assert ctx.authenticated is False

    async def test_get_forms_refuse_to_send_credentials(self):
        html = LOGIN_PAGE.replace('method="post"', 'method="get"')

        async def fetch(url, cookies=None):
            return 200, html, {}

        seen = {}

        async def post(url, data):
            seen["sent"] = True
            return 200, "", {}

        ctx = await login_with_credentials(
            "http://target.test/login", "op", "s3cret",
            fetch=fetch, post=post)

        assert ctx.authenticated is False
        assert "sent" not in seen
        assert "GET" in ctx.detail


class TestSecretSafety:
    def test_password_nowhere_on_context(self):
        ctx = AuthContext(login_url="http://t/login", username="op",
                          authenticated=True,
                          cookies={"sessionid": "abc123"},
                          detail="x")
        blob = "%r %s" % (ctx, ctx.summary())
        assert "s3cret" not in blob
        assert "abc123" not in blob  # values excluded, names only
        assert "sessionid" in str(ctx.summary())

    def test_seed_session_installs_cookies(self):
        import asyncio

        async def go():
            import aiohttp
            ctx = AuthContext(login_url="http://target.test/login",
                              username="op", authenticated=True,
                              cookies={"sessionid": "abc123"},
                              cookie_url="http://target.test/login")
            async with aiohttp.ClientSession() as sess:
                assert ctx.seed_session(sess) == 1
                from yarl import URL
                jar = sess.cookie_jar.filter_cookies(
                    URL("http://target.test/dashboard"))
                assert jar.get("sessionid") is not None

        asyncio.run(go())

    def test_unauthenticated_seeds_nothing(self):
        import asyncio

        async def go():
            import aiohttp
            ctx = AuthContext()
            async with aiohttp.ClientSession() as sess:
                assert ctx.seed_session(sess) == 0

        asyncio.run(go())


class TestResolveAuthArgs:
    def test_flags_win_over_env(self, monkeypatch):
        import argparse
        monkeypatch.setenv("ATHENA_AUTH_USER", "envuser")
        args = argparse.Namespace(auth_login_url="http://t/login",
                                  auth_user="flaguser", auth_pass="",
                                  auth_verify="")
        assert resolve_auth_args(args)["username"] == "flaguser"

    def test_env_fallback(self, monkeypatch):
        import argparse
        monkeypatch.setenv("ATHENA_AUTH_LOGIN_URL", "http://t/login")
        monkeypatch.setenv("ATHENA_AUTH_USER", "envuser")
        monkeypatch.setenv("ATHENA_AUTH_PASS", "envpass")
        args = argparse.Namespace()
        out = resolve_auth_args(args)
        assert out == {"login_url": "http://t/login", "username": "envuser",
                       "password": "envpass", "verify": ""}
