"""Prompt B: headless-crawl + coverage-stage units.

The browser is always injected (fake page source) or absent (missing
Playwright simulated) - no real Chromium, no network.
"""

import argparse
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import modules.headless_crawl  # noqa: F401  (module import surface)
from modules.auth_session import AuthContext
from modules.headless_crawl import (
    HeadlessConfig,
    _clean_url,
    _in_scope,
    _scope_roots,
    headless_crawl,
)

SITE = {
    "http://target.test/": (
        ["/about", "/app", "http://external.test/x"],
        [{"action": "/login", "method": "post",
          "inputs": [{"name": "user", "type": "text"},
                     {"name": "pw", "type": "password"}]}],
    ),
    "http://target.test/about": (["/", "/team"], []),
    "http://target.test/app": (["/app/settings"], []),
    "http://target.test/app/settings": ([], []),
    "http://target.test/team": ([], []),
}


def _site_source(site):
    async def source(url):
        if url not in site:
            raise ConnectionError("not in fake site: %s" % url)
        return site[url]
    return source


class TestScopeHelpers:
    def test_scope_roots(self):
        assert _scope_roots(["http://target.test/a",
                             "https://sub.target.test/b"]) == {
            "target.test", "sub.target.test"}

    def test_subdomains_are_in_scope(self):
        roots = {"target.test"}
        assert _in_scope("http://sub.target.test/x", roots) is True
        assert _in_scope("http://target.test.evil.test/x", roots) is False
        assert _in_scope("http://external.test/x", roots) is False

    def test_clean_url_drops_fragments_and_non_http(self):
        assert _clean_url("http://target.test/a#frag") == \
            "http://target.test/a"
        assert _clean_url("javascript:void(0)") is None
        assert _clean_url("mailto:a@b.test") is None
        assert _clean_url("not a url") is None


class TestHeadlessCrawl:
    pytestmark = pytest.mark.asyncio

    async def test_injected_crawl_collects_urls_and_forms(self):
        result = await headless_crawl(
            ["http://target.test/"], HeadlessConfig(max_pages=10),
            page_source=_site_source(SITE))

        assert result.status == "completed"
        assert result.pages_visited == 5
        for expected in ("http://target.test/about",
                         "http://target.test/app",
                         "http://target.test/app/settings",
                         "http://target.test/team"):
            assert expected in result.urls
        assert "http://external.test/x" not in result.urls
        assert result.external_seen == 1
        assert len(result.forms) == 1
        form = result.forms[0]
        assert form["action"] == "http://target.test/login"
        assert form["method"] == "post"
        assert {i["name"] for i in form["inputs"]} == {"user", "pw"}

    async def test_max_pages_bounds_visits(self):
        result = await headless_crawl(
            ["http://target.test/"], HeadlessConfig(max_pages=2),
            page_source=_site_source(SITE))

        assert result.status == "completed"
        assert result.pages_visited == 2

    async def test_no_seeds_skips(self):
        result = await headless_crawl([], page_source=_site_source(SITE))
        assert result.status == "skipped"

    async def test_page_errors_do_not_abort(self):
        async def flaky(url):
            if url.endswith("/app"):
                raise RuntimeError("renderer hiccup")
            return await _site_source(SITE)(url)

        result = await headless_crawl(
            ["http://target.test/"], HeadlessConfig(max_pages=10),
            page_source=flaky)

        assert result.status == "completed"
        # The failed /app page is skipped (not counted); its child
        # /app/settings is therefore never reached - the crawl still
        # completes with everything else.
        assert result.pages_visited == 3
        assert "http://target.test/app/settings" not in result.urls
        assert "http://target.test/team" in result.urls

    async def test_missing_playwright_skips_cleanly(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "playwright", None)
        monkeypatch.setitem(sys.modules, "playwright.async_api", None)
        result = await headless_crawl(["http://target.test/"])
        assert result.status == "skipped"
        assert "not installed" in result.detail

    async def test_summary_shape(self):
        result = await headless_crawl(
            ["http://target.test/"], HeadlessConfig(max_pages=2),
            page_source=_site_source(SITE))
        summary = result.summary()
        assert summary["status"] == "completed"
        assert summary["pages_visited"] == 2
        assert summary["urls_found"] == len(result.urls)
        assert summary["forms_found"] == len(result.forms)


class TestCoverageStage:
    pytestmark = pytest.mark.asyncio

    @staticmethod
    def _args(**over):
        base = {"no_headless": True, "crawl_max_pages": 30,
                "auth_login_url": "", "auth_user": "", "auth_pass": "",
                "auth_verify": ""}
        base.update(over)
        return argparse.Namespace(**base)

    async def test_anonymous_skip_paths_store_summaries(self):
        import athena
        discovery = {"urls": ["http://target.test/"], "login_forms": []}
        ctx, headless = await athena.run_coverage_stage(
            "http://target.test", self._args(), discovery, ckpt=None)

        assert ctx is None
        assert headless["status"] == "skipped"
        assert discovery["auth"] is None
        assert discovery["headless"]["status"] == "skipped"

    async def test_form_derived_login_and_merge(self, monkeypatch):
        import athena
        from modules.headless_crawl import HeadlessResult

        authed = AuthContext(login_url="http://target.test/login",
                             username="op", authenticated=True,
                             cookies={"sid": "v"}, verified_by="markers")

        async def fake_login(url, user, pw, verify_markers=(), verify_url=""):
            assert pw == "s3cret"
            return authed

        crawled = HeadlessResult(
            status="completed", pages_visited=2,
            urls=["http://target.test/", "http://target.test/hidden"],
            forms=[])

        async def _done(value):
            return value

        monkeypatch.setattr(athena, "login_with_credentials", fake_login)
        monkeypatch.setattr(
            athena, "headless_crawl",
            lambda seeds, config=None, auth=None: _done(crawled))

        discovery = {"urls": ["http://target.test/"],
                     "login_forms": [{"url": "http://target.test/login"}]}
        args = self._args(no_headless=False, auth_user="op",
                          auth_pass="s3cret")
        ctx, headless = await athena.run_coverage_stage(
            "http://target.test", args, discovery, ckpt=None)

        assert ctx is authed
        assert headless["status"] == "completed"
        assert headless["urls_added"] == 1
        assert "http://target.test/hidden" in discovery["urls"]
        assert discovery["auth"]["authenticated"] is True
        # Secret-free checkpoint payload: no password, no cookie values.
        import json
        blob = json.dumps(discovery)
        assert "s3cret" not in blob
        assert '"sid": "v"' not in blob

    async def test_resume_keeps_checkpointed_crawl(self, monkeypatch):
        import athena
        calls = {"crawl": 0}

        async def fake_crawl(seeds, config=None, auth=None):
            calls["crawl"] += 1
            raise AssertionError("must not re-crawl on resume")

        monkeypatch.setattr(athena, "headless_crawl", fake_crawl)
        discovery = {"urls": ["http://target.test/",
                              "http://target.test/hidden"],
                     "headless": {"status": "completed", "pages_visited": 2,
                                  "urls_found": 2, "urls_added": 1,
                                  "forms_found": 0, "external_seen": 0,
                                  "detail": "earlier run"}}
        ctx, headless = await athena.run_coverage_stage(
            "http://target.test", self._args(no_headless=False),
            discovery, ckpt=None)

        assert ctx is None
        assert calls["crawl"] == 0
        assert headless["urls_added"] == 1
        assert discovery["urls"].count("http://target.test/hidden") == 1
