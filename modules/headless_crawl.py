"""Headless-browser coverage crawl (Prompt B - Coverage).

Static HTTP crawling misses everything rendered by JavaScript: SPA routes,
lazy-loaded links, forms mounted at runtime.  This module drives a real
Chromium via Playwright (headless), visits seed URLs, and returns the
same-scope links + forms the static crawler never sees.  Results merge
into discovery output, so vuln scanning and nuclei automatically cover
the extra surface.

Boundaries (safe by construction):

* Same-scope only: a page is visited only when its hostname equals the
  seed host or is a subdomain of it.  External links are recorded as
  seen but never visited.
* Bounded: ``max_pages`` cap (default 30), per-page timeout, one browser
  for the whole run, always closed (``finally``).
* Optional dependency: Playwright is imported lazily.  Missing package
  OR missing browser binaries (``playwright install chromium`` not run)
  returns ``status: skipped`` - never raises, never kills a scan.
* Authenticated crawl: when an :class:`AuthContext` is supplied, its
  cookies are added to the browser context before visiting.
* No crawling outside the engagement scope: callers pass seeds already
  gated by ``run_scan_session``; seeds with other hosts are dropped.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("athena.headless")


@dataclass
class HeadlessConfig:
    max_pages: int = 30
    page_timeout_ms: int = 20000
    wait_until: str = "domcontentloaded"
    same_scope_only: bool = True


@dataclass
class HeadlessResult:
    status: str = "skipped"  # completed | skipped | unavailable
    pages_visited: int = 0
    urls: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    external_seen: int = 0
    detail: str = ""

    def summary(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "pages_visited": self.pages_visited,
            "urls_found": len(self.urls),
            "forms_found": len(self.forms),
            "external_seen": self.external_seen,
            "detail": self.detail,
        }


def _scope_roots(seeds: List[str]) -> Set[str]:
    roots = set()
    for seed in seeds or []:
        try:
            host = (urlparse(str(seed)).hostname or "").lower()
        except Exception:
            continue
        if host:
            roots.add(host)
    return roots


def _in_scope(url: str, roots: Set[str]) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host or not roots:
        return False
    return any(host == r or host.endswith("." + r) for r in roots)


def _clean_url(url: str) -> Optional[str]:
    try:
        parsed = urlparse(str(url or "").strip())
    except Exception:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    return parsed._replace(fragment="").geturl()


# A ``PageSource`` yields rendered page data without a real browser:
# ``(links, forms)`` for a URL.  Tests inject fakes; production passes None
# and gets Playwright.
PageSource = Callable[[str], Awaitable[Any]]


async def _extract_with_playwright(page: Any, url: str):
    """Render ``url`` in an existing Playwright page; return (links, forms)."""
    links = await page.evaluate("""() => Array.from(
        document.querySelectorAll('a[href]'),
        a => a.getAttribute('href'))""")
    forms = await page.evaluate("""() => Array.from(
        document.querySelectorAll('form')).map(f => ({
            action: f.getAttribute('action') || '',
            method: (f.getAttribute('method') || 'get').toLowerCase(),
            inputs: Array.from(f.querySelectorAll('input,select,textarea'))
                .map(i => ({
                    name: i.getAttribute('name') || '',
                    type: (i.getAttribute('type') || 'text').toLowerCase(),
                })).filter(i => i.name),
        }))""")
    return links or [], forms or []


async def headless_crawl(
    seeds: List[str],
    config: HeadlessConfig = None,
    auth: Any = None,
    page_source: PageSource = None,
) -> HeadlessResult:
    """Crawl seeds in a headless browser.  Never raises.

    ``page_source`` overrides the browser (tests).  Otherwise Playwright
    Chromium is launched headless; any problem (not installed, no
    browsers, launch failure) yields ``status: skipped`` with a reason.
    """
    cfg = config or HeadlessConfig()
    clean_seeds = []
    for seed in seeds or []:
        cleaned = _clean_url(seed)
        if cleaned and cleaned not in clean_seeds:
            clean_seeds.append(cleaned)
    if not clean_seeds:
        return HeadlessResult(status="skipped",
                              detail="no seed URLs for headless crawl")
    roots = _scope_roots(clean_seeds)
    max_pages = max(1, int(cfg.max_pages or 30))

    result = HeadlessResult(status="completed")
    seen: Set[str] = set()
    queue: List[str] = list(clean_seeds)

    async def visit(url: str, get_page_data) -> None:
        try:
            raw_links, raw_forms = await get_page_data(url)
        except Exception as exc:
            logger.debug("headless page failed %r: %s", url, exc)
            return
        result.pages_visited += 1
        for href in raw_links or []:
            absolute = urljoin(url, str(href or ""))
            cleaned = _clean_url(absolute)
            if not cleaned:
                continue
            if _in_scope(cleaned, roots):
                if cleaned not in seen and cleaned not in queue \
                        and len(seen) + len(queue) < max_pages * 4:
                    queue.append(cleaned)
                if cleaned not in result.urls:
                    result.urls.append(cleaned)
            else:
                result.external_seen += 1
        for form in raw_forms or []:
            if not isinstance(form, dict):
                continue
            action = urljoin(url, str(form.get("action") or ""))
            record = {"url": url,
                      "action": _clean_url(action) or action,
                      "method": str(form.get("method") or "get").lower(),
                      "inputs": [i for i in (form.get("inputs") or [])
                                 if isinstance(i, dict)]}
            if record not in result.forms:
                result.forms.append(record)

    if page_source is not None:
        # Injected transport (tests): no browser involved.
        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            await visit(url, page_source)
        result.detail = ("headless crawl (injected transport): %d page(s), "
                         "%d url(s), %d form(s)"
                         % (result.pages_visited, len(result.urls),
                            len(result.forms)))
        return result

    # -- real browser path ---------------------------------------------
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return HeadlessResult(
            status="skipped",
            detail=("Playwright not installed (pip install playwright); "
                    "static crawl results unchanged"))
    try:
        async with async_playwright() as pw:
            try:
                browser = await asyncio.wait_for(
                    pw.chromium.launch(headless=True), timeout=90)
            except Exception as exc:
                text = str(exc)
                if "Executable doesn't exist" in text \
                        or "playwright install" in text.lower():
                    return HeadlessResult(
                        status="skipped",
                        detail=("Chromium binaries missing; run "
                                "'playwright install chromium' once"))
                logger.info("headless browser launch failed: %s", exc)
                return HeadlessResult(
                    status="skipped",
                    detail="browser launch failed: %s" % (exc,))
            try:
                context = await browser.new_context(
                    user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) "
                                "Chrome/120.0.0.0 Safari/537.36"),
                    ignore_https_errors=True)
                # Authenticated crawl: replay the proven login cookies.
                try:
                    cookies = getattr(auth, "cookies", None) or {}
                    cookie_url = (getattr(auth, "cookie_url", "") or
                                  getattr(auth, "login_url", ""))
                    authed = bool(getattr(auth, "authenticated", False))
                    if authed and cookies and cookie_url:
                        host = (urlparse(cookie_url).hostname or "")
                        if host:
                            await context.add_cookies([{
                                "name": str(k), "value": str(v),
                                "domain": host, "path": "/",
                            } for k, v in cookies.items()])
                except Exception as exc:
                    logger.debug("headless auth cookie replay failed: %s",
                                 exc)
                page = await context.new_page()
                try:
                    page.set_default_timeout(int(cfg.page_timeout_ms or 20000))
                except Exception:
                    pass

                async def browser_source(target: str):
                    try:
                        await page.goto(target, wait_until=cfg.wait_until)
                    except Exception as exc:
                        logger.debug("headless goto failed %r: %s",
                                     target, exc)
                        return [], []
                    return await _extract_with_playwright(page, target)

                while queue and len(seen) < max_pages:
                    url = queue.pop(0)
                    if url in seen:
                        continue
                    seen.add(url)
                    await visit(url, browser_source)
            finally:
                try:
                    await browser.close()
                except Exception:
                    pass
    except Exception as exc:  # pragma: no cover - never break a scan
        logger.debug("headless crawl aborted: %s", exc)
        if result.pages_visited:
            result.detail = ("headless crawl aborted mid-run: %d page(s), "
                             "%d url(s)" % (result.pages_visited,
                                            len(result.urls)))
            return result
        return HeadlessResult(status="skipped",
                              detail="headless crawl aborted: %s" % (exc,))
    result.detail = ("headless Chromium: %d page(s), %d url(s), "
                     "%d form(s)%s"
                     % (result.pages_visited, len(result.urls),
                        len(result.forms),
                        " (authenticated)" if getattr(
                            auth, "authenticated", False) else ""))
    return result
