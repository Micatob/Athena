import asyncio
import aiohttp
import logging
import random
import re
from typing import Dict, Optional, Any
from urllib.parse import urlparse

from modules.framework_config import FrameworkConfig
from modules.evasion import EvasionEngine, EvasionConfig

#: Statuses where the server refused to hand back a representation.  Body
#: checks against these compare an error page, never the resource, so any
#: finding derived from them is a false positive.
ERROR_STATUSES = frozenset({
    400, 401, 403, 406, 407, 408, 415, 418, 421, 429,
    500, 501, 502, 503, 504, 505, 507, 508, 510, 511,
})

_ERROR_TITLE = re.compile(
    r'<title>\s*\d{3}\s+(?:not acceptable|forbidden|bad request|'
    r'too many requests|service unavailable|internal server error|'
    r'bad gateway|request timeout|unsupported media type)',
    re.IGNORECASE)


def is_error_page(status: Optional[int], body: str = '') -> bool:
    """True when ``status``/``body`` is a server error page, not content.

    ``404`` is deliberately *not* an error page: "the resource does not
    exist" is a usable answer.  ``None`` (request failed) counts as one so
    callers fall back to "no evidence".
    """
    if status is None:
        return True
    try:
        if int(status) in ERROR_STATUSES:
            return True
    except (TypeError, ValueError):
        return True
    if body and _ERROR_TITLE.search(body[:2000]):
        return True
    return False


async def make_request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    host_failure_count: Dict[str, int],
    max_host_failures: int = 5,
    rate_limiter: asyncio.Semaphore,
    stealth_mode: bool = False,
    stealth_engine=None,
    evasion_engine: Optional[EvasionEngine] = None,
    logger: Optional[logging.Logger] = None,
    proxy: Optional[str] = None,
    **kwargs,
) -> Optional[aiohttp.ClientResponse]:
    host = urlparse(url).netloc
    if host_failure_count.get(host, 0) >= max_host_failures:
        if logger:
            logger.debug("Circuit breaker: Skipping %s due to repeated failures on %s", url, host)
        return None

    ev_engine = evasion_engine or (EvasionEngine() if stealth_mode else None)
    max_attempts = FrameworkConfig.HTTP_MAX_RETRIES

    for attempt in range(max_attempts):
        if stealth_mode:
            if ev_engine:
                delay = ev_engine.get_delay()
                await asyncio.sleep(delay)
                kwargs.setdefault('headers', {})
                kwargs['headers']['User-Agent'] = ev_engine.get_random_user_agent()
                kwargs['headers'] = ev_engine.add_noise_headers(kwargs['headers'])
            else:
                await asyncio.sleep(random.uniform(FrameworkConfig.STEALTH_MIN_DELAY, FrameworkConfig.STEALTH_MAX_DELAY))

        if proxy:
            kwargs['proxy'] = proxy

        async with rate_limiter:
            try:
                jitter = random.uniform(0.1, 0.5) if stealth_mode else random.uniform(0.05, 0.2)
                await asyncio.sleep(jitter)

                response = await session.request(method, url, **kwargs)
                host_failure_count[host] = 0

                if response.status in (429, 502, 503):
                    retry_after = response.headers.get('Retry-After')
                    try:
                        delay = float(retry_after) if retry_after else random.uniform(5.0, 15.0)
                    except ValueError:
                        delay = random.uniform(5.0, 15.0)
                    if logger:
                        logger.warning("Rate limited (HTTP %s) on %s. Sleeping %.2fs...", response.status, url, delay)
                    await asyncio.sleep(delay)
                    if ev_engine:
                        kwargs['headers'] = ev_engine.add_noise_headers(kwargs.get('headers', {}))
                    continue

                return response
            except aiohttp.ClientProxyConnectionError as e:
                if logger:
                    logger.error("Proxy connection error for %s: %s", url, e)
                return None
            except aiohttp.ClientHttpProxyError as e:
                if logger:
                    logger.error("HTTP proxy error for %s: %s", url, e)
                return None
            except Exception as e:
                host_failure_count[host] = host_failure_count.get(host, 0) + 1
                if logger:
                    logger.debug("Request failed for %s (attempt %d/%d): %s", url, attempt + 1, max_attempts, e)
                if attempt == max_attempts - 1:
                    return None
                await asyncio.sleep(random.uniform(1.0, 3.0))

    return None


async def create_stealth_session(
    evasion_config: Optional[EvasionConfig] = None,
    proxy_url: Optional[str] = None,
    max_connections: int = 100,
    timeout: int = 30,
) -> aiohttp.ClientSession:
    connector = aiohttp.TCPConnector(
        ssl=False,
        limit=max_connections,
        limit_per_host=max(1, max_connections // 2),
    )
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    if proxy_url:
        return aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers=headers,
        )
    return aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=timeout),
        headers=headers,
    )
