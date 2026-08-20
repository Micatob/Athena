"""Tests for credential stuffing on discovered login forms."""

import asyncio
import logging
import os
import tempfile
import unittest
from unittest.mock import MagicMock, AsyncMock

import aiohttp

import modules.bruteforce as bf_module

LOGIN_FORM = {
    'url': 'https://example.com/login',
    'method': 'POST',
    'inputs': [
        {'name': 'username'},
        {'name': 'password'},
        {'name': 'csrf_token'},
    ],
}


class _FakeResponse:
    """Async context manager stand-in for aiohttp.ClientResponse."""

    def __init__(self, text: str, status: int = 200):
        self.status = status
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def text(self):
        return self._text


def _fake_response(text: str, status: int = 200):
    return _FakeResponse(text, status)


class _FakeSession:
    """Minimal stand-in for aiohttp.ClientSession (cookie jar only)."""

    def __init__(self):
        self.cookie_jar = aiohttp.CookieJar()


class TestCredentialStuffing(unittest.TestCase):

    async def _make_module(self):
        module = bf_module.BruteforceModule.__new__(bf_module.BruteforceModule)
        session = _FakeSession()
        session.cookie_jar = aiohttp.CookieJar()
        module.session = session
        module.proxy = None
        module.logger = logging.getLogger('test-bruteforce')
        return module

    def test_success_found(self):
        async def _run():
            bf = await self._make_module()
            bf._request = AsyncMock(side_effect=[_fake_response('Invalid login'),
                                                 _fake_response('Welcome back, admin! Dashboard')])
            return await bf.credential_stuffing([LOGIN_FORM])
        results = asyncio.run(_run())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['username'], 'admin')
        self.assertEqual(results[0]['source'], 'credential-stuffing')

    def test_no_success(self):
        async def _run():
            bf = await self._make_module()
            bf._request = AsyncMock(return_value=_fake_response('Invalid credentials'))
            return await bf.credential_stuffing([LOGIN_FORM])
        results = asyncio.run(_run())
        self.assertEqual(results, [])

    def test_get_form(self):
        get_form = dict(LOGIN_FORM, method='GET')
        async def _run():
            bf = await self._make_module()
            bf._request = AsyncMock(return_value=_fake_response('Welcome to your dashboard'))
            return await bf.credential_stuffing([get_form])
        results = asyncio.run(_run())
        self.assertEqual(len(results), 1)

    def test_missing_fields_skipped(self):
        bad_form = {'url': 'https://example.com/x', 'method': 'POST',
                    'inputs': [{'name': 'foo'}, {'name': 'bar'}]}
        async def _run():
            bf = await self._make_module()
            return await bf.credential_stuffing([bad_form])
        results = asyncio.run(_run())
        self.assertEqual(results, [])

    def test_custom_creds_file(self):
        bf = asyncio.run(self._make_module())
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as f:
            f.write("alice:secret1\n# comment\nbob:s3cret2\n")
            path = f.name
        try:
            self.assertEqual(
                bf._load_credentials(path),
                [('alice', 'secret1'), ('bob', 's3cret2')])
        finally:
            os.unlink(path)

    def test_default_creds(self):
        bf = asyncio.run(self._make_module())
        creds = bf._load_credentials(None)
        self.assertTrue(('admin', 'admin') in creds)
        self.assertTrue(creds)

    def test_cookie_file_seeding(self):
        bf = asyncio.run(self._make_module())
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as f:
            f.write("# Netscape HTTP Cookie File\n"
                    ".example.com\tTRUE\t/\tFALSE\t0\tsessionid\tabc123\n"
                    "csrf=xyz789\n")
            path = f.name
        try:
            count = bf._load_cookies(path)
            self.assertEqual(count, 2)
            jar_cookies = list(bf.session.cookie_jar)
            values = {c.key: c.value for c in jar_cookies}
            self.assertIn('csrf', values)
            self.assertEqual(values['csrf'], 'xyz789')
        finally:
            os.unlink(path)

    def test_email_style_field_identification(self):
        bf = asyncio.run(self._make_module())
        form = {'url': 'https://example.com/login', 'method': 'POST',
                'inputs': [{'name': 'email_address', 'type': 'email'},
                           {'name': 'passwd'},
                           {'name': 'remember'}]}
        async def _run():
            bf._request = AsyncMock(return_value=_fake_response('Welcome, signed in'))
            return await bf.credential_stuffing([form])
        results = asyncio.run(_run())
        self.assertEqual(len(results), 1)

    def test_no_fields_falls_back_to_basic_auth(self):
        bf = asyncio.run(self._make_module())
        form = {'url': 'https://example.com/secure', 'method': 'POST',
                'inputs': [{'name': 'foo'}, {'name': 'bar'}]}
        async def _run():
            bf._try_basic_auth = AsyncMock(side_effect=[False, True])
            return await bf.credential_stuffing([form])
        results = asyncio.run(_run())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['method'], 'basic-auth')
        self.assertEqual(bf._try_basic_auth.await_count, 2)

    def test_basic_auth_success(self):
        bf = asyncio.run(self._make_module())
        token = 'YWRtaW46YWRtaW4='  # admin:admin
        async def _run():
            bf._request = AsyncMock(return_value=_fake_response('Welcome to the admin dashboard'))
            ok = await bf._try_basic_auth('https://example.com/', 'admin', 'admin')
            headers = bf._request.call_args.kwargs['headers']
            return ok, headers
        ok, headers = asyncio.run(_run())
        self.assertTrue(ok)
        self.assertEqual(headers['Authorization'], f'Basic {token}')

    def test_basic_auth_rejects_401(self):
        bf = asyncio.run(self._make_module())
        async def _run():
            bf._request = AsyncMock(return_value=_fake_response('unauthorized', status=401))
            return await bf._try_basic_auth('https://example.com/', 'admin', 'admin')
        self.assertFalse(asyncio.run(_run()))

    def test_csrf_token_harvested_and_replayed(self):
        bf = asyncio.run(self._make_module())
        form = {'url': 'https://example.com/login', 'method': 'POST',
                'inputs': [{'name': 'username'}, {'name': 'password'}]}
        csrf_page = '<form><input type="hidden" name="csrf_token" value="tok123"></form>'
        async def _run():
            bf._request = AsyncMock(side_effect=[
                _fake_response(csrf_page),
                _fake_response('Invalid credentials'),
                _fake_response('Welcome back, admin! Dashboard'),
            ])
            results = await bf.credential_stuffing([form])
            last_data = bf._request.call_args.kwargs.get('data', {})
            return results, last_data
        results, last_data = asyncio.run(_run())
        self.assertEqual(len(results), 1)
        self.assertEqual(last_data.get('csrf_token'), 'tok123')

    def test_rate_limit_adaptive_backoff(self):
        bf = asyncio.run(self._make_module())
        async def _run():
            with unittest.mock.patch('modules.bruteforce.asyncio.sleep', new=AsyncMock()):
                bf._request = AsyncMock(return_value=_fake_response('Too many requests', status=429))
                await bf.credential_stuffing([LOGIN_FORM])
                return bf._request.await_count
        count = asyncio.run(_run())
        self.assertGreaterEqual(count, len(bf._load_credentials(None)))

    def test_max_attempts_cap(self):
        bf = asyncio.run(self._make_module())
        async def _run():
            bf._request = AsyncMock(return_value=_fake_response('Invalid credentials'))
            results = await bf.credential_stuffing([LOGIN_FORM], max_attempts_per_form=3)
            return results, bf._request.await_count
        results, count = asyncio.run(_run())
        self.assertEqual(results, [])
        # 1 CSRF harvest GET + 3 stuffing attempts
        self.assertEqual(count, 4)

    def test_proxy_rotation(self):
        bf = asyncio.run(self._make_module())
        bf.proxies = ['http://p1:8080', 'http://p2:8080']
        bf._proxy_index = 0
        self.assertEqual(bf._next_proxy(), 'http://p1:8080')
        self.assertEqual(bf._next_proxy(), 'http://p2:8080')
        self.assertEqual(bf._next_proxy(), 'http://p1:8080')

    def test_parse_proxies(self):
        bf = asyncio.run(self._make_module())
        self.assertEqual(bf._parse_proxies(None), [])
        self.assertEqual(bf._parse_proxies('http://p1:8080, http://p2:8080'),
                         ['http://p1:8080', 'http://p2:8080'])
        self.assertEqual(bf._parse_proxies(['http://p1:8080']), ['http://p1:8080'])

    def test_ai_prioritize_never_raises(self):
        bf = asyncio.run(self._make_module())
        async def _run():
            return await bf._ai_prioritize_credentials([('admin', 'admin'), ('root', 'root')])
        result = asyncio.run(_run())
        self.assertEqual(len(result), 2)


if __name__ == '__main__':
    unittest.main()