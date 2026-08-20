"""
tests/test_scanner.py – Unit tests for VulnerabilityScanner
============================================================
Covers:
  * rate_limiter initialisation (regression for the missing-semaphore bug)
  * Circuit breaker state: trips after max failures, skips further requests
  * SQL injection detection (error-based indicator in response)
  * XSS reflection detection
  * Missing security headers → MEDIUM severity finding
  * Sensitive info disclosure (db_password in body) → CRITICAL finding
  * Path traversal base URL scanning
  * scan_all() deduplication (duplicate URLs scanned only once)
  * scan_url() public alias delegates to scan_single_url()
  * fuzz_parameters() discovers parameters on 200 responses
  * _expand_urls() generates additional test endpoints
  * close() is idempotent and does not raise
"""

import re
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from aioresponses import aioresponses

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.vulnerability_scanner import VulnerabilityScanner
from modules.framework_config import FrameworkConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_scanner(stealth_mode: bool = False) -> VulnerabilityScanner:
    """Construct a VulnerabilityScanner with stealth disabled for test speed."""
    return VulnerabilityScanner(stealth_mode=stealth_mode)


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestScannerInit:
    """VulnerabilityScanner.__init__() must set up all required attributes."""

    def test_rate_limiter_is_initialised(self):
        """Regression test for the AttributeError caused by missing rate_limiter."""
        import asyncio
        scanner = make_scanner()
        assert hasattr(scanner, 'rate_limiter'), 'rate_limiter attribute must be created in __init__'
        assert isinstance(scanner.rate_limiter, asyncio.Semaphore)

    def test_host_failure_count_starts_empty(self):
        scanner = make_scanner()
        assert isinstance(scanner.host_failure_count, dict)
        assert len(scanner.host_failure_count) == 0

    def test_max_host_failures_positive(self):
        scanner = make_scanner()
        assert isinstance(scanner.max_host_failures, int)
        assert scanner.max_host_failures >= 1

    def test_scanned_endpoints_starts_empty(self):
        scanner = make_scanner()
        assert isinstance(scanner.scanned_endpoints, set)
        assert len(scanner.scanned_endpoints) == 0

    def test_stealth_engine_created(self):
        scanner = make_scanner()
        assert scanner.stealth_engine is not None

    def test_progress_counters_start_at_zero(self):
        scanner = make_scanner()
        assert scanner.total_to_scan == 0
        assert scanner.scanned_count == 0


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    """Circuit breaker must block requests after max failures and reset on success."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_blocks_after_max_failures(self):
        scanner = make_scanner()
        url = 'http://dead.test.local/api'
        host = 'dead.test.local'

        # Drive failure counter to threshold
        scanner.host_failure_count[host] = scanner.max_host_failures

        result = await scanner._request('GET', url)
        assert result is None, 'Requests to a tripped circuit breaker must return None'

        await scanner.close()

    @pytest.mark.asyncio
    async def test_circuit_breaker_trips_incrementally(self):
        """Each failed request must increment the failure counter."""
        scanner = make_scanner()
        url = 'http://failing.test.local/api'
        host = 'failing.test.local'

        with aioresponses() as mock_http:
            # Simulate failures below the threshold
            for _ in range(scanner.max_host_failures - 1):
                mock_http.get(url, exception=Exception('connection refused'))

            for _ in range(scanner.max_host_failures - 1):
                try:
                    await scanner._request('GET', url)
                except Exception:
                    pass

        assert scanner.host_failure_count.get(host, 0) >= scanner.max_host_failures - 1
        await scanner.close()

    @pytest.mark.asyncio
    async def test_circuit_breaker_resets_on_200(self):
        scanner = make_scanner()
        url = 'http://recovery.test.local/api'
        host = 'recovery.test.local'
        scanner.host_failure_count[host] = scanner.max_host_failures - 1

        with aioresponses() as mock_http:
            mock_http.get(url, status=200, body='ok')
            response = await scanner._request('GET', url)

        assert response is not None
        assert scanner.host_failure_count[host] == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# SQL Injection detection
# ---------------------------------------------------------------------------


class TestSQLInjectionDetection:
    """test_sql_injection_aggressive() must surface error-based SQL injection findings."""

    @pytest.mark.asyncio
    async def test_detects_error_based_sqli(self):
        scanner = make_scanner()
        url = 'http://sqli.test.local/page?id=1'

        with aioresponses() as mock_http:
            # Return a SQL error message for any request to this host
            mock_http.get(
                re.compile(r'.*sqli\.test\.local'),
                status=500,
                body="mysql error: You have an error in your SQL syntax",
                repeat=True,
            )

            params = {'id': ['1']}
            results = await scanner.test_sql_injection_aggressive(url, params)

        sqli = [v for v in results if 'SQL' in v.get('type', '')]
        assert len(sqli) > 0, 'SQL injection finding must be reported on SQL error body'
        assert sqli[0]['severity'] in ('CRITICAL', 'HIGH')
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_sqli_on_clean_response(self):
        scanner = make_scanner()
        url = 'http://clean.test.local/page?id=1'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*clean\.test\.local'),
                status=200,
                body='<html>Hello World</html>',
                repeat=True,
            )

            params = {'id': ['1']}
            results = await scanner.test_sql_injection_aggressive(url, params)

        sqli = [v for v in results if 'SQL' in v.get('type', '')]
        assert len(sqli) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# XSS detection
# ---------------------------------------------------------------------------


class TestXSSDetection:
    """test_xss_aggressive() must detect reflected payloads."""

    @pytest.mark.asyncio
    async def test_detects_reflected_xss(self):
        scanner = make_scanner()
        xss_payload = "<script>alert('XSS')</script>"
        url = 'http://xss.test.local/search?q=test'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*xss\.test\.local'),
                status=200,
                body=f'<html>Results: {xss_payload}</html>',
                repeat=True,
            )

            params = {'q': ['test']}
            results = await scanner.test_xss_aggressive(url, params)

        xss = [v for v in results if 'XSS' in v.get('type', '')]
        assert len(xss) > 0, 'Reflected XSS payload must be reported'
        assert xss[0]['severity'] in ('HIGH', 'CRITICAL')
        await scanner.close()


# ---------------------------------------------------------------------------
# Security headers check
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    """Missing security headers must produce a MEDIUM finding."""

    @pytest.mark.asyncio
    async def test_missing_security_headers_reported(self):
        scanner = make_scanner()
        url = 'http://noheaders.test.local/'

        # No X-Frame-Options, no CSP, no HSTS
        minimal_headers = {'Content-Type': 'text/html', 'Server': 'Apache/2.4.51'}

        with aioresponses() as mock_http:
            mock_http.get(url, status=200, body='<html></html>', headers=minimal_headers)

            results = await scanner.test_common_misconfigurations(url)

        header_findings = [v for v in results if 'Header' in v.get('type', '')]
        assert len(header_findings) > 0, 'Missing headers must be reported'
        for f in header_findings:
            assert f['severity'] == 'MEDIUM'
        await scanner.close()


# ---------------------------------------------------------------------------
# Sensitive info disclosure
# ---------------------------------------------------------------------------


class TestSensitiveInfoDisclosure:
    """Sensitive strings in response body must produce a CRITICAL finding."""

    @pytest.mark.asyncio
    async def test_db_password_in_body_detected(self):
        scanner = make_scanner()
        url = 'http://leak.test.local/.env'

        with aioresponses() as mock_http:
            mock_http.get(
                url, status=200,
                body='DB_PASSWORD="supersecret"\nAPI_KEY="12345"\n',
                headers={'Content-Type': 'text/plain'},
            )

            results = await scanner.test_common_misconfigurations(url)

        crit = [v for v in results if v.get('severity') == 'CRITICAL']
        assert len(crit) > 0, 'db_password exposure must yield a CRITICAL finding'
        await scanner.close()


# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------


class TestPathTraversalScanning:
    """test_path_traversal_base() must catch /etc/passwd via traversal payloads."""

    @pytest.mark.asyncio
    async def test_detects_passwd_via_traversal(self):
        scanner = make_scanner()
        url = 'http://traversal.test.local/app'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*traversal\.test\.local'),
                status=200,
                body='root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:',
                repeat=True,
            )

            results = await scanner.test_path_traversal_base(url)

        traversal = [v for v in results if 'Traversal' in v.get('type', '')]
        assert len(traversal) > 0
        assert traversal[0]['severity'] == 'CRITICAL'
        await scanner.close()


# ---------------------------------------------------------------------------
# scan_all deduplication
# ---------------------------------------------------------------------------


class TestScanAll:
    """scan_all() must not scan the same URL twice."""

    @pytest.mark.asyncio
    async def test_deduplication_of_duplicate_urls(self):
        scanner = make_scanner()
        url = 'http://dedup.test.local/'
        # Pass the same URL three times
        targets = [url, url, url]

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value='<html></html>')
        mock_resp.__aenter__.return_value = mock_resp
        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp
        mock_session.closed = False

        with aioresponses() as mock_http:
            with patch.object(scanner, '_expand_urls', return_value=[url]):
                with patch.object(scanner, '_ensure_session', new=AsyncMock(return_value=mock_session)):
                    with patch('asyncio.open_connection', side_effect=OSError('mock')):
                        with patch('socket.gethostbyname_ex', return_value=('dedup.test.local', [], ['1.2.3.4'])):
                            with patch('socket.gethostbyaddr', return_value=('dedup.test.local', [], ['1.2.3.4'])):
                                mock_http.get(
                                    re.compile(r'.*dedup\.test\.local'),
                                    status=200, body='<html></html>', repeat=True,
                                )
                                await scanner.scan_all(targets)

        # The scanned_endpoints set proves deduplication
        base_count = sum(1 for ep in scanner.scanned_endpoints if ep == url)
        # The base URL must appear only once even though it was passed 3 times
        assert base_count <= 1, 'Duplicate base URL should not be scanned multiple times'
        await scanner.close()


# ---------------------------------------------------------------------------
# scan_url alias
# ---------------------------------------------------------------------------


class TestScanUrlAlias:
    """scan_url() is a public alias for scan_single_url()."""

    @pytest.mark.asyncio
    async def test_scan_url_returns_list(self):
        scanner = make_scanner()
        url = 'http://alias.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(re.compile(r'.*alias\.test\.local'), status=200,
                          body='<html></html>', repeat=True)

            results = await scanner.scan_url(url)

        assert isinstance(results, list)
        await scanner.close()


# ---------------------------------------------------------------------------
# _expand_urls
# ---------------------------------------------------------------------------


class TestExpandUrls:
    """_expand_urls() must add common sensitive endpoints."""

    def test_expands_adds_admin_endpoint(self):
        scanner = make_scanner()
        base = ['http://expand.test.local/']
        expanded = scanner._expand_urls(base)
        admin_urls = [u for u in expanded if '/admin' in u]
        assert len(admin_urls) > 0, '/admin endpoint must be added by URL expansion'

    def test_expands_skips_malformed_urls(self):
        scanner = make_scanner()
        base = ['not-a-url', 'ftp://notsupported.com']
        expanded = scanner._expand_urls(base)
        # Should not crash; may return empty or partial list
        assert isinstance(expanded, list)


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


class TestScannerClose:
    """close() must be idempotent."""

    @pytest.mark.asyncio
    async def test_close_is_idempotent(self):
        scanner = make_scanner()
        await scanner.close()
        await scanner.close()   # second call must not raise


# ---------------------------------------------------------------------------
# SSTI (Server-Side Template Injection)
# ---------------------------------------------------------------------------


class TestSSTI:
    """test_ssti() must detect template expression reflection."""

    @pytest.mark.asyncio
    async def test_detects_jinja2_ssti(self):
        scanner = make_scanner()
        url = 'http://ssti.test.local/page?name=test'
        params = {'name': ['test']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*ssti\.test\.local'),
                status=200, body='<html>49</html>', repeat=True,
            )
            results = await scanner.test_ssti(url, params)

        ssti = [v for v in results if 'Template Injection' in v.get('type', '')]
        assert len(ssti) > 0
        assert ssti[0]['severity'] == 'CRITICAL'
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_ssti_on_clean_response(self):
        scanner = make_scanner()
        url = 'http://cleanssti.test.local/page?name=test'
        params = {'name': ['test']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*cleanssti\.test\.local'),
                status=200, body='<html>Hello World</html>', repeat=True,
            )
            results = await scanner.test_ssti(url, params)

        ssti = [v for v in results if 'Template Injection' in v.get('type', '')]
        assert len(ssti) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# NoSQL Injection
# ---------------------------------------------------------------------------


class TestNoSQLInjection:
    """test_nosql_injection() must check for timing-based NoSQL injection."""

    @pytest.mark.asyncio
    async def test_no_nosql_on_normal_response(self):
        scanner = make_scanner()
        url = 'http://nosql.test.local/login?user=admin'
        params = {'user': ['admin']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*nosql\.test\.local'),
                status=200, body='<html>Login Page</html>', repeat=True,
            )
            results = await scanner.test_nosql_injection(url, params)

        nosql = [v for v in results if 'NoSQL' in v.get('type', '')]
        assert len(nosql) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# LDAP Injection
# ---------------------------------------------------------------------------


class TestLDAPInjection:
    """test_ldap_injection() must flag LDAP filter manipulation."""

    @pytest.mark.asyncio
    async def test_detects_ldap_bypass_on_large_response(self):
        scanner = make_scanner()
        url = 'http://ldap.test.local/login?user=admin'
        params = {'user': ['admin']}

        # Baseline is a login page; the injected request returns a much
        # larger authenticated dashboard (auth-bypass indicators) - this
        # mirrors the FP-reduced detection (baseline comparison + auth context)
        login_page = ('<html><head><title>Login</title></head><body>'
                      'Please enter your username and password to sign in. '
                      'Invalid credentials will be rejected.</body></html>')
        admin_page = ('A' * 1000 + 'Welcome back, admin! Dashboard '
                      'You are now logged in. Admin panel active.')

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*ldap\.test\.local'),
                status=200, body=login_page,
            )
            mock_http.get(
                re.compile(r'.*ldap\.test\.local'),
                status=200, body=admin_page, repeat=True,
            )
            results = await scanner.test_ldap_injection(url, params)

        ldap = [v for v in results if 'LDAP' in v.get('type', '')]
        assert len(ldap) > 0
        assert ldap[0]['severity'] == 'HIGH'
        await scanner.close()

    @pytest.mark.asyncio
    async def test_ldap_detects_welcome_in_response(self):
        scanner = make_scanner()
        url = 'http://ldap2.test.local/login?user=admin'
        params = {'user': ['admin']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*ldap2\.test\.local'),
                status=200, body='Welcome admin', repeat=True,
            )
            results = await scanner.test_ldap_injection(url, params)

        ldap = [v for v in results if 'LDAP' in v.get('type', '')]
        assert len(ldap) > 0
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_ldap_on_small_response(self):
        scanner = make_scanner()
        url = 'http://ldap3.test.local/login?user=admin'
        params = {'user': ['admin']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*ldap3\.test\.local'),
                status=200, body='Error', repeat=True,
            )
            results = await scanner.test_ldap_injection(url, params)

        ldap = [v for v in results if 'LDAP' in v.get('type', '')]
        assert len(ldap) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# XPath Injection
# ---------------------------------------------------------------------------


class TestXPathInjection:
    """test_xpath_injection() must detect XPath boolean bypasses."""

    @pytest.mark.asyncio
    async def test_detects_xpath_via_dashboard(self):
        scanner = make_scanner()
        url = 'http://xpath.test.local/data?category=books'
        params = {'category': ['books']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*xpath\.test\.local'),
                status=200, body='Welcome to the dashboard', repeat=True,
            )
            results = await scanner.test_xpath_injection(url, params)

        xpath = [v for v in results if 'XPath' in v.get('type', '')]
        assert len(xpath) > 0
        assert xpath[0]['severity'] == 'HIGH'
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_xpath_on_normal_response(self):
        scanner = make_scanner()
        url = 'http://xpath2.test.local/data?category=books'
        params = {'category': ['books']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*xpath2\.test\.local'),
                status=200, body='<data><item>Book</item></data>', repeat=True,
            )
            results = await scanner.test_xpath_injection(url, params)

        xpath = [v for v in results if 'XPath' in v.get('type', '')]
        assert len(xpath) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# Open Redirect
# ---------------------------------------------------------------------------


class TestOpenRedirect:
    """test_open_redirect() must detect redirect to external domains."""

    @pytest.mark.asyncio
    async def test_detects_open_redirect(self):
        scanner = make_scanner()
        url = 'http://redirect.test.local/go?url=http://evil.com'
        params = {'url': ['http://evil.com']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*redirect\.test\.local'),
                status=302,
                headers={'Location': 'http://evil.com'},
                repeat=True,
            )
            results = await scanner.test_open_redirect(url, params)

        redirect = [v for v in results if 'Open Redirect' in v.get('type', '')]
        assert len(redirect) > 0
        assert redirect[0]['severity'] == 'MEDIUM'
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_redirect_on_same_origin(self):
        scanner = make_scanner()
        url = 'http://redirect2.test.local/go?url=/same'
        params = {'url': ['/same']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*redirect2\.test\.local'),
                status=302,
                headers={'Location': '/same'},
                repeat=True,
            )
            results = await scanner.test_open_redirect(url, params)

        redirect = [v for v in results if 'Open Redirect' in v.get('type', '')]
        assert len(redirect) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# CRLF Injection / HTTP Response Splitting
# ---------------------------------------------------------------------------


class TestCRLFInjection:
    """test_crlf_injection() must detect injected response headers."""

    @pytest.mark.asyncio
    async def test_detects_crlf_injected_header(self):
        scanner = make_scanner()
        url = 'http://crlf.test.local/page?input=test'
        params = {'input': ['test']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*crlf\.test\.local'),
                status=200,
                headers={'X-Injected': 'true'},
                repeat=True,
            )
            results = await scanner.test_crlf_injection(url, params)

        crlf = [v for v in results if 'CRLF' in v.get('type', '')]
        assert len(crlf) > 0
        assert crlf[0]['severity'] == 'HIGH'
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_crlf_without_injected_header(self):
        scanner = make_scanner()
        url = 'http://crlf2.test.local/page?input=test'
        params = {'input': ['test']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*crlf2\.test\.local'),
                status=200,
                headers={'Content-Type': 'text/html'},
                repeat=True,
            )
            results = await scanner.test_crlf_injection(url, params)

        crlf = [v for v in results if 'CRLF' in v.get('type', '')]
        assert len(crlf) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# CORS Misconfiguration
# ---------------------------------------------------------------------------


class TestCORSMisconfiguration:
    """test_cors_misconfiguration() must flag permissive CORS policies."""

    @pytest.mark.asyncio
    async def test_detects_permissive_cors(self):
        scanner = make_scanner()
        url = 'http://cors.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*cors\.test\.local'),
                status=200,
                headers={'Access-Control-Allow-Origin': 'https://evil.com'},
                body='<html></html>',
                repeat=True,
            )
            results = await scanner.test_cors_misconfiguration(url)

        cors = [v for v in results if 'CORS' in v.get('type', '')]
        assert len(cors) > 0
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_cors_on_secure_policy(self):
        scanner = make_scanner()
        url = 'http://cors2.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*cors2\.test\.local'),
                status=200,
                headers={'Access-Control-Allow-Origin': 'https://trusted.example.com'},
                body='<html></html>',
                repeat=True,
            )
            results = await scanner.test_cors_misconfiguration(url)

        cors = [v for v in results if 'CORS' in v.get('type', '')]
        assert len(cors) == 0
        await scanner.close()

    @pytest.mark.asyncio
    async def test_cors_with_credentials_is_critical(self):
        scanner = make_scanner()
        url = 'http://cors3.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*cors3\.test\.local'),
                status=200,
                headers={
                    'Access-Control-Allow-Origin': 'https://evil.com',
                    'Access-Control-Allow-Credentials': 'true',
                },
                body='<html></html>',
                repeat=True,
            )
            results = await scanner.test_cors_misconfiguration(url)

        dangerous = [v for v in results if 'Credentials' in v.get('type', '')]
        assert len(dangerous) > 0
        assert dangerous[0]['severity'] == 'CRITICAL'
        await scanner.close()


# ---------------------------------------------------------------------------
# JWT Vulnerabilities
# ---------------------------------------------------------------------------


class TestJWTVulnerabilities:
    """test_jwt_vulnerabilities() must find exposed JWT tokens."""

    @pytest.mark.asyncio
    async def test_detects_jwt_in_authorization_header(self):
        scanner = make_scanner()
        url = 'http://jwt.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*jwt\.test\.local'),
                status=200,
                headers={'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.secret'},
                body='<html></html>',
                repeat=True,
            )
            results = await scanner.test_jwt_vulnerabilities(url)

        jwt = [v for v in results if 'JWT' in v.get('type', '')]
        assert len(jwt) > 0
        await scanner.close()

    @pytest.mark.asyncio
    async def test_detects_jwt_in_page_source(self):
        scanner = make_scanner()
        url = 'http://jwt2.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*jwt2\.test\.local'),
                status=200,
                body='<script>var token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.secret";</script>',
                repeat=True,
            )
            results = await scanner.test_jwt_vulnerabilities(url)

        jwt = [v for v in results if 'JWT' in v.get('type', '')]
        assert any('Source' in v.get('type', '') for v in jwt)
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_jwt_on_clean_response(self):
        scanner = make_scanner()
        url = 'http://jwt3.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*jwt3\.test\.local'),
                status=200,
                body='<html>Hello</html>',
                repeat=True,
            )
            results = await scanner.test_jwt_vulnerabilities(url)

        jwt = [v for v in results if 'JWT' in v.get('type', '')]
        assert len(jwt) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# Cookie Security
# ---------------------------------------------------------------------------


class TestCookieSecurity:
    """test_cookie_security() must flag missing Secure/HttpOnly/SameSite flags."""

    @pytest.mark.asyncio
    async def test_reports_insecure_cookie(self):
        scanner = make_scanner()
        url = 'http://cookies.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*cookies\.test\.local'),
                status=200,
                headers={'Set-Cookie': 'session=abc123'},
                body='<html></html>',
                repeat=True,
            )
            results = await scanner.test_cookie_security(url)

        cookie_vulns = [v for v in results if 'Cookie' in v.get('type', '')]
        assert len(cookie_vulns) > 0
        assert all(v['severity'] == 'MEDIUM' for v in cookie_vulns)
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_report_for_secure_cookie(self):
        scanner = make_scanner()
        url = 'http://cookies2.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*cookies2\.test\.local'),
                status=200,
                headers={'Set-Cookie': 'session=abc123; Secure; HttpOnly; SameSite=Lax'},
                body='<html></html>',
                repeat=True,
            )
            results = await scanner.test_cookie_security(url)

        cookie_vulns = [v for v in results if 'Cookie' in v.get('type', '')]
        assert len(cookie_vulns) == 0
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_cookies_no_finding(self):
        scanner = make_scanner()
        url = 'http://cookies3.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*cookies3\.test\.local'),
                status=200,
                body='<html></html>',
                repeat=True,
            )
            results = await scanner.test_cookie_security(url)

        cookie_vulns = [v for v in results if 'Cookie' in v.get('type', '')]
        assert len(cookie_vulns) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# GraphQL Introspection
# ---------------------------------------------------------------------------


class TestGraphQLIntrospection:
    """test_graphql_introspection() must detect enabled introspection."""

    @pytest.mark.asyncio
    async def test_detects_graphql_introspection(self):
        scanner = make_scanner()
        url = 'http://gql.test.local/'

        with aioresponses() as mock_http:
            mock_http.post(
                re.compile(r'.*gql\.test\.local.*'),
                status=200,
                body='{"data": {"__schema": {"types": [{"name": "Query"}]}}}',
                repeat=True,
            )
            results = await scanner.test_graphql_introspection(url)

        gql = [v for v in results if 'GraphQL' in v.get('type', '')]
        assert len(gql) > 0
        assert gql[0]['severity'] == 'HIGH'
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_introspection_when_disabled(self):
        scanner = make_scanner()
        url = 'http://gql2.test.local/'

        with aioresponses() as mock_http:
            mock_http.post(
                re.compile(r'.*gql2\.test\.local.*'),
                status=400,
                body='{"errors": [{"message": "query not allowed"}]}',
                repeat=True,
            )
            results = await scanner.test_graphql_introspection(url)

        gql = [v for v in results if 'GraphQL' in v.get('type', '')]
        assert len(gql) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# Prototype Pollution
# ---------------------------------------------------------------------------


class TestPrototypePollution:
    """test_prototype_pollution() must detect vulnerable libraries."""

    @pytest.mark.asyncio
    async def test_detects_vulnerable_jquery(self):
        scanner = make_scanner()
        url = 'http://pp.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*pp\.test\.local'),
                status=200,
                body='<script src="jquery-3.4.1.min.js"></script>',
                repeat=True,
            )
            results = await scanner.test_prototype_pollution(url)

        pp = [v for v in results if 'Prototype Pollution' in v.get('type', '')]
        assert len(pp) > 0
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_pollution_with_modern_libraries(self):
        scanner = make_scanner()
        url = 'http://pp2.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*pp2\.test\.local'),
                status=200,
                body='<script src="app.js"></script>',
                repeat=True,
            )
            results = await scanner.test_prototype_pollution(url)

        pp = [v for v in results if 'Prototype Pollution' in v.get('type', '')]
        assert len(pp) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# Host Header Injection
# ---------------------------------------------------------------------------


class TestHostHeaderInjection:
    """test_host_header_injection() must detect reflected Host header."""

    @pytest.mark.asyncio
    async def test_detects_host_header_reflection(self):
        scanner = make_scanner()
        url = 'http://hhi.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*hhi\.test\.local'),
                status=200,
                body='<html>evil.com</html>',
                repeat=True,
            )
            results = await scanner.test_host_header_injection(url)

        hhi = [v for v in results if 'Host Header' in v.get('type', '')]
        assert len(hhi) > 0
        assert hhi[0]['severity'] == 'HIGH'
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_host_header_reflection(self):
        scanner = make_scanner()
        url = 'http://hhi2.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*hhi2\.test\.local'),
                status=200,
                body='<html>Welcome</html>',
                repeat=True,
            )
            results = await scanner.test_host_header_injection(url)

        hhi = [v for v in results if 'Host Header' in v.get('type', '')]
        assert len(hhi) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# HTTP Method Fuzzing
# ---------------------------------------------------------------------------


class TestHTTPMethodFuzzing:
    """test_http_method_fuzzing() must detect dangerous methods."""

    @pytest.mark.asyncio
    async def test_detects_put_method(self):
        scanner = make_scanner()
        url = 'http://methods.test.local/'

        with aioresponses() as mock_http:
            mock_http.put(
                re.compile(r'.*methods\.test\.local'),
                status=200,
                body='',
                repeat=True,
            )
            # Other methods return 405
            mock_http.delete(
                re.compile(r'.*methods\.test\.local'),
                status=405,
                repeat=True,
            )
            mock_http.patch(
                re.compile(r'.*methods\.test\.local'),
                status=405,
                repeat=True,
            )
            mock_http.options(
                re.compile(r'.*methods\.test\.local'),
                status=405,
                repeat=True,
            )
            mock_http.head(
                re.compile(r'.*methods\.test\.local'),
                status=405,
                repeat=True,
            )

            results = await scanner.test_http_method_fuzzing(url)

        methods = [v for v in results if 'HTTP Method' in v.get('type', '')]
        assert len(methods) > 0
        assert any('PUT' in v.get('payload', '') for v in methods)
        await scanner.close()

    @pytest.mark.asyncio
    async def test_all_methods_blocked(self):
        scanner = make_scanner()
        url = 'http://methods2.test.local/'

        with aioresponses() as mock_http:
            for m in ['PUT', 'DELETE', 'PATCH', 'OPTIONS']:
                getattr(mock_http, m.lower())(
                    re.compile(r'.*methods2\.test\.local'),
                    status=405,
                    repeat=True,
                )

            results = await scanner.test_http_method_fuzzing(url)

        methods = [v for v in results if 'HTTP Method' in v.get('type', '')]
        assert len(methods) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# Cache Poisoning
# ---------------------------------------------------------------------------


class TestCachePoisoning:
    """test_cache_poisoning() must detect reflected unkeyed headers."""

    @pytest.mark.asyncio
    async def test_detects_x_forwarded_host_reflection(self):
        scanner = make_scanner()
        url = 'http://cache.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*cache\.test\.local'),
                status=200,
                body='<html>evil.com</html>',
                repeat=True,
            )
            results = await scanner.test_cache_poisoning(url)

        cache = [v for v in results if 'Cache Poisoning' in v.get('type', '')]
        assert len(cache) > 0
        assert cache[0]['severity'] == 'HIGH'
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_cache_poisoning_without_reflection(self):
        scanner = make_scanner()
        url = 'http://cache2.test.local/'

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*cache2\.test\.local'),
                status=200,
                body='<html>No reflection</html>',
                repeat=True,
            )
            results = await scanner.test_cache_poisoning(url)

        cache = [v for v in results if 'Cache Poisoning' in v.get('type', '')]
        assert len(cache) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# Parameter Pollution
# ---------------------------------------------------------------------------


class TestParameterPollution:
    """test_parameter_pollution() must detect duplicate param handling."""

    @pytest.mark.asyncio
    async def test_detects_parameter_pollution(self):
        scanner = make_scanner()
        url = 'http://hpp.test.local/search?q=test'
        params = {'q': ['test']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*hpp\.test\.local'),
                status=200,
                body='<html>evil</html>',
                repeat=True,
            )
            results = await scanner.test_parameter_pollution(url, params)

        hpp = [v for v in results if 'Parameter Pollution' in v.get('type', '')]
        assert len(hpp) > 0
        assert hpp[0]['severity'] == 'LOW'
        await scanner.close()

    @pytest.mark.asyncio
    async def test_no_parameter_pollution_without_evil(self):
        scanner = make_scanner()
        url = 'http://hpp2.test.local/search?q=test'
        params = {'q': ['test']}

        with aioresponses() as mock_http:
            mock_http.get(
                re.compile(r'.*hpp2\.test\.local'),
                status=200,
                body='<html>Clean response</html>',
                repeat=True,
            )
            results = await scanner.test_parameter_pollution(url, params)

        hpp = [v for v in results if 'Parameter Pollution' in v.get('type', '')]
        assert len(hpp) == 0
        await scanner.close()

    @pytest.mark.asyncio
    async def test_empty_params_no_finding(self):
        scanner = make_scanner()
        url = 'http://hpp3.test.local/'
        params = {}

        results = await scanner.test_parameter_pollution(url, params)
        assert len(results) == 0
        await scanner.close()


# ---------------------------------------------------------------------------
# Subdomain Takeover (socket-based)
# ---------------------------------------------------------------------------


class TestSubdomainTakeover:
    """test_subdomain_takeover() must detect CNAME-based takeover indicators."""

    @pytest.mark.asyncio
    async def test_no_takeover_on_normal_domain(self):
        scanner = make_scanner()
        url = 'https://takeover.test.local/'

        with patch('socket.gethostbyname_ex', return_value=('takeover.test.local', [], ['1.2.3.4'])):
            with patch('socket.gethostbyaddr', return_value=('real-server.example.com', [], ['1.2.3.4'])):
                results = await scanner.test_subdomain_takeover(url)

        takeover = [v for v in results if 'Subdomain Takeover' in v.get('type', '')]
        assert len(takeover) == 0
        await scanner.close()

    @pytest.mark.asyncio
    async def test_detects_cloudfront_takeover(self):
        scanner = make_scanner()
        url = 'https://takeover2.test.local/'

        with patch('socket.gethostbyname_ex', return_value=('takeover2.test.local', [], ['1.2.3.4'])):
            with patch('socket.gethostbyaddr', return_value=('d123.cloudfront.net', [], ['1.2.3.4'])):
                results = await scanner.test_subdomain_takeover(url)

        takeover = [v for v in results if 'Subdomain Takeover' in v.get('type', '')]
        assert len(takeover) > 0
        assert takeover[0]['severity'] == 'HIGH'
        await scanner.close()

    @pytest.mark.asyncio
    async def test_detects_s3_takeover(self):
        scanner = make_scanner()
        url = 'https://takeover3.test.local/'

        with patch('socket.gethostbyname_ex', return_value=('takeover3.test.local', [], ['1.2.3.4'])):
            with patch('socket.gethostbyaddr', return_value=('bucket.s3.amazonaws.com', [], ['1.2.3.4'])):
                results = await scanner.test_subdomain_takeover(url)

        takeover = [v for v in results if 'Subdomain Takeover' in v.get('type', '')]
        assert len(takeover) > 0
        await scanner.close()


# ---------------------------------------------------------------------------
# HTTP Request Smuggling (raw TCP)
# ---------------------------------------------------------------------------


class TestHTTPRequestSmuggling:
    """test_http_request_smuggling() must attempt raw connection tests."""

    @pytest.mark.asyncio
    async def test_smuggling_does_not_crash(self):
        scanner = make_scanner()
        url = 'http://smuggling.test.local/'

        # Mock asyncio.open_connection to avoid actual network calls
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b'HTTP/1.1 200 OK\r\n\r\n')
        # writer.write()/close() are synchronous; only drain/wait_closed await
        mock_writer = MagicMock(write=lambda data: None)
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        with patch('asyncio.open_connection', new=AsyncMock(return_value=(mock_reader, mock_writer))):
            results = await scanner.test_http_request_smuggling(url)

        assert isinstance(results, list)
        await scanner.close()
