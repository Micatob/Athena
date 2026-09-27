"""
tests/test_discovery.py – Unit tests for DiscoveryModule
========================================================
Covers:
  * _extract_version_pattern for various version string formats
  * _extract_version_from_url for script/CSS URL version extraction
  * _guess_port_service port-to-service mapping
  * _is_comment_library_noise filtering of library/minifier comments
  * SECRET_PATTERNS regex matches
  * _add_tech and _add_versioned_tech confidence tracking
  * _sanitize_technologies HTML artifact removal
  * analyze_dns_records DNS record parsing and SPF/DMARC analysis
  * check_tls_certificate TLS certificate parsing and expiry checks
  * discover_security_endpoints well-known security endpoint discovery
"""

import asyncio
import re
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.discovery import DiscoveryModule


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture()
def discovery():
    with patch('aiohttp.ClientSession') as mock_session:
        mock_session.return_value = MagicMock()
        d = DiscoveryModule()
        yield d


# ============================================================================
# _extract_version_pattern
# ============================================================================


class TestExtractVersionPattern:

    def test_apache(self, discovery):
        name, ver = discovery._extract_version_pattern('Apache/2.4.49 (Ubuntu)')
        assert name == 'Apache'
        assert ver == '2.4.49'

    def test_nginx(self, discovery):
        name, ver = discovery._extract_version_pattern('nginx/1.18.0')
        assert name == 'Nginx'
        assert ver == '1.18.0'

    def test_php(self, discovery):
        name, ver = discovery._extract_version_pattern('PHP/8.0.28')
        assert name == 'PHP'
        assert ver == '8.0.28'

    def test_plain_name_no_version(self, discovery):
        name, ver = discovery._extract_version_pattern('Cloudflare')
        assert name == 'Cloudflare'
        assert ver == ''

    def test_name_map_case_insensitive(self, discovery):
        name, ver = discovery._extract_version_pattern('MICROSOFT-IIS/10.0')
        assert name == 'IIS'
        assert ver == '10.0'

    def test_version_with_hyphen_prerelease(self, discovery):
        name, ver = discovery._extract_version_pattern('node/16.14.2-alpine')
        assert name == 'Node.js'
        assert ver == '16.14.2-alpine'

    def test_empty_string(self, discovery):
        name, ver = discovery._extract_version_pattern('')
        assert name == ''
        assert ver == ''

    def test_whitespace_only(self, discovery):
        name, ver = discovery._extract_version_pattern('   ')
        assert name == ''
        assert ver == ''

    def test_triple_digit_version(self, discovery):
        name, ver = discovery._extract_version_pattern('Python/3.10.4')
        assert name == 'Python'
        assert ver == '3.10.4'

    def test_double_digit_version(self, discovery):
        name, ver = discovery._extract_version_pattern('IIS 8.5')
        assert name == 'IIS'
        assert ver == '8.5'


# ============================================================================
# _extract_version_from_url
# ============================================================================


class TestExtractVersionFromURL:

    def test_jquery(self, discovery):
        results = discovery._extract_version_from_url('https://cdn.example.com/jquery-3.6.0.min.js')
        assert ('jQuery', '3.6.0') in results

    def test_bootstrap(self, discovery):
        results = discovery._extract_version_from_url('https://cdn.example.com/bootstrap-5.2.3.min.css')
        assert ('Bootstrap', '5.2.3') in results

    def test_vue(self, discovery):
        results = discovery._extract_version_from_url('https://cdn.example.com/vue-3.3.4.js')
        assert ('Vue.js', '3.3.4') in results

    def test_react(self, discovery):
        results = discovery._extract_version_from_url('https://cdn.example.com/react-18.2.0.js')
        assert ('React', '18.2.0') in results

    def test_angular(self, discovery):
        results = discovery._extract_version_from_url('https://cdn.example.com/angular-15.0.0.js')
        assert ('Angular', '15.0.0') in results

    def test_multiple_matches(self, discovery):
        results = discovery._extract_version_from_url('https://cdn.example.com/jquery-3.6.0/bootstrap-5.0.0.js')
        assert ('jQuery', '3.6.0') in results
        assert ('Bootstrap', '5.0.0') in results

    def test_no_match(self, discovery):
        results = discovery._extract_version_from_url('https://cdn.example.com/app.js')
        assert results == []

    def test_case_insensitive(self, discovery):
        results = discovery._extract_version_from_url('https://cdn.example.com/JQUERY-3.6.0.JS')
        assert ('jQuery', '3.6.0') in results


# ============================================================================
# _guess_port_service
# ============================================================================


class TestGuessPortService:

    def test_ssh(self, discovery):
        assert discovery._guess_port_service(22) == 'SSH'

    def test_http(self, discovery):
        assert discovery._guess_port_service(80) == 'HTTP'

    def test_https(self, discovery):
        assert discovery._guess_port_service(443) == 'HTTPS'

    def test_mysql(self, discovery):
        assert discovery._guess_port_service(3306) == 'MySQL'

    def test_unknown_port(self, discovery):
        assert discovery._guess_port_service(9999) == 'Unknown'

    def test_redis(self, discovery):
        assert discovery._guess_port_service(6379) == 'Redis'


# ============================================================================
# _is_comment_library_noise
# ============================================================================


class TestIsCommentLibraryNoise:

    def test_license_text_is_noise(self, discovery):
        assert discovery._is_comment_library_noise('MIT License')

    def test_copyright_is_noise(self, discovery):
        assert discovery._is_comment_library_noise('Copyright (c) 2023 Example Corp')

    def test_minifier_boilerplate_is_noise(self, discovery):
        assert discovery._is_comment_library_noise('Minified by terser')

    def test_eslint_directive_is_noise(self, discovery):
        assert discovery._is_comment_library_noise('eslint-disable')

    def test_short_single_word_is_noise(self, discovery):
        assert discovery._is_comment_library_noise('global')

    def test_long_comments_are_noise(self, discovery):
        long_text = 'word ' * 61
        assert discovery._is_comment_library_noise(long_text)

    def test_jsdoc_style_is_noise(self, discovery):
        assert discovery._is_comment_library_noise('@param name string')

    def test_meaningful_todo_is_not_noise(self, discovery):
        assert not discovery._is_comment_library_noise('TODO: fix this security issue in login')

    def test_todo_password_is_not_noise(self, discovery):
        assert not discovery._is_comment_library_noise('TODO: remove hardcoded password')

    def test_fixme_bypass_is_not_noise(self, discovery):
        assert not discovery._is_comment_library_noise('FIXME: authentication bypass in admin')


# ============================================================================
# SECRET_PATTERNS regex matches
# ============================================================================


class TestSecretPatterns:

    def test_aws_access_key(self, discovery):
        pattern = discovery.SECRET_PATTERNS['AWS API Key']
        assert re.search(pattern, 'AKIAIOSFODNN7EXAMPLE')

    def test_aws_secret_key(self, discovery):
        pattern = discovery.SECRET_PATTERNS['AWS Secret Key']
        assert re.search(pattern, 'aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')

    def test_github_token(self, discovery):
        pattern = discovery.SECRET_PATTERNS['GitHub Token']
        token = 'ghp_' + 'a' * 36
        assert re.search(pattern, token)

    def test_stripe_api_key(self, discovery):
        pattern = discovery.SECRET_PATTERNS['Stripe API Key']
        assert re.search(pattern, 'sk_live_REDACTED')

    def test_database_connection_string(self, discovery):
        pattern = discovery.SECRET_PATTERNS['Database Connection String']
        assert re.search(pattern, 'mysql://user:password@localhost:3306/mydb')

    def test_private_key_header(self, discovery):
        pattern = discovery.SECRET_PATTERNS['Private Key']
        assert re.search(pattern, '-----BEGIN RSA PRIVATE KEY-----')

    def test_generic_credential(self, discovery):
        pattern = discovery.SECRET_PATTERNS['Generic Credential / Token']
        assert re.search(pattern, 'password = "supersecret1234567890"')


# ============================================================================
# _add_tech and _add_versioned_tech
# ============================================================================


class TestAddTech:

    def test_add_tech_adds_to_set(self, discovery):
        discovery._add_tech('TestTech')
        assert 'TestTech' in discovery.technologies

    def test_add_tech_tracks_confidence(self, discovery):
        discovery._add_tech('TestTech', confidence=2)
        assert discovery._tech_confidence.get('TestTech') == 2

    def test_add_tech_default_confidence(self, discovery):
        discovery._add_tech('TestTech')
        assert discovery._tech_confidence.get('TestTech') == 3

    def test_add_tech_max_confidence(self, discovery):
        discovery._add_tech('TestTech', confidence=2)
        discovery._add_tech('TestTech', confidence=3)
        assert discovery._tech_confidence.get('TestTech') == 3

    def test_add_versioned_tech_base_and_versioned(self, discovery):
        discovery._add_versioned_tech('PHP', '8.0.1')
        assert 'PHP' in discovery.technologies
        assert 'PHP 8.0.1' in discovery.technologies

    def test_add_versioned_tech_no_version(self, discovery):
        discovery._add_versioned_tech('Nginx')
        assert 'Nginx' in discovery.technologies

    def test_add_versioned_tech_confidence(self, discovery):
        discovery._add_versioned_tech('Apache', '2.4.49', confidence=2)
        assert discovery._tech_confidence.get('Apache') == 2
        assert discovery._tech_confidence.get('Apache 2.4.49') == 2


# ============================================================================
# _sanitize_technologies
# ============================================================================


@pytest.mark.asyncio
class TestSanitizeTechnologies:

    async def test_removes_html_tags(self, discovery):
        discovery.technologies = {'PHP', '<div>', 'Apache'}
        await discovery._sanitize_technologies()
        assert 'PHP' in discovery.technologies
        assert 'Apache' in discovery.technologies
        assert '<div>' not in discovery.technologies

    async def test_removes_single_character(self, discovery):
        discovery.technologies = {'A', 'PHP'}
        await discovery._sanitize_technologies()
        assert 'PHP' in discovery.technologies
        assert 'A' not in discovery.technologies

    async def test_removes_html_comment_start(self, discovery):
        discovery.technologies = {'PHP', '<!--', 'Apache'}
        await discovery._sanitize_technologies()
        assert 'PHP' in discovery.technologies
        assert '<!--' not in discovery.technologies

    async def test_removes_curly_bracket_start(self, discovery):
        discovery.technologies = {'PHP', '{some: json}', 'Apache'}
        await discovery._sanitize_technologies()
        assert 'PHP' in discovery.technologies
        assert '{some: json}' not in discovery.technologies

    async def test_removes_bracket_start(self, discovery):
        discovery.technologies = {'PHP', '[1,2,3]'}
        await discovery._sanitize_technologies()
        assert 'PHP' in discovery.technologies
        assert '[1,2,3]' not in discovery.technologies

    async def test_empty_set(self, discovery):
        discovery.technologies = set()
        await discovery._sanitize_technologies()
        assert discovery.technologies == set()


# ============================================================================
# analyze_dns_records
# ============================================================================


class TestAnalyzeDNSRecords:
    """DNS record analysis must return structured info and security assessments."""

    @pytest.mark.asyncio
    async def test_dns_a_records_populated(self, discovery):
        with patch('socket.gethostbyname_ex', return_value=('example.com', [], ['1.2.3.4'])):
            result = await discovery.analyze_dns_records('https://example.com')
        assert result['domain'] == 'example.com'
        assert '1.2.3.4' in result['a_records']

    @pytest.mark.asyncio
    async def test_dns_no_dnspython_fallback(self, discovery):
        with patch('socket.gethostbyname_ex', return_value=('example.com', [], ['1.2.3.4'])):
            with patch('builtins.__import__', side_effect=ImportError('no dnspython')):
                result = await discovery.analyze_dns_records('https://example.com')
        assert result['domain'] == 'example.com'
        assert result['mx_records'] == []

    @pytest.mark.asyncio
    async def test_dns_detects_cloudflare_cdn(self, discovery):
        with patch('socket.gethostbyname_ex', return_value=('example.com', [], ['104.16.1.1'])):
            result = await discovery.analyze_dns_records('https://example.com')
        assert 'Cloudflare CDN' in discovery.technologies

    @pytest.mark.asyncio
    async def test_dns_detects_aws_hosting(self, discovery):
        with patch('socket.gethostbyname_ex', return_value=('example.com', [], ['54.123.45.67'])):
            result = await discovery.analyze_dns_records('https://example.com')
        assert 'AWS Hosting' in discovery.technologies


# ============================================================================
# check_tls_certificate
# ============================================================================


class TestCheckTLSCertificate:
    """TLS certificate check must return domain and parse cert details."""

    @pytest.mark.asyncio
    async def test_tls_returns_domain_on_failure(self, discovery):
        with patch('socket.create_connection', side_effect=OSError('connection refused')):
            result = await discovery.check_tls_certificate('https://example.com')
        assert result['domain'] == 'example.com'
        assert 'issues' in result

    @pytest.mark.asyncio
    async def test_tls_parses_subject_and_sans(self, discovery):
        cert_data = {
            'subject': (('commonName', 'example.com'),),
            'issuer': (('organizationName', 'Test CA'),),
            'notAfter': 'Jun 17 23:59:59 2027 GMT',
            'notBefore': 'Jun 17 00:00:00 2026 GMT',
            'subjectAltName': (('DNS', 'example.com'), ('DNS', 'www.example.com')),
        }
        future = asyncio.Future()
        future.set_result((cert_data, 'TLSv1.2', ('AES256-GCM-SHA384', 256, 'TLSv1.2')))
        mock_loop = MagicMock()
        mock_loop.run_in_executor = MagicMock(return_value=future)

        with patch('asyncio.get_event_loop', return_value=mock_loop):
            result = await discovery.check_tls_certificate('https://example.com')

        assert result['domain'] == 'example.com'
        assert 'example.com' in result.get('subject_alt_names', [])
        assert 'www.example.com' in result.get('subject_alt_names', [])

    @pytest.mark.asyncio
    async def test_tls_reports_weak_version(self, discovery):
        cert_data = {
            'subject': (('commonName', 'example.com'),),
            'issuer': (('organizationName', 'Test CA'),),
            'notAfter': 'Jun 17 23:59:59 2027 GMT',
            'subjectAltName': (('DNS', 'example.com'),),
        }
        future = asyncio.Future()
        future.set_result((cert_data, 'TLSv1.1', ('RC4-SHA', 128, 'TLSv1.1')))
        mock_loop = MagicMock()
        mock_loop.run_in_executor = MagicMock(return_value=future)

        with patch('asyncio.get_event_loop', return_value=mock_loop):
            result = await discovery.check_tls_certificate('https://example.com')

        issues = ' '.join(result.get('issues', []))
        assert 'TLSv1.1' in issues or 'Weak' in issues or 'RC4' in issues or 'weak' in issues

    @pytest.mark.asyncio
    async def test_tls_detects_wildcard_cert(self, discovery):
        cert_data = {
            'subject': (('commonName', '*.other.com'),),
            'issuer': (('organizationName', 'Test CA'),),
            'notAfter': 'Jun 17 23:59:59 2027 GMT',
            'subjectAltName': (('DNS', '*.other.com'),),
        }
        future = asyncio.Future()
        future.set_result((cert_data, 'TLSv1.2', ('AES256-GCM-SHA384', 256, 'TLSv1.2')))
        mock_loop = MagicMock()
        mock_loop.run_in_executor = MagicMock(return_value=future)

        with patch('asyncio.get_event_loop', return_value=mock_loop):
            result = await discovery.check_tls_certificate('https://example.com')

        wildcard_found = any('Wildcard' in t for t in discovery.technologies)
        assert wildcard_found


# ============================================================================
# discover_security_endpoints
# ============================================================================


class TestDiscoverSecurityEndpoints:
    """Security endpoint discovery must find well-known resources."""

    @pytest.mark.asyncio
    async def test_discover_security_endpoints_finds_robots_txt(self, discovery):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value='User-agent: *\nDisallow: /admin')
        mock_resp.__aenter__.return_value = mock_resp
        mock_session.get.return_value = mock_resp
        discovery._get_session = AsyncMock(return_value=mock_session)

        result = await discovery.discover_security_endpoints('https://example.com')
        assert len(result) > 0
        assert result[0]['status'] == 200

    @pytest.mark.asyncio
    async def test_discover_security_endpoints_skips_404(self, discovery):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.text = AsyncMock(return_value='Not Found')
        mock_resp.__aenter__.return_value = mock_resp
        mock_session.get.return_value = mock_resp
        discovery._get_session = AsyncMock(return_value=mock_session)

        result = await discovery.discover_security_endpoints('https://example.com')
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_discover_security_endpoints_returns_content_length(self, discovery):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value='content')
        mock_resp.__aenter__.return_value = mock_resp
        mock_session.get.return_value = mock_resp
        discovery._get_session = AsyncMock(return_value=mock_session)

        result = await discovery.discover_security_endpoints('https://example.com')
        assert result[0]['content_length'] == len('content')
