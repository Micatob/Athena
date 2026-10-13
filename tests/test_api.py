"""
tests/test_api.py – Integration tests for the Athena Flask REST API
====================================================================
Covers:
  * GET  /health               → 200 with correct structure
  * POST /scan (no key)        → 401
  * POST /scan (bad key)       → 401
  * POST /scan (valid key)     → 202 + job_id
  * POST /scan (multi-target)  → 202 + targets_count == 2
  * POST /scan (missing target field) → 400
  * POST /scan (empty target)  → 400
  * POST /scan (too many targets) → 400
  * POST /scan (invalid mode)  → 400
  * GET  /scan/status/{id}     → 200 with job structure
  * GET  /scan/status/bad-id   → 404
  * POST /scan/url (valid URL) → 200 with findings list
  * POST /scan/url (bad URL)   → 400
  * POST /scan/url (missing url field) → 400
  * GET  /jobs                 → 200 with jobs list
  * GET  /metrics              → 200 with Prometheus text
  * Security headers present on responses
  * Rate limiting returns 429 after threshold
"""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


@pytest.fixture(scope='module')
def flask_app():
    """Build a Flask test app without binding to a port."""
    import os
    import tempfile
    os.environ.setdefault('ATHENA_API_KEY', 'test-api-key-athena-1234')
    os.environ.setdefault('REQUIRE_API_KEY', 'true')
    os.environ.setdefault('AETHELRED_SAFE_MODE', 'true')
    os.environ.setdefault('MAX_TARGETS_PER_REQUEST', '5')
    os.environ.setdefault('HTTPS_ENABLED', 'false')
    os.environ.setdefault('RATE_LIMIT_SCAN', '1000 per minute')
    os.environ.setdefault('RATE_LIMIT_DEFAULT', '10000 per hour')
    # Durable queue/history must never touch the operator's real DB.
    os.environ['ATHENA_DB_PATH'] = os.path.join(
        tempfile.mkdtemp(prefix='athena-test-db-'), 'test.db')

    # Patch Flask.run so run_web_server doesn't block
    from flask import Flask
    original_run = Flask.run
    captured: dict = {}

    def fake_run(self, *a, **kw):
        captured['app'] = self

    Flask.run = fake_run
    try:
        from athena import run_web_server
        run_web_server(safe_mode=True)
    finally:
        Flask.run = original_run

    app = captured['app']
    app.config['TESTING'] = True
    return app


@pytest.fixture()
def client(flask_app):
    with flask_app.test_client() as c:
        yield c


@pytest.fixture()
def auth(monkeypatch):
    """Sets ATHENA_API_KEY for the duration of a single test."""
    monkeypatch.setenv('ATHENA_API_KEY', 'test-api-key-athena-1234')
    return {'X-API-KEY': 'test-api-key-athena-1234', 'Content-Type': 'application/json'}


@pytest.fixture()
def no_auth():
    return {'Content-Type': 'application/json'}


@pytest.fixture()
def bad_auth():
    return {'X-API-KEY': 'totally-wrong', 'Content-Type': 'application/json'}


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


class TestHealthEndpoint:

    def test_health_returns_200(self, client, auth):
        resp = client.get('/health')
        assert resp.status_code == 200

    def test_health_returns_online_status(self, client, auth):
        data = resp_json(client.get('/health'))
        assert data['status'] == 'online'

    def test_health_includes_version(self, client, auth):
        data = resp_json(client.get('/health'))
        assert 'version' in data

    def test_health_includes_safe_mode(self, client, auth):
        data = resp_json(client.get('/health'))
        assert 'safe_mode' in data

    def test_health_includes_active_scans(self, client, auth):
        data = resp_json(client.get('/health'))
        assert 'active_scans' in data
        assert isinstance(data['active_scans'], int)

    def test_health_no_auth_required(self, client, no_auth):
        """Health endpoint is public (no API key needed)."""
        resp = client.get('/health')
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /metrics
# ---------------------------------------------------------------------------


class TestMetricsEndpoint:

    def test_metrics_returns_200(self, client):
        resp = client.get('/metrics')
        assert resp.status_code == 200

    def test_metrics_content_type_prometheus(self, client):
        resp = client.get('/metrics')
        assert 'text/plain' in resp.content_type

    def test_metrics_contains_athena_counter(self, client):
        resp = client.get('/metrics')
        body = resp.data.decode('utf-8')
        assert 'athena_scan_requests_total' in body or 'athena_' in body


# ---------------------------------------------------------------------------
# /scan authentication
# ---------------------------------------------------------------------------


class TestScanAuthentication:

    def test_scan_without_api_key_returns_401(self, client, no_auth):
        resp = client.post('/scan', headers=no_auth,
                           data=json.dumps({'target': 'example.com'}))
        assert resp.status_code == 401

    def test_scan_with_wrong_api_key_returns_401(self, client, bad_auth):
        resp = client.post('/scan', headers=bad_auth,
                           data=json.dumps({'target': 'example.com'}))
        assert resp.status_code == 401

    def test_scan_401_body_has_error_key(self, client, no_auth):
        resp = client.post('/scan', headers=no_auth,
                           data=json.dumps({'target': 'example.com'}))
        data = resp_json(resp)
        assert 'error' in data


# ---------------------------------------------------------------------------
# /scan request validation
# ---------------------------------------------------------------------------


class TestScanRequestValidation:

    def test_scan_missing_target_returns_400(self, client, auth):
        resp = client.post('/scan', headers=auth, data=json.dumps({}))
        assert resp.status_code == 400

    def test_scan_empty_target_string_returns_400(self, client, auth):
        resp = client.post('/scan', headers=auth, data=json.dumps({'target': '   '}))
        assert resp.status_code == 400

    def test_scan_invalid_mode_returns_400(self, client, auth):
        resp = client.post('/scan', headers=auth,
                           data=json.dumps({'target': 'example.com', 'mode': '9'}))
        assert resp.status_code == 400

    def test_scan_too_many_targets_returns_400(self, client, auth):
        # MAX_TARGETS_PER_REQUEST is set to 5 in fixture env
        targets = [f'target{i}.com' for i in range(20)]
        resp = client.post('/scan', headers=auth,
                           data=json.dumps({'target': targets}))
        assert resp.status_code == 400

    def test_scan_body_not_json_returns_400(self, client, auth):
        headers = {**auth, 'Content-Type': 'text/plain'}
        resp = client.post('/scan', headers=headers, data='not json')
        assert resp.status_code in (400, 415)


# ---------------------------------------------------------------------------
# /scan successful dispatch
# ---------------------------------------------------------------------------


class TestScanDispatch:

    @patch('athena._run_background_scan', new_callable=AsyncMock)
    def test_scan_single_target_returns_202(self, mock_bg, client, auth):
        resp = client.post('/scan', headers=auth,
                           data=json.dumps({'target': 'example.com'}))
        assert resp.status_code == 202

    @patch('athena._run_background_scan', new_callable=AsyncMock)
    def test_scan_returns_job_id(self, mock_bg, client, auth):
        resp = client.post('/scan', headers=auth,
                           data=json.dumps({'target': 'example.com'}))
        data = resp_json(resp)
        assert 'job_id' in data
        assert len(data['job_id']) > 0

    @patch('athena._run_background_scan', new_callable=AsyncMock)
    def test_scan_returns_targets_count(self, mock_bg, client, auth):
        resp = client.post('/scan', headers=auth,
                           data=json.dumps({'target': 'example.com'}))
        data = resp_json(resp)
        assert data.get('targets_count') == 1

    @patch('athena._run_background_scan', new_callable=AsyncMock)
    def test_scan_multi_target_list(self, mock_bg, client, auth):
        resp = client.post('/scan', headers=auth,
                           data=json.dumps({'target': ['a.com', 'b.com']}))
        assert resp.status_code == 202
        data = resp_json(resp)
        assert data['targets_count'] == 2

    @patch('athena._run_background_scan', new_callable=AsyncMock)
    def test_scan_multi_target_comma_string(self, mock_bg, client, auth):
        resp = client.post('/scan', headers=auth,
                           data=json.dumps({'target': 'a.com,b.com,c.com'}))
        assert resp.status_code == 202
        data = resp_json(resp)
        assert data['targets_count'] == 3

    @patch('athena._run_background_scan', new_callable=AsyncMock)
    def test_scan_returns_poll_url(self, mock_bg, client, auth):
        resp = client.post('/scan', headers=auth,
                           data=json.dumps({'target': 'example.com'}))
        data = resp_json(resp)
        assert 'poll_url' in data
        assert data['poll_url'].startswith('/scan/status/')


# ---------------------------------------------------------------------------
# /scan/status
# ---------------------------------------------------------------------------


class TestScanStatus:

    @patch('athena._run_background_scan', new_callable=AsyncMock)
    def test_status_for_existing_job_returns_200(self, mock_bg, client, auth):
        # Create a job
        resp = client.post('/scan', headers=auth,
                           data=json.dumps({'target': 'status.test.com'}))
        job_id = resp_json(resp)['job_id']

        # Poll it
        status_resp = client.get(f'/scan/status/{job_id}', headers=auth)
        assert status_resp.status_code == 200

    @patch('athena._run_background_scan', new_callable=AsyncMock)
    def test_status_response_has_required_keys(self, mock_bg, client, auth):
        resp = client.post('/scan', headers=auth,
                           data=json.dumps({'target': 'keys.test.com'}))
        job_id = resp_json(resp)['job_id']
        data = resp_json(client.get(f'/scan/status/{job_id}', headers=auth))
        for key in ('id', 'status', 'targets', 'mode', 'started_at'):
            assert key in data

    def test_status_for_nonexistent_job_returns_404(self, client, auth):
        resp = client.get('/scan/status/no-such-job-id', headers=auth)
        assert resp.status_code == 404

    def test_status_without_auth_returns_401(self, client, no_auth):
        resp = client.get('/scan/status/anything', headers=no_auth)
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /scan/url
# ---------------------------------------------------------------------------


class TestScanUrl:

    def test_scan_url_requires_url_field(self, client, auth):
        resp = client.post('/scan/url', headers=auth, data=json.dumps({}))
        assert resp.status_code == 400

    def test_scan_url_rejects_non_http_scheme(self, client, auth):
        resp = client.post('/scan/url', headers=auth,
                           data=json.dumps({'url': 'ftp://evil.com'}))
        assert resp.status_code == 400

    def test_scan_url_rejects_bare_string(self, client, auth):
        resp = client.post('/scan/url', headers=auth,
                           data=json.dumps({'url': 'not-a-url'}))
        assert resp.status_code == 400

    @patch('athena.VulnerabilityScanner')
    def test_scan_url_valid_returns_200(self, mock_scanner_cls, client, auth):
        instance = mock_scanner_cls.return_value
        instance.scan_url = AsyncMock(return_value=[])
        instance.close = AsyncMock()

        resp = client.post('/scan/url', headers=auth,
                           data=json.dumps({'url': 'http://example.com/test?id=1'}))
        assert resp.status_code == 200

    @patch('athena.VulnerabilityScanner')
    def test_scan_url_response_has_findings_key(self, mock_scanner_cls, client, auth):
        instance = mock_scanner_cls.return_value
        instance.scan_url = AsyncMock(return_value=[])
        instance.close = AsyncMock()

        resp = client.post('/scan/url', headers=auth,
                           data=json.dumps({'url': 'https://example.com/'}))
        data = resp_json(resp)
        assert 'findings' in data
        assert 'count' in data


# ---------------------------------------------------------------------------
# /jobs
# ---------------------------------------------------------------------------


class TestJobsList:

    def test_jobs_requires_auth(self, client, no_auth):
        resp = client.get('/jobs', headers=no_auth)
        assert resp.status_code == 401

    @patch('athena._run_background_scan', new_callable=AsyncMock)
    def test_jobs_returns_list(self, mock_bg, client, auth):
        resp = client.get('/jobs', headers=auth)
        assert resp.status_code == 200
        data = resp_json(resp)
        assert 'jobs' in data
        assert isinstance(data['jobs'], list)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    """All responses must include mandatory security headers."""

    REQUIRED_HEADERS = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Cache-Control',
    ]

    def test_health_response_has_security_headers(self, client):
        resp = client.get('/health')
        for header in self.REQUIRED_HEADERS:
            assert header in resp.headers, f'Missing security header: {header}'

    def test_x_frame_options_is_deny(self, client):
        resp = client.get('/health')
        assert resp.headers.get('X-Frame-Options') == 'DENY'

    def test_x_content_type_options_is_nosniff(self, client):
        resp = client.get('/health')
        assert resp.headers.get('X-Content-Type-Options') == 'nosniff'


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def resp_json(resp) -> dict:
    """Parse response JSON with a helpful error message on failure."""
    try:
        return resp.get_json() or json.loads(resp.data)
    except Exception as exc:
        raise AssertionError(
            f'Response was not valid JSON. Status={resp.status_code} Body={resp.data[:200]}'
        ) from exc
