"""
tests/conftest.py – Shared pytest fixtures for the Athena test suite
====================================================================
Provides:
  * ``mock_env``        – sets mandatory env vars for testing
  * ``app_client``      – Flask test client with mocked API key
  * ``clean_config``    – resets FrameworkConfig to known defaults after each test
  * ``event_loop``      – shared asyncio event loop (pytest-asyncio)
  * ``mock_auth_file``  – creates a fresh AETHELRED_AUTHORIZATION.txt in tmp dir
  * ``audit_log_path``  – temp path for audit logs during test runs
"""

import asyncio
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Generator

import pytest

# ---------------------------------------------------------------------------
# Suppress routine asyncio DNS-probe noise in ALL tests, even when the
# production setup_logging() is not called.  Without this, every aiohttp
# request to an unresolvable host spams stderr with "[asyncio] [ERROR]
# gaierror exception in shielded future …".
# ---------------------------------------------------------------------------
from modules.logging_config import SilentProbeFilter
_asyncio_logger = logging.getLogger('asyncio')
if not any(isinstance(f, SilentProbeFilter) for f in _asyncio_logger.filters):
    _asyncio_logger.addFilter(SilentProbeFilter())
_asyncio_logger.setLevel(logging.ERROR)

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so bare imports (modules.X) resolve
# ---------------------------------------------------------------------------
HERE = Path(__file__).parent.parent  # project root
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# ---------------------------------------------------------------------------
# aiohttp >= 3.14 compat for aioresponses 0.7.9 (no upstream fix as of
# 2026-10-17).  ClientResponse.__init__ gained a required keyword-only
# ``stream_writer`` argument; aioresponses constructs ClientResponse directly
# without it -> TypeError -> mocks never intercept and every mocked HTTP test
# fails.  This injects a null writer unless the caller already passed one
# (real aiohttp call sites always pass one).  Remove once aioresponses
# ships a fix.
# ---------------------------------------------------------------------------


class _NullStreamWriter:
    output_size = 0


def _patch_aioresponses_for_aiohttp314() -> None:
    import aiohttp
    ver = tuple(int(x) for x in aiohttp.__version__.split(".")[:2])
    if ver < (3, 14):
        return
    orig_init = aiohttp.ClientResponse.__init__

    def _init_with_default_stream_writer(self, *args, **kwargs):
        if "stream_writer" not in kwargs:
            kwargs["stream_writer"] = _NullStreamWriter()
        return orig_init(self, *args, **kwargs)

    aiohttp.ClientResponse.__init__ = _init_with_default_stream_writer


_patch_aioresponses_for_aiohttp314()


# ---------------------------------------------------------------------------
# Environment fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def mock_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set minimal env vars required by all tests.

    Applied automatically (autouse=True) so every test starts with a clean,
    well-defined environment regardless of what the developer has in their
    local ``.env`` file.
    """
    env_vars = {
        'ATHENA_API_KEY': 'test-api-key-athena-1234',
        'REQUIRE_API_KEY': 'true',
        'AETHELRED_SAFE_MODE': 'true',
        'AETHELRED_STEALTH': 'false',   # keep tests fast
        'AETHELRED_PROFILE': 'balanced',
        'PCI_AUDIT_ENABLED': 'true',
        'GDPR_LOGGING_ENABLED': 'true',
        'HTTP_TIMEOUT': '5',
        'HTTP_MAX_RETRIES': '2',
        'STEALTH_MIN_DELAY': '0',
        'STEALTH_MAX_DELAY': '0.05',
        'SCANNING_THREADS': '3',
        'LOG_FILE': 'test_aethelred.log',
        'AUDIT_LOG_FILE': 'test_audit.log',
    }
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)


@pytest.fixture()
def audit_log_path(tmp_path: Path) -> Path:
    """Return a temporary path for audit log files."""
    return tmp_path / 'audit.log'


# ---------------------------------------------------------------------------
# FrameworkConfig reset
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_config():
    """Reset FrameworkConfig class-level attributes to defaults after each test.

    This prevents profile-mutation tests from leaking state into subsequent
    tests that depend on the balanced defaults.
    """
    from modules.framework_config import FrameworkConfig, QuickConfigs

    # Capture original values
    original = {k: v for k, v in vars(FrameworkConfig).items() if not k.startswith('_')}

    yield

    # Restore originals
    for key, value in original.items():
        if not callable(value):
            setattr(FrameworkConfig, key, value)

    # Re-apply balanced profile so config is coherent
    QuickConfigs.balanced_profile()


# ---------------------------------------------------------------------------
# Flask test client
# ---------------------------------------------------------------------------


@pytest.fixture()
def app_client():
    """Return a Flask test-client with API key injected into every request."""
    # Build the Flask app without starting the underlying server
    import importlib
    import athena as athena_module

    # Patch run_web_server to expose the app object instead of binding a port
    original_run = athena_module.Flask.run
    captured_app = {}

    def patched_run(self, *args, **kwargs):
        captured_app['app'] = self

    athena_module.Flask.run = patched_run

    try:
        athena_module.run_web_server(safe_mode=True)
    finally:
        athena_module.Flask.run = original_run

    app = captured_app.get('app')
    assert app is not None, 'Flask app was not captured – check run_web_server'

    app.config['TESTING'] = True
    with app.test_client() as client:
        client.API_KEY = 'test-api-key-athena-1234'
        yield client


@pytest.fixture()
def api_headers() -> dict:
    """Return HTTP headers with a valid API key."""
    return {
        'X-API-KEY': 'test-api-key-athena-1234',
        'Content-Type': 'application/json',
    }


@pytest.fixture()
def bad_api_headers() -> dict:
    """Return HTTP headers with an *invalid* API key."""
    return {
        'X-API-KEY': 'wrong-key',
        'Content-Type': 'application/json',
    }


# ---------------------------------------------------------------------------
# Authorisation file fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_auth_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create a valid AETHELRED_AUTHORIZATION.txt and patch cwd to find it."""
    auth_file = tmp_path / 'AETHELRED_AUTHORIZATION.txt'
    auth_file.write_text(
        'AETHELRED-AUTHORIZED\nIssued: test fixture\n', encoding='utf-8'
    )
    monkeypatch.chdir(tmp_path)
    return auth_file


# ---------------------------------------------------------------------------
# Asyncio event loop
# ---------------------------------------------------------------------------


@pytest.fixture(scope='session')
def event_loop():
    """Single asyncio event loop shared across the whole test session."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()
