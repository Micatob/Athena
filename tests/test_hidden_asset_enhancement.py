import pytest
import asyncio
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch
from modules.hidden_asset_scanner import HiddenAssetScanner, HIDDEN_PATHS, BACKUP_EXTENSIONS
from modules.ai_integration import AIIntegration, AIProvider


class _AsyncCtx:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, *args):
        return False


def _async_ctx(response):
    return _AsyncCtx(response)


def _async_value(value):
    return AsyncMock(return_value=value)


class TestHiddenAssetScanner:
    def test_scanner_initialization(self):
        scanner = HiddenAssetScanner()
        assert scanner.discovered_hidden_directories == []
        assert scanner.discovered_backup_files == []
        assert scanner.discovered_misconfigurations == []

    def test_classify_path(self):
        scanner = HiddenAssetScanner()
        assert scanner._classify_path("/.git/") == "version_control"
        assert scanner._classify_path("/.env") == "environment_config"
        assert scanner._classify_path("/config.php.bak") == "backup_file"
        assert scanner._classify_path("/.htaccess") == "server_config"
        assert scanner._classify_path("/admin/") == "admin_panel"
        assert scanner._classify_path("/api/") == "api_endpoint"
        assert scanner._classify_path("/.hidden") == "hidden_file"
        assert scanner._classify_path("/logs/") == "log_file"

    def test_determine_severity(self):
        scanner = HiddenAssetScanner()
        mock_headers = {}
        assert scanner._determine_severity("/.git/", mock_headers) == "CRITICAL"
        assert scanner._determine_severity("/.env", mock_headers) == "CRITICAL"
        assert scanner._determine_severity("/config.php.bak", mock_headers) == "CRITICAL"
        assert scanner._determine_severity("/admin/", mock_headers) == "CRITICAL"
        assert scanner._determine_severity("/.htaccess", mock_headers) == "HIGH"

    def test_hidden_paths_not_empty(self):
        assert len(HIDDEN_PATHS) > 50
        assert "/.git" in HIDDEN_PATHS
        assert "/.env" in HIDDEN_PATHS
        assert "/config.php.bak" in HIDDEN_PATHS

    def test_backup_extensions(self):
        assert ".bak" in BACKUP_EXTENSIONS
        assert ".sql" in BACKUP_EXTENSIONS
        assert ".zip" in BACKUP_EXTENSIONS
        assert ".tar.gz" in BACKUP_EXTENSIONS

    def test_build_results(self):
        scanner = HiddenAssetScanner()
        scanner.discovered_hidden_directories = [{"path": "/.git/", "severity": "CRITICAL"}]
        scanner.discovered_backup_files = [{"path": "/config.php.bak", "severity": "CRITICAL"}]
        scanner.discovered_misconfigurations = [{"type": "directory_listing", "severity": "HIGH"}]
        results = scanner._build_results("https://example.com", "", 0)
        assert results["summary"]["total_hidden_directories"] == 1
        assert results["summary"]["total_backup_files"] == 1
        assert results["summary"]["total_misconfigurations"] == 1
        assert results["summary"]["critical_findings"] >= 2

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        scanner = HiddenAssetScanner()
        network_calls = [
            "scan_hidden_paths", "scan_backup_files", "check_security_headers",
            "test_http_methods", "check_directory_listing", "check_default_credentials",
            "check_cors", "check_verbose_errors",
        ]
        with patch.multiple(HiddenAssetScanner, **{name: AsyncMock() for name in network_calls}):
            results = await scanner.run("https://example.com")
        assert isinstance(results, dict)
        assert "hidden_directories" in results
        assert "backup_files" in results
        assert "misconfigurations" in results
        assert "summary" in results
        assert results["target"] == "https://example.com"
        await scanner.close()

    @pytest.mark.asyncio
    async def test_run_normalizes_bare_hostname(self):
        scanner = HiddenAssetScanner()
        network_calls = [
            "scan_hidden_paths", "scan_backup_files", "check_security_headers",
            "test_http_methods", "check_directory_listing", "check_default_credentials",
            "check_cors", "check_verbose_errors",
        ]
        with patch.multiple(HiddenAssetScanner, **{name: AsyncMock() for name in network_calls}):
            results = await scanner.run("example.com")
        assert results["target"] == "https://example.com"
        await scanner.close()

    @pytest.mark.asyncio
    async def test_run_survives_task_failure(self):
        scanner = HiddenAssetScanner()
        network_calls = [
            "scan_hidden_paths", "scan_backup_files", "check_security_headers",
            "test_http_methods", "check_directory_listing", "check_default_credentials",
            "check_cors", "check_verbose_errors",
        ]
        mocks = {name: AsyncMock() for name in network_calls}
        mocks["scan_hidden_paths"] = AsyncMock(side_effect=RuntimeError("boom"))
        with patch.multiple(HiddenAssetScanner, **mocks):
            results = await scanner.run("https://example.com")
        assert isinstance(results, dict)
        assert results["hidden_directories"] == []
        await scanner.close()

    @pytest.mark.skipif(
        os.environ.get("ATHENA_LIVE_TESTS") != "1",
        reason="set ATHENA_LIVE_TESTS=1 to run real network scanning (slow: ~231 requests)",
    )
    @pytest.mark.asyncio
    async def test_run_live(self):
        scanner = HiddenAssetScanner()
        results = await scanner.run("https://example.com")
        assert isinstance(results, dict)
        assert "summary" in results
        await scanner.close()

    def test_closed_passes(self):
        scanner = HiddenAssetScanner()
        assert callable(scanner.close)

    def test_bounded_concurrency_defaults(self):
        scanner = HiddenAssetScanner()
        assert scanner.max_concurrency > 0
        assert scanner.budget_seconds > 0
        assert scanner._semaphore._value == scanner.max_concurrency

    def test_concurrency_and_budget_configurable(self):
        scanner = HiddenAssetScanner(max_concurrency=4, budget_seconds=7.5)
        assert scanner.max_concurrency == 4
        assert scanner.budget_seconds == 7.5
        assert scanner._semaphore._value == 4

    @pytest.mark.asyncio
    async def test_probe_respects_budget(self):
        scanner = HiddenAssetScanner(budget_seconds=0.0)
        scanner._deadline = time.monotonic() - 1
        session = AsyncMock()
        assert await scanner._probe(session, "https://example.com/.git") is None
        assert scanner.probes_skipped == 1
        assert scanner.probes_completed == 0

    @pytest.mark.asyncio
    async def test_probe_returns_none_for_non_200(self):
        scanner = HiddenAssetScanner()
        scanner._deadline = time.monotonic() + 30
        response = MagicMock()
        response.status = 404
        response.headers = {}
        session = MagicMock()
        session.get = MagicMock(return_value=_async_ctx(response))
        assert await scanner._probe(session, "https://example.com/nope") is None
        assert scanner.probes_completed == 1

    @pytest.mark.asyncio
    async def test_scan_paths_dedupes_and_records(self):
        scanner = HiddenAssetScanner()
        scanner._deadline = time.monotonic() + 30
        requested = []

        def make_get(url, **kwargs):
            requested.append(url)
            response = MagicMock()
            response.status = 200
            response.headers = {"Server": "nginx"}
            response.text = _async_value("[core]\nrepositoryformatversion = 0\n")
            return _async_ctx(response)

        session = MagicMock()
        session.get = make_get
        scanner._get_session = AsyncMock(return_value=session)

        await scanner.scan_hidden_paths("https://example.com")

        paths = {d["path"] for d in scanner.discovered_hidden_directories}
        assert "/.git" in paths
        assert len(requested) == len(set(requested)), "probe URLs must be deduplicated"
        assert len(requested) <= len(HIDDEN_PATHS)
        assert all(d["status_code"] == 200 for d in scanner.discovered_hidden_directories)
        assert all(d["severity"] in ("CRITICAL", "HIGH", "MEDIUM")
                   for d in scanner.discovered_hidden_directories)

    @pytest.mark.asyncio
    async def test_scan_paths_ignores_non_200(self):
        scanner = HiddenAssetScanner()
        scanner._deadline = time.monotonic() + 30

        def make_get(url, **kwargs):
            response = MagicMock()
            response.status = 404
            response.headers = {}
            response.text = _async_value("not found")
            return _async_ctx(response)

        session = MagicMock()
        session.get = make_get
        scanner._get_session = AsyncMock(return_value=session)

        await scanner.scan_hidden_paths("https://example.com")

        assert scanner.discovered_hidden_directories == []
        assert scanner.probes_completed > 0


class TestAIIntegrationEnhancements:
    def test_prompts_contain_new_keys(self):
        """Verify new prompt templates are registered."""
        engine = AIIntegration()
        assert "hidden_asset_scanner" in engine.PROMPTS
        assert "post_exploitation_validation" in engine.PROMPTS
        assert "aggressive_confirmation" in engine.PROMPTS

    def test_prompts_have_no_minor(self):
        """'minor' may only appear to forbid its use, never to classify a finding."""
        import re
        negation = re.compile(r"never|not\b|must not|no\b", re.IGNORECASE)
        engine = AIIntegration()
        for key in ["hidden_asset_scanner", "post_exploitation_validation", "aggressive_confirmation"]:
            prompt = engine.PROMPTS[key]
            for match in re.finditer(r"minor", prompt, re.IGNORECASE):
                window = prompt[max(0, match.start() - 90):match.end() + 90]
                assert negation.search(window), f"{key} uses 'minor' as a classification"

    @pytest.mark.asyncio
    async def test_validate_hidden_assets_returns_empty_when_disabled(self):
        engine = AIIntegration()
        if not engine._enabled:
            result = await engine.validate_hidden_assets({})
            assert result == []

    @pytest.mark.asyncio
    async def test_validate_post_exploitation_returns_empty_when_disabled(self):
        engine = AIIntegration()
        if not engine._enabled:
            result = await engine.validate_post_exploitation({})
            assert result == []

    @pytest.mark.asyncio
    async def test_analyze_misconfigurations_returns_empty_when_disabled(self):
        engine = AIIntegration()
        if not engine._enabled:
            result = await engine.analyze_misconfigurations({}, {}, [])
            assert result == []

    def test_provider_groq_available(self):
        engine = AIIntegration()
        assert AIProvider.GROQ in [p for p in [AIProvider.GEMINI, AIProvider.GROQ, AIProvider.DEEPSEEK]]


class TestPostExploitationEnhancements:
    def test_enum_class_has_new_methods(self):
        from modules.post_exploitation.enumeration import SystemEnumerator
        assert hasattr(SystemEnumerator, "_enum_hidden_files_linux")
        assert hasattr(SystemEnumerator, "_enum_backup_files_linux")
        assert hasattr(SystemEnumerator, "_enum_misconfigurations_linux")
        assert hasattr(SystemEnumerator, "_enum_hidden_files_windows")
        assert hasattr(SystemEnumerator, "_enum_backup_files_windows")
        assert hasattr(SystemEnumerator, "_enum_misconfigurations_windows")

    def test_hidden_files_method_signature(self):
        from modules.post_exploitation.enumeration import SystemEnumerator
        import inspect
        sig = inspect.signature(SystemEnumerator._enum_hidden_files_linux)
        assert "session" in sig.parameters
        assert "deadline" in sig.parameters

    def test_backup_files_method_signature(self):
        from modules.post_exploitation.enumeration import SystemEnumerator
        import inspect
        sig = inspect.signature(SystemEnumerator._enum_backup_files_linux)
        assert "session" in sig.parameters
        assert "deadline" in sig.parameters


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
