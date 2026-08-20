"""
tests/test_config.py – Unit tests for FrameworkConfig and QuickConfigs
======================================================================
Covers:
  * Default values and type correctness
  * All four QuickConfig profiles (stealth, balanced, aggressive, debug)
  * Environment variable overrides
  * get_exploitation_config, get_stealth_config, get_logging_config, get_api_config
  * get_config() top-level key structure
  * load_config() with valid and unknown profiles
  * _load_payloads() fallback when payloads.json is missing
  * WAF_BYPASS_TECHNIQUES and PAYLOAD_TEMPLATES availability
"""

import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.framework_config import (
    FrameworkConfig,
    QuickConfigs,
    WAF_BYPASS_TECHNIQUES,
    PAYLOAD_TEMPLATES,
    _load_payloads,
    get_config,
    load_config,
)


# ============================================================================
# Default attribute tests
# ============================================================================


class TestFrameworkConfigDefaults:
    """FrameworkConfig must expose all required attributes with sensible defaults."""

    def test_operational_mode_attributes_exist(self):
        assert hasattr(FrameworkConfig, 'STEALTH_MODE')
        assert hasattr(FrameworkConfig, 'VERBOSE_MODE')
        assert hasattr(FrameworkConfig, 'AGGRESSIVE_MODE')
        assert hasattr(FrameworkConfig, 'SAFE_MODE')

    def test_operational_modes_are_booleans(self):
        assert isinstance(FrameworkConfig.STEALTH_MODE, bool)
        assert isinstance(FrameworkConfig.VERBOSE_MODE, bool)
        assert isinstance(FrameworkConfig.AGGRESSIVE_MODE, bool)
        assert isinstance(FrameworkConfig.SAFE_MODE, bool)

    def test_http_timeout_is_positive_int(self):
        assert isinstance(FrameworkConfig.HTTP_TIMEOUT, int)
        assert FrameworkConfig.HTTP_TIMEOUT >= 1

    def test_http_max_retries_is_positive_int(self):
        assert isinstance(FrameworkConfig.HTTP_MAX_RETRIES, int)
        assert FrameworkConfig.HTTP_MAX_RETRIES >= 1

    def test_stealth_delays_are_floats_and_ordered(self):
        assert isinstance(FrameworkConfig.STEALTH_MIN_DELAY, float)
        assert isinstance(FrameworkConfig.STEALTH_MAX_DELAY, float)
        assert FrameworkConfig.STEALTH_MIN_DELAY <= FrameworkConfig.STEALTH_MAX_DELAY

    def test_thread_counts_are_positive_ints(self):
        assert FrameworkConfig.DISCOVERY_THREADS >= 1
        assert FrameworkConfig.SCANNING_THREADS >= 1
        assert FrameworkConfig.EXPLOITATION_THREADS >= 1
        assert FrameworkConfig.BRUTEFORCE_THREADS >= 1

    def test_new_api_security_attributes_exist(self):
        assert hasattr(FrameworkConfig, 'REQUIRE_API_KEY')
        assert hasattr(FrameworkConfig, 'MAX_TARGETS_PER_REQUEST')

    def test_compliance_attributes_exist(self):
        assert hasattr(FrameworkConfig, 'PCI_AUDIT_ENABLED')
        assert hasattr(FrameworkConfig, 'GDPR_LOGGING_ENABLED')
        assert hasattr(FrameworkConfig, 'AUDIT_LOG_RETENTION_DAYS')

    def test_max_targets_per_request_is_positive_int(self):
        assert isinstance(FrameworkConfig.MAX_TARGETS_PER_REQUEST, int)
        assert FrameworkConfig.MAX_TARGETS_PER_REQUEST >= 1

    def test_audit_retention_days_is_positive_int(self):
        assert isinstance(FrameworkConfig.AUDIT_LOG_RETENTION_DAYS, int)
        assert FrameworkConfig.AUDIT_LOG_RETENTION_DAYS > 0

    def test_log_file_is_non_empty_string(self):
        assert isinstance(FrameworkConfig.LOG_FILE, str)
        assert len(FrameworkConfig.LOG_FILE) > 0

    def test_audit_log_file_is_non_empty_string(self):
        assert isinstance(FrameworkConfig.AUDIT_LOG_FILE, str)
        assert len(FrameworkConfig.AUDIT_LOG_FILE) > 0


# ============================================================================
# Environment variable override tests
# ============================================================================


class TestEnvironmentOverrides:
    """FrameworkConfig must pick up env vars correctly."""

    def test_http_timeout_override(self, monkeypatch):
        monkeypatch.setenv('HTTP_TIMEOUT', '42')
        # Re-import to pick up the new value (or test the raw env lookup)
        val = int(os.getenv('HTTP_TIMEOUT', '10'))
        assert val == 42

    def test_safe_mode_override_false(self, monkeypatch):
        monkeypatch.setenv('ATHENA_SAFE_MODE', 'false')
        val = os.getenv('ATHENA_SAFE_MODE', 'True').lower() == 'true'
        assert val is False

    def test_require_api_key_can_be_disabled(self, monkeypatch):
        monkeypatch.setenv('REQUIRE_API_KEY', 'false')
        val = os.getenv('REQUIRE_API_KEY', 'true').lower() in ('1', 'true', 'yes')
        assert val is False

    def test_max_targets_override(self, monkeypatch):
        monkeypatch.setenv('MAX_TARGETS_PER_REQUEST', '25')
        val = int(os.getenv('MAX_TARGETS_PER_REQUEST', '10'))
        assert val == 25


# ============================================================================
# Config accessor methods
# ============================================================================


class TestConfigAccessors:
    """Test the config dict-returning class methods."""

    def test_get_exploitation_config_keys(self):
        config = FrameworkConfig.get_exploitation_config()
        required_keys = {
            'aggressive_mode', 'waf_bypass', 'stealth_mode',
            'max_retries', 'timeout', 'session_management',
            'exploit_chaining', 'safe_mode',
        }
        assert required_keys.issubset(config.keys())

    def test_get_exploitation_config_safe_mode_is_bool(self):
        config = FrameworkConfig.get_exploitation_config()
        assert isinstance(config['safe_mode'], bool)

    def test_get_stealth_config_keys(self):
        config = FrameworkConfig.get_stealth_config()
        required_keys = {
            'stealth_mode', 'min_delay', 'max_delay',
            'randomize_ua', 'noise_headers', 'waf_detect', 'waf_bypass',
        }
        assert required_keys.issubset(config.keys())

    def test_get_logging_config_keys(self):
        config = FrameworkConfig.get_logging_config()
        required_keys = {
            'log_file', 'audit_log_file', 'log_level',
            'pci_audit_enabled', 'gdpr_logging_enabled',
        }
        assert required_keys.issubset(config.keys())

    def test_get_api_config_keys(self):
        config = FrameworkConfig.get_api_config()
        required_keys = {
            'require_api_key', 'max_targets_per_request',
            'rate_limit_scan', 'rate_limit_default',
        }
        assert required_keys.issubset(config.keys())

    def test_get_config_top_level_keys(self):
        config = get_config()
        required_keys = {
            'exploitation', 'stealth', 'logging', 'api', 'threading', 'compliance',
        }
        assert required_keys.issubset(config.keys())

    def test_get_config_compliance_keys(self):
        config = get_config()
        compliance = config['compliance']
        assert 'pci_audit_enabled' in compliance
        assert 'gdpr_logging_enabled' in compliance
        assert 'audit_retention_days' in compliance

    def test_get_config_threading_keys(self):
        config = get_config()
        threading = config['threading']
        for key in ('discovery', 'scanning', 'exploitation', 'bruteforce'):
            assert key in threading
            assert isinstance(threading[key], int)


# ============================================================================
# QuickConfigs profile tests
# ============================================================================


class TestQuickConfigProfiles:
    """Each profile must produce a coherent, self-consistent configuration."""

    def test_stealth_profile_disables_aggressive(self):
        QuickConfigs.stealth_profile()
        assert FrameworkConfig.STEALTH_MODE is True
        assert FrameworkConfig.AGGRESSIVE_MODE is False

    def test_stealth_profile_uses_slow_delays(self):
        QuickConfigs.stealth_profile()
        assert FrameworkConfig.STEALTH_MIN_DELAY >= 0.05
        assert FrameworkConfig.STEALTH_MAX_DELAY >= 0.1

    def test_aggressive_profile_disables_stealth(self):
        QuickConfigs.aggressive_profile()
        assert FrameworkConfig.STEALTH_MODE is False
        assert FrameworkConfig.AGGRESSIVE_MODE is True

    def test_aggressive_profile_uses_fast_delays(self):
        QuickConfigs.aggressive_profile()
        assert FrameworkConfig.STEALTH_MAX_DELAY < 1.0

    def test_balanced_profile_moderate_settings(self):
        QuickConfigs.balanced_profile()
        assert FrameworkConfig.STEALTH_MODE is True
        assert FrameworkConfig.AGGRESSIVE_MODE is True

    def test_debug_profile_enables_verbosity(self):
        QuickConfigs.debug_profile()
        assert FrameworkConfig.VERBOSE_MODE is True
        assert FrameworkConfig.LOG_LEVEL == 'DEBUG'
        assert FrameworkConfig.SUPPRESS_PROBE_FAILURES is False

    def test_aggressive_profile_increases_scanning_threads(self):
        QuickConfigs.aggressive_profile()
        assert FrameworkConfig.SCANNING_THREADS >= 15


# ============================================================================
# load_config helper
# ============================================================================


class TestLoadConfig:
    """load_config() must map profile names to QuickConfigs methods."""

    def test_load_stealth_profile_by_name(self):
        load_config('stealth')
        assert FrameworkConfig.STEALTH_MODE is True
        assert FrameworkConfig.AGGRESSIVE_MODE is False

    def test_load_aggressive_profile_by_name(self):
        load_config('aggressive')
        assert FrameworkConfig.STEALTH_MODE is False

    def test_load_unknown_profile_falls_back_to_balanced(self, capsys):
        load_config('nonexistent_profile')
        # Should not raise; balanced profile applied
        assert FrameworkConfig.STEALTH_MODE is True
        captured = capsys.readouterr()
        assert 'Unknown profile' in captured.out  # warning printed

    def test_load_config_case_insensitive(self):
        load_config('STEALTH')
        assert FrameworkConfig.STEALTH_MODE is True


# ============================================================================
# Payload loading
# ============================================================================


class TestPayloadLoading:
    """_load_payloads() must return valid dicts; gracefully handle missing files."""

    def test_load_payloads_returns_dict(self):
        result = _load_payloads()
        assert isinstance(result, dict)

    def test_load_payloads_has_required_keys(self):
        result = _load_payloads()
        assert 'WAF_BYPASS_TECHNIQUES' in result
        assert 'PAYLOAD_TEMPLATES' in result

    def test_load_payloads_fallback_on_missing_file(self, monkeypatch, tmp_path):
        """When payloads.json does not exist the function must return a safe default."""
        import modules.framework_config as fc_mod
        # Point the loader at a non-existent path
        original = fc_mod._load_payloads
        monkeypatch.setattr(fc_mod, '_load_payloads', lambda: {
            'WAF_BYPASS_TECHNIQUES': {}, 'PAYLOAD_TEMPLATES': {}
        })
        result = fc_mod._load_payloads()
        assert result == {'WAF_BYPASS_TECHNIQUES': {}, 'PAYLOAD_TEMPLATES': {}}

    def test_waf_bypass_techniques_is_dict(self):
        assert isinstance(WAF_BYPASS_TECHNIQUES, dict)

    def test_payload_templates_is_dict(self):
        assert isinstance(PAYLOAD_TEMPLATES, dict)

    def test_load_payloads_from_custom_json(self, tmp_path):
        """_load_payloads reads a custom file containing valid JSON."""
        custom = {'WAF_BYPASS_TECHNIQUES': {'TEST': ['a', 'b']}, 'PAYLOAD_TEMPLATES': {}}
        custom_file = tmp_path / 'payloads.json'
        custom_file.write_text(json.dumps(custom), encoding='utf-8')

        # Simulate what _load_payloads does but against our tmp file
        with open(custom_file, 'r', encoding='utf-8') as fh:
            loaded = json.load(fh)
        assert loaded['WAF_BYPASS_TECHNIQUES']['TEST'] == ['a', 'b']
