"""
Aethelred Framework Configuration
==================================
Central, environment-aware configuration for all modules.
All values can be overridden via a `.env` file or real environment variables.

Priority chain: environment variable → .env file → coded default.
"""

import os
import json
from typing import Any, Dict

from dotenv import load_dotenv

# Load .env file from the project root (if present).
# override=True ensures .env values take precedence over stale system env vars
# (e.g. a leftover GEMINI_API_KEY that the user no longer wants to use).
load_dotenv(override=True)

# ============================================================================
# MAIN CONFIGURATION CLASS
# ============================================================================


class FrameworkConfig:
    """Central configuration for the Aethelred framework.

    All class attributes are derived from environment variables so that
    different deployment environments (dev, staging, production) can be
    configured without touching source code.
    """

    # -- Operational Mode ----------------------------------------------------
    STEALTH_MODE: bool = os.getenv('AETHELRED_STEALTH', 'True').lower() == 'true'
    VERBOSE_MODE: bool = os.getenv('AETHELRED_VERBOSE', 'False').lower() == 'true'
    AGGRESSIVE_MODE: bool = os.getenv('AETHELRED_AGGRESSIVE', 'True').lower() == 'true'
    SAFE_MODE: bool = os.getenv('AETHELRED_SAFE_MODE', 'True').lower() == 'true'

    # -- API Security --------------------------------------------------------
    #: When True (default), every API request must carry a valid X-API-KEY header.
    REQUIRE_API_KEY: bool = os.getenv('REQUIRE_API_KEY', 'True').lower() == 'true'
    #: Maximum number of scan targets accepted in a single /scan POST request.
    MAX_TARGETS_PER_REQUEST: int = int(os.getenv('MAX_TARGETS_PER_REQUEST', '10'))

    # -- WAF Detection & Bypass ---------------------------------------------
    WAF_BYPASS_ENABLED: bool = os.getenv('WAF_BYPASS_ENABLED', 'True').lower() == 'true'
    WAF_SIGNATURE_CHECK: bool = os.getenv('WAF_SIGNATURE_CHECK', 'True').lower() == 'true'
    WAF_ADAPTIVE_BYPASS: bool = os.getenv('WAF_ADAPTIVE_BYPASS', 'True').lower() == 'true'

    # -- HTTP Configuration -------------------------------------------------
    HTTP_TIMEOUT: int = int(os.getenv('HTTP_TIMEOUT', '10'))
    HTTP_MAX_RETRIES: int = int(os.getenv('HTTP_MAX_RETRIES', '3'))
    HTTP_RETRY_DELAY: float = float(os.getenv('HTTP_RETRY_DELAY', '1.0'))
    HTTP_MAX_CONNECTIONS: int = int(os.getenv('HTTP_MAX_CONNECTIONS', '10'))
    MAX_HOST_FAILURES: int = int(os.getenv('MAX_HOST_FAILURES', '15'))

    # -- Port Scanning ------------------------------------------------------
    PORT_SCAN_TIMEOUT: int = int(os.getenv('PORT_SCAN_TIMEOUT', '5'))
    PORT_SCAN_RETRIES: int = int(os.getenv('PORT_SCAN_RETRIES', '2'))

    # -- Stealth / Timing ---------------------------------------------------
    STEALTH_MIN_DELAY: float = float(os.getenv('STEALTH_MIN_DELAY', '0.5'))
    STEALTH_MAX_DELAY: float = float(os.getenv('STEALTH_MAX_DELAY', '3.0'))
    RANDOMIZE_USER_AGENTS: bool = os.getenv('RANDOMIZE_USER_AGENTS', 'True').lower() == 'true'
    ADD_NOISE_HEADERS: bool = os.getenv('ADD_NOISE_HEADERS', 'True').lower() == 'true'
    USE_PROXIES: bool = os.getenv('USE_PROXIES', 'False').lower() == 'true'
    PROXIES: list = json.loads(os.getenv('PROXIES', '[]'))

    # -- Exploitation -------------------------------------------------------
    MAX_COLUMN_COUNT: int = int(os.getenv('MAX_COLUMN_COUNT', '15'))
    BLIND_INJECTION_THRESHOLD: float = float(os.getenv('BLIND_INJECTION_THRESHOLD', '4.0'))
    BOOLEAN_INJECTION_THRESHOLD: int = int(os.getenv('BOOLEAN_INJECTION_THRESHOLD', '100'))
    DEFAULT_WORDLIST: str = os.getenv('DEFAULT_WORDLIST', 'common_files.txt')

    # -- Logging & Audit ----------------------------------------------------
    LOG_FILE: str = os.getenv('LOG_FILE', 'aethelred.log')
    AUDIT_LOG_FILE: str = os.getenv('AUDIT_LOG_FILE', 'athena_audit.log')
    LOG_LEVEL: str = os.getenv(
        'LOG_LEVEL',
        'WARNING' if os.getenv('AETHELRED_STEALTH', 'True').lower() == 'true' else 'INFO',
    )
    SUPPRESS_PROBE_FAILURES: bool = os.getenv('SUPPRESS_PROBE_FAILURES', 'True').lower() == 'true'
    COLORED_OUTPUT: bool = os.getenv('COLORED_OUTPUT', 'True').lower() == 'true'

    # -- Compliance ---------------------------------------------------------
    #: Enable PCI DSS Requirement 10 audit event logging.
    PCI_AUDIT_ENABLED: bool = os.getenv('PCI_AUDIT_ENABLED', 'True').lower() == 'true'
    #: Enable GDPR Article 6 data-access and consent logging.
    GDPR_LOGGING_ENABLED: bool = os.getenv('GDPR_LOGGING_ENABLED', 'True').lower() == 'true'
    #: Number of days to retain rotating audit log files.
    AUDIT_LOG_RETENTION_DAYS: int = int(os.getenv('AUDIT_LOG_RETENTION_DAYS', '90'))

    # -- Reporting ----------------------------------------------------------
    REPORT_CONFIRMED_ONLY: bool = os.getenv('REPORT_CONFIRMED_ONLY', 'False').lower() == 'true'
    REPORT_CONFIRMED_AND_POSSIBLE: bool = (
        os.getenv('REPORT_CONFIRMED_AND_POSSIBLE', 'True').lower() == 'true'
    )
    REPORT_ALL_RESULTS: bool = os.getenv('REPORT_ALL_RESULTS', 'False').lower() == 'true'

    # -- Concurrency --------------------------------------------------------
    DISCOVERY_THREADS: int = int(os.getenv('DISCOVERY_THREADS', '5'))
    SCANNING_THREADS: int = int(os.getenv('SCANNING_THREADS', '10'))
    EXPLOITATION_THREADS: int = int(os.getenv('EXPLOITATION_THREADS', '5'))
    BRUTEFORCE_THREADS: int = int(os.getenv('BRUTEFORCE_THREADS', '3'))

    # -- Rate Limiting (Flask API) ------------------------------------------
    RATE_LIMIT_DEFAULT: str = os.getenv('RATE_LIMIT_DEFAULT', '200 per day')
    RATE_LIMIT_SCAN: str = os.getenv('RATE_LIMIT_SCAN', '5 per minute')

    # -- Session Management -------------------------------------------------
    SESSION_TIMEOUT: int = int(os.getenv('SESSION_TIMEOUT', '300'))
    MAINTAIN_SESSIONS: bool = os.getenv('MAINTAIN_SESSIONS', 'True').lower() == 'true'
    CACHE_EXPLOITS: bool = os.getenv('CACHE_EXPLOITS', 'True').lower() == 'true'

    # -- Metrics Exposure ---------------------------------------------------
    #: When True, the /metrics endpoint also requires a valid API key.
    METRICS_AUTH_REQUIRED: bool = os.getenv('METRICS_AUTH_REQUIRED', 'False').lower() == 'true'

    # -----------------------------------------------------------------------
    # Config accessors
    # -----------------------------------------------------------------------

    @classmethod
    def get_exploitation_config(cls) -> Dict[str, Any]:
        """Return a dict consumed by :class:`ExploitationModule`."""
        return {
            'aggressive_mode': cls.AGGRESSIVE_MODE,
            'waf_bypass': cls.WAF_BYPASS_ENABLED,
            'stealth_mode': cls.STEALTH_MODE,
            'max_retries': cls.HTTP_MAX_RETRIES,
            'timeout': cls.HTTP_TIMEOUT,
            'session_management': cls.MAINTAIN_SESSIONS,
            'exploit_chaining': True,
            'safe_mode': cls.SAFE_MODE,
        }

    @classmethod
    def get_stealth_config(cls) -> Dict[str, Any]:
        """Return a dict consumed by the stealth engine."""
        return {
            'stealth_mode': cls.STEALTH_MODE,
            'min_delay': cls.STEALTH_MIN_DELAY,
            'max_delay': cls.STEALTH_MAX_DELAY,
            'randomize_ua': cls.RANDOMIZE_USER_AGENTS,
            'noise_headers': cls.ADD_NOISE_HEADERS,
            'waf_detect': cls.WAF_SIGNATURE_CHECK,
            'waf_bypass': cls.WAF_BYPASS_ENABLED,
        }

    @classmethod
    def get_logging_config(cls) -> Dict[str, Any]:
        """Return a dict describing the logging subsystem configuration."""
        return {
            'log_file': cls.LOG_FILE,
            'audit_log_file': cls.AUDIT_LOG_FILE,
            'log_level': cls.LOG_LEVEL,
            'stealth_mode': cls.STEALTH_MODE,
            'suppress_probe_failures': cls.SUPPRESS_PROBE_FAILURES,
            'colored_output': cls.COLORED_OUTPUT,
            'pci_audit_enabled': cls.PCI_AUDIT_ENABLED,
            'gdpr_logging_enabled': cls.GDPR_LOGGING_ENABLED,
            'audit_retention_days': cls.AUDIT_LOG_RETENTION_DAYS,
        }

    @classmethod
    def get_api_config(cls) -> Dict[str, Any]:
        """Return public-safe API configuration (no secrets)."""
        return {
            'require_api_key': cls.REQUIRE_API_KEY,
            'max_targets_per_request': cls.MAX_TARGETS_PER_REQUEST,
            'rate_limit_scan': cls.RATE_LIMIT_SCAN,
            'rate_limit_default': cls.RATE_LIMIT_DEFAULT,
            'metrics_auth_required': cls.METRICS_AUTH_REQUIRED,
        }


# ============================================================================
# PRESET PROFILES
# ============================================================================


class QuickConfigs:
    """Preset operational profiles that mutate :class:`FrameworkConfig` in-place."""

    @staticmethod
    def stealth_profile() -> None:
        """Maximum stealth – evasive, randomized delays, moderate concurrency."""
        FrameworkConfig.STEALTH_MODE = True
        FrameworkConfig.AGGRESSIVE_MODE = False
        FrameworkConfig.STEALTH_MIN_DELAY = 0.2
        FrameworkConfig.STEALTH_MAX_DELAY = 0.8
        FrameworkConfig.HTTP_TIMEOUT = 10
        FrameworkConfig.HTTP_MAX_RETRIES = 2
        FrameworkConfig.HTTP_MAX_CONNECTIONS = 10
        FrameworkConfig.SCANNING_THREADS = 10
        FrameworkConfig.EXPLOITATION_THREADS = 5
        FrameworkConfig.BRUTEFORCE_THREADS = 3
        FrameworkConfig.VERBOSE_MODE = False

    @staticmethod
    def balanced_profile() -> None:
        """Balanced – moderate speed with reasonable stealth."""
        FrameworkConfig.STEALTH_MODE = True
        FrameworkConfig.AGGRESSIVE_MODE = True
        FrameworkConfig.STEALTH_MIN_DELAY = 0.5
        FrameworkConfig.STEALTH_MAX_DELAY = 2.0
        FrameworkConfig.HTTP_TIMEOUT = 10
        FrameworkConfig.HTTP_MAX_CONNECTIONS = 10
        FrameworkConfig.SCANNING_THREADS = 10

    @staticmethod
    def aggressive_profile() -> None:
        """Aggressive – fast, comprehensive, likely to trigger IDS/WAF alerts."""
        FrameworkConfig.STEALTH_MODE = False
        FrameworkConfig.AGGRESSIVE_MODE = True
        FrameworkConfig.STEALTH_MIN_DELAY = 0.05
        FrameworkConfig.STEALTH_MAX_DELAY = 0.3
        FrameworkConfig.HTTP_TIMEOUT = 5
        FrameworkConfig.HTTP_MAX_CONNECTIONS = 25
        FrameworkConfig.SCANNING_THREADS = 20
        FrameworkConfig.VERBOSE_MODE = True

    @staticmethod
    def debug_profile() -> None:
        """Debug – maximum verbosity for troubleshooting and development."""
        FrameworkConfig.STEALTH_MODE = False
        FrameworkConfig.VERBOSE_MODE = True
        FrameworkConfig.LOG_LEVEL = 'DEBUG'
        FrameworkConfig.SUPPRESS_PROBE_FAILURES = False
        FrameworkConfig.COLORED_OUTPUT = True
        FrameworkConfig.STEALTH_MIN_DELAY = 0.0
        FrameworkConfig.STEALTH_MAX_DELAY = 0.1


# ============================================================================
# PAYLOAD LOADING
# ============================================================================


def _load_payloads() -> Dict[str, Any]:
    """Load WAF bypass techniques and payload templates from ``config/payloads.json``.

    Falls back to a safe empty structure if the file is missing or malformed
    so that the framework always starts cleanly.
    """
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'config',
        'payloads.json',
    )
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as fh:
                return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f'[!] Warning: could not load payloads.json: {exc}')

    return {'WAF_BYPASS_TECHNIQUES': {}, 'PAYLOAD_TEMPLATES': {}}


_PAYLOAD_DATA = _load_payloads()
WAF_BYPASS_TECHNIQUES: Dict[str, Any] = _PAYLOAD_DATA.get('WAF_BYPASS_TECHNIQUES', {})
PAYLOAD_TEMPLATES: Dict[str, Any] = _PAYLOAD_DATA.get('PAYLOAD_TEMPLATES', {})


# ============================================================================
# HELPERS
# ============================================================================


def load_config(profile: str = '') -> None:
    """Apply a named preset profile.

    If *profile* is empty the value of the ``AETHELRED_PROFILE`` environment
    variable is used, defaulting to ``'balanced'``.

    Also seeds any variables defined in the project ``.env`` file into the
    process environment (as a fallback, never overwriting an existing real
    env var), so Athena's dotenv-style configuration actually takes effect.
    """
    if not profile:
        profile = os.getenv('AETHELRED_PROFILE', 'balanced')

    profiles = {
        'stealth': QuickConfigs.stealth_profile,
        'balanced': QuickConfigs.balanced_profile,
        'aggressive': QuickConfigs.aggressive_profile,
        'debug': QuickConfigs.debug_profile,
    }

    handler = profiles.get(profile.lower())
    if handler:
        handler()
    else:
        # Unknown profile – fall back to balanced and warn rather than crashing
        print(f"[!] Unknown profile '{profile}', defaulting to 'balanced'")
        QuickConfigs.balanced_profile()


def get_config() -> Dict[str, Any]:
    """Return the full runtime configuration as a serialisable dictionary."""
    return {
        'exploitation': FrameworkConfig.get_exploitation_config(),
        'stealth': FrameworkConfig.get_stealth_config(),
        'logging': FrameworkConfig.get_logging_config(),
        'api': FrameworkConfig.get_api_config(),
        'threading': {
            'discovery': FrameworkConfig.DISCOVERY_THREADS,
            'scanning': FrameworkConfig.SCANNING_THREADS,
            'exploitation': FrameworkConfig.EXPLOITATION_THREADS,
            'bruteforce': FrameworkConfig.BRUTEFORCE_THREADS,
        },
        'compliance': {
            'pci_audit_enabled': FrameworkConfig.PCI_AUDIT_ENABLED,
            'gdpr_logging_enabled': FrameworkConfig.GDPR_LOGGING_ENABLED,
            'audit_retention_days': FrameworkConfig.AUDIT_LOG_RETENTION_DAYS,
        },
    }


# Apply the default profile when this module is first imported
load_config()
