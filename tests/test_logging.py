"""
tests/test_logging.py – Unit tests for logging_config and PayloadManager
=========================================================================
Covers:
  AuditLogger:
    * Writes valid JSON entries to the log file
    * log_action() fields (user, action, target, status, details)
    * log_data_access() – GDPR Art.6 fields (legal_basis, data_type)
    * log_pci_event() – PCI DSS Req 10 fields (card_system, actor, outcome)
    * log_scope_change() – old_scope, new_scope, justification
    * log_consent() – granted boolean recorded correctly
    * Does NOT propagate to root logger
    * Multiple events write multiple lines

  SilentProbeFilter:
    * Suppresses expected probe-failure patterns at ERROR level
    * Allows genuine exceptions through (traceback keyword)
    * Passes non-suppressed messages at INFO level

  ColoredFormatter:
    * Injects ANSI escape codes into levelname

  PayloadManager:
    * get_payloads returns non-empty list for known categories
    * register_payload adds to custom layer
    * load_custom_payloads merges correctly
    * load_custom_payloads raises FileNotFoundError on missing file
    * load_custom_payloads raises ValueError on invalid JSON
    * export_effective_payloads includes built_in and custom keys
    * get_waf_bypass returns list
    * list_categories returns sorted list
    * get_all_profiles returns available profiles
"""

import json
import logging
import os
import sys
import tempfile
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.logging_config import (
    AuditLogger,
    ColoredFormatter,
    SilentProbeFilter,
    setup_logging,
)
from modules.payload_manager import PayloadManager


# ---------------------------------------------------------------------------
# AuditLogger tests
# ---------------------------------------------------------------------------


class TestAuditLogger:
    """AuditLogger must write well-formed JSON compliance events."""

    @pytest.fixture()
    def audit(self, tmp_path):
        log_file = str(tmp_path / 'audit_test.log')
        a = AuditLogger(audit_file=log_file)
        yield a, log_file
        # Teardown: close file handlers
        for h in a.logger.handlers[:]:
            h.close()
            a.logger.removeHandler(h)

    def _read_last_line(self, path: str) -> dict:
        lines = Path(path).read_text(encoding='utf-8').strip().splitlines()
        assert lines, f'Audit log is empty: {path}'
        return json.loads(lines[-1])

    def test_log_action_writes_valid_json(self, audit):
        a, log_file = audit
        a.log_action('tester', 'SCAN_START', 'example.com', 'INITIATED', 'unit test')
        entry = self._read_last_line(log_file)
        assert isinstance(entry, dict)

    def test_log_action_contains_required_fields(self, audit):
        a, log_file = audit
        a.log_action('alice', 'API_AUTH_FAILED', '/scan', 'DENIED', 'wrong key')
        entry = self._read_last_line(log_file)
        assert entry.get('user') == 'alice'
        assert entry.get('action') == 'API_AUTH_FAILED'
        assert entry.get('target') == '/scan'
        assert entry.get('status') == 'DENIED'
        assert 'wrong key' in entry.get('details', '')

    def test_log_action_contains_timestamp(self, audit):
        a, log_file = audit
        a.log_action('sys', 'TEST', 'target', 'OK')
        entry = self._read_last_line(log_file)
        assert 'timestamp' in entry
        # ISO-8601 timestamps contain a 'T'
        assert 'T' in entry['timestamp']

    def test_log_data_access_gdpr_fields(self, audit):
        a, log_file = audit
        a.log_data_access(
            user='scanner',
            data_type='PII',
            target='users_table',
            legal_basis='legitimate_interests',
            purpose='security assessment',
        )
        entry = self._read_last_line(log_file)
        assert entry.get('event_type') == 'GDPR_DATA_ACCESS'
        assert entry.get('legal_basis') == 'legitimate_interests'
        assert entry.get('data_type') == 'PII'
        assert entry.get('purpose') == 'security assessment'

    def test_log_pci_event_pci_fields(self, audit):
        a, log_file = audit
        a.log_pci_event(
            actor='red-team',
            card_system='payment_gateway',
            action='READ',
            outcome='SUCCESS',
            details='accessed cardholder record',
        )
        entry = self._read_last_line(log_file)
        assert entry.get('event_type') == 'PCI_DSS_REQ10'
        assert entry.get('card_system') == 'payment_gateway'
        assert entry.get('action') == 'READ'
        assert entry.get('outcome') == 'SUCCESS'
        assert entry.get('pci_req') == '10.3'

    def test_log_scope_change_fields(self, audit):
        a, log_file = audit
        a.log_scope_change(
            user='admin',
            old_scope='scan:read',
            new_scope='scan:read scan:write',
            justification='pentest engagement',
        )
        entry = self._read_last_line(log_file)
        assert entry.get('event_type') == 'SCOPE_CHANGE'
        assert entry.get('old_scope') == 'scan:read'
        assert entry.get('new_scope') == 'scan:read scan:write'

    def test_log_consent_granted(self, audit):
        a, log_file = audit
        a.log_consent(
            user='data_subject_1',
            target='vulnerability_scanner',
            scope='scan:read',
            consent_type='explicit',
            granted=True,
        )
        entry = self._read_last_line(log_file)
        assert entry.get('event_type') == 'GDPR_CONSENT'
        assert entry.get('granted') is True
        assert entry.get('consent_type') == 'explicit'

    def test_log_consent_withdrawn(self, audit):
        a, log_file = audit
        a.log_consent(
            user='ds2', target='scanner', scope='full', consent_type='withdrawal', granted=False
        )
        entry = self._read_last_line(log_file)
        assert entry.get('granted') is False

    def test_multiple_events_write_multiple_lines(self, audit):
        a, log_file = audit
        a.log_action('u1', 'ACT1', 't1', 'OK')
        a.log_action('u2', 'ACT2', 't2', 'OK')
        a.log_action('u3', 'ACT3', 't3', 'FAIL')
        lines = [ln for ln in Path(log_file).read_text().strip().splitlines() if ln.strip()]
        assert len(lines) >= 3

    def test_audit_logger_does_not_propagate(self, audit):
        a, _ = audit
        assert a.logger.propagate is False, (
            'Audit logger must not propagate to root logger to prevent filtering'
        )


# ---------------------------------------------------------------------------
# SilentProbeFilter tests
# ---------------------------------------------------------------------------


class TestSilentProbeFilter:
    """SilentProbeFilter must suppress expected network noise at ERROR level."""

    def _make_record(self, message: str, level: int) -> logging.LogRecord:
        record = logging.LogRecord(
            name='test', level=level,
            pathname='', lineno=0,
            msg=message, args=(), exc_info=None,
        )
        return record

    def test_suppresses_connection_refused_at_error(self):
        f = SilentProbeFilter()
        record = self._make_record('connection refused to host', logging.ERROR)
        assert f.filter(record) is False, 'connection refused must be suppressed at ERROR'

    def test_suppresses_timeout_at_error(self):
        f = SilentProbeFilter()
        record = self._make_record('request timeout after 10s', logging.ERROR)
        assert f.filter(record) is False

    def test_allows_genuine_exception_through(self):
        f = SilentProbeFilter()
        record = self._make_record('RuntimeError – exception in module', logging.ERROR)
        assert f.filter(record) is True, 'Records mentioning "exception" must pass through'

    def test_allows_traceback_through(self):
        f = SilentProbeFilter()
        record = self._make_record('AttributeError – traceback follows', logging.ERROR)
        assert f.filter(record) is True

    def test_allows_info_records_unconditionally(self):
        f = SilentProbeFilter()
        record = self._make_record('connection refused', logging.INFO)
        assert f.filter(record) is True, 'INFO-level records must always pass through'

    def test_allows_unrelated_error_messages(self):
        f = SilentProbeFilter()
        record = self._make_record('Unexpected configuration error in reporting module', logging.ERROR)
        assert f.filter(record) is True


# ---------------------------------------------------------------------------
# ColoredFormatter tests
# ---------------------------------------------------------------------------


class TestColoredFormatter:
    """ColoredFormatter must inject ANSI codes into the levelname field."""

    def test_format_injects_ansi_in_levelname(self):
        formatter = ColoredFormatter('[%(levelname)s] %(message)s')
        record = logging.LogRecord(
            name='test', level=logging.WARNING,
            pathname='', lineno=0,
            msg='test message', args=(), exc_info=None,
        )
        formatted = formatter.format(record)
        # ANSI escape starts with ESC (0x1b) or \033
        assert '\033[' in formatted, 'ANSI escape code must appear in formatted output'

    def test_format_contains_original_message(self):
        formatter = ColoredFormatter('%(message)s')
        record = logging.LogRecord(
            name='t', level=logging.ERROR,
            pathname='', lineno=0,
            msg='important message', args=(), exc_info=None,
        )
        formatted = formatter.format(record)
        assert 'important message' in formatted


# ---------------------------------------------------------------------------
# PayloadManager tests
# ---------------------------------------------------------------------------


class TestPayloadManager:
    """PayloadManager must provide correct payload retrieval and management."""

    def test_list_categories_non_empty(self):
        pm = PayloadManager()
        cats = pm.list_categories()
        assert len(cats) > 0

    def test_list_categories_contains_known_types(self):
        pm = PayloadManager()
        cats = pm.list_categories()
        for expected in ('SQL_INJECTION', 'XSS', 'COMMAND_INJECTION'):
            assert expected in cats

    def test_get_payloads_default_profile_non_empty(self):
        pm = PayloadManager()
        payloads = pm.get_payloads('SQL_INJECTION')
        assert len(payloads) > 0

    def test_get_payloads_time_based_profile(self):
        pm = PayloadManager()
        payloads = pm.get_payloads('SQL_INJECTION', profile='time_based')
        assert any('SLEEP' in str(p) or 'sleep' in str(p) for p in payloads)

    def test_get_payloads_includes_aggressive_when_flag_set(self):
        pm = PayloadManager()
        base = pm.get_payloads('SQL_INJECTION', include_aggressive=False)
        aggressive = pm.get_payloads('SQL_INJECTION', include_aggressive=True)
        assert len(aggressive) >= len(base), 'Aggressive flag must add more payloads'

    def test_get_payloads_deduplicates(self):
        pm = PayloadManager()
        payloads = pm.get_payloads('XSS', include_aggressive=True)
        assert len(payloads) == len({repr(p) for p in payloads})

    def test_get_payloads_ssrf_cloud_metadata(self):
        pm = PayloadManager()
        ssrf = pm.get_payloads('SSRF', profile='cloud_metadata')
        aws = [p for p in ssrf if '169.254.169.254' in str(p)]
        assert len(aws) > 0, 'SSRF cloud_metadata must include AWS metadata URL'

    def test_register_payload_adds_to_custom(self):
        pm = PayloadManager()
        pm.register_payload('XSS', '<custom-payload>', profile='custom_pentest')
        custom = pm.get_payloads('XSS', profile='custom_pentest')
        assert '<custom-payload>' in custom

    def test_register_payload_metadata_stored(self):
        pm = PayloadManager()
        pm.register_payload('SQL_INJECTION', "' CUSTOM --", metadata={'team': 'red', 'cve': 'N/A'})
        export = pm.export_effective_payloads()
        meta_entries = export['custom_metadata'].get('SQL_INJECTION', [])
        assert len(meta_entries) > 0

    def test_load_custom_payloads_from_file(self, tmp_path):
        custom_data = {
            'SQL_INJECTION': {
                'custom': ["' LOADED FROM FILE --"]
            }
        }
        custom_file = tmp_path / 'custom.json'
        custom_file.write_text(json.dumps(custom_data), encoding='utf-8')

        pm = PayloadManager()
        count = pm.load_custom_payloads(str(custom_file))
        assert count == 1
        payloads = pm.get_payloads('SQL_INJECTION', profile='custom')
        assert "' LOADED FROM FILE --" in payloads

    def test_load_custom_payloads_flat_list(self, tmp_path):
        custom_data = {'XSS': ["<flat-xss-payload>"]}
        custom_file = tmp_path / 'flat.json'
        custom_file.write_text(json.dumps(custom_data), encoding='utf-8')

        pm = PayloadManager()
        count = pm.load_custom_payloads(str(custom_file))
        assert count == 1

    def test_load_custom_payloads_raises_on_missing_file(self):
        pm = PayloadManager()
        with pytest.raises(FileNotFoundError):
            pm.load_custom_payloads('/no/such/file.json')

    def test_load_custom_payloads_raises_on_invalid_json(self, tmp_path):
        bad_file = tmp_path / 'bad.json'
        bad_file.write_text('{ not valid json ]', encoding='utf-8')
        pm = PayloadManager()
        with pytest.raises(ValueError):
            pm.load_custom_payloads(str(bad_file))

    def test_export_effective_payloads_structure(self):
        pm = PayloadManager()
        export = pm.export_effective_payloads()
        assert 'built_in' in export
        assert 'custom' in export
        assert 'categories' in export
        assert 'waf_bypass_techniques' in export

    def test_get_waf_bypass_returns_list(self):
        pm = PayloadManager()
        result = pm.get_waf_bypass('SQL_INJECTION')
        assert isinstance(result, list)

    def test_get_waf_bypass_unknown_type_returns_empty_list(self):
        pm = PayloadManager()
        result = pm.get_waf_bypass('NONEXISTENT_TYPE')
        assert result == []

    def test_get_all_profiles_returns_sorted_list(self):
        pm = PayloadManager()
        profiles = pm.get_all_profiles('SQL_INJECTION')
        assert isinstance(profiles, list)
        assert profiles == sorted(profiles)
        assert 'default' in profiles
