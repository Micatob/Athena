"""
Logging Configuration – Athena Security Suite
=============================================
Provides:
  * ``setup_logging()``    – configure the root logger with file + console handlers
  * ``AuditLogger``        – structured GDPR/PCI compliance audit trail
  * ``SilentProbeFilter``  – suppress expected network noise
  * ``ColoredFormatter``   – ANSI-coloured console output

GDPR & PCI DSS compliance methods on AuditLogger:
  * ``log_action``        – general security-relevant event
  * ``log_operation``     – structured security-operation event (full schema)
  * ``log_data_access``   – GDPR Art. 6 lawful basis record
  * ``log_pci_event``     – PCI DSS Req 10 cardholder system event
  * ``log_scope_change``  – authorisation scope mutation record
  * ``log_consent``       – GDPR consent grant / withdrawal record

Structured operation schema (``log_operation``), one JSON line per event:
  operator / engagement_id / target / module / action / timestamp /
  result / authorization_decision / scope_decision / evidence_ref / details

Every security-relevant action should be auditable: modules that carry out
sensitive work emit these events through the ``audit_operation`` helper,
which falls back to ``log_action`` for audit backends that predate the
structured schema.
"""

import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ============================================================================
# FILTERS
# ============================================================================


class SilentProbeFilter(logging.Filter):
    """Suppress routine network-probe noise while keeping genuine errors visible.

    Log records below ERROR level pass through unconditionally.  ERROR and
    higher records are suppressed when their message matches one of the
    known-benign patterns, regardless of 'exception'/'traceback' keywords
    (aiohttp frequently wraps routine DNS/connection errors that way).
    """

    SUPPRESSED_PATTERNS = frozenset([
        'probe failed',
        'connection timeout',
        'could not connect',
        'connection refused',
        'service not found',
        'port closed',
        'no response',
        'unreachable',
        'timeout',
        '503 service unavailable',
        '404 not found',
        'request timeout',
        'failed to resolve',
        'nameresolution',
        'getaddrinfo failed',
        'gaierror',
        'econnrefused',
        'ehostunreach',
        'enetunreach',
        'cannot connect to host',
        'clientoserror',
    ])

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage().lower()
        if record.levelno >= logging.ERROR:
            for pattern in self.SUPPRESSED_PATTERNS:
                if pattern in message:
                    return False
            if 'exception' in message or 'traceback' in message:
                return True
            return True
        return True


# ============================================================================
# FORMATTERS
# ============================================================================


class ColoredFormatter(logging.Formatter):
    """ANSI-coloured log records for the console handler."""

    _COLORS: Dict[str, str] = {
        'DEBUG':    '\033[36m',    # Cyan
        'INFO':     '\033[32m',    # Green
        'WARNING':  '\033[33m',    # Yellow
        'ERROR':    '\033[31m',    # Red
        'CRITICAL': '\033[35m',    # Magenta
        'RESET':    '\033[0m',
    }

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        color = self._COLORS.get(record.levelname, self._COLORS['RESET'])
        reset = self._COLORS['RESET']
        record = logging.makeLogRecord(record.__dict__)
        record.levelname = f'{color}{record.levelname}{reset}'
        return super().format(record)


class _JSONLineFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object (JSON-L format)."""

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        entry: Dict[str, Any] = {
            'timestamp': datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'process': record.process,
            'thread': record.thread,
            'message': record.getMessage(),
        }
        if record.exc_info:
            entry['exc_info'] = self.formatException(record.exc_info)
        if hasattr(record, 'extra_data') and record.extra_data:
            entry.update(record.extra_data)
        return json.dumps(entry, default=str)


# ============================================================================
# SETUP
# ============================================================================


def setup_logging(log_file: str = 'athena.log', stealth_mode: bool = True) -> None:
    """Configure the root logger with file, console, and structured JSON-L handlers.

    Args:
        log_file:     Path to the primary plain-text rotating log file.
        stealth_mode: When ``True`` the console handler is restricted to WARNING+
                      and non-critical probe noise is filtered out.
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    probe_filter = SilentProbeFilter()

    # -- Plain-text rotating file handler (always DEBUG level) ---------------
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB per file
        backupCount=5,
        encoding='utf-8',
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.addFilter(probe_filter)
    file_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] [%(name)s] [%(levelname)s] %(funcName)s:%(lineno)d – %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    ))
    root.addHandler(file_handler)

    # -- Structured JSON-L handler (always DEBUG level) ---------------------
    jsonl_path = log_file.replace('.log', '_structured.jsonl')
    jsonl_handler = logging.handlers.RotatingFileHandler(
        jsonl_path,
        maxBytes=20 * 1024 * 1024,  # 20 MB per file
        backupCount=10,
        encoding='utf-8',
    )
    jsonl_handler.setLevel(logging.DEBUG)
    jsonl_handler.addFilter(probe_filter)
    jsonl_handler.setFormatter(_JSONLineFormatter())
    root.addHandler(jsonl_handler)

    # -- Console handler (stderr) -------------------------------------------
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING if stealth_mode else logging.INFO)
    console_handler.addFilter(probe_filter)
    console_handler.setFormatter(ColoredFormatter(
        '[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    ))
    root.addHandler(console_handler)

    # -- Module-specific verbosity adjustments ------------------------------
    logging.getLogger('athena.stealth').setLevel(
        logging.WARNING if stealth_mode else logging.DEBUG
    )
    logging.getLogger('athena.exploitation').setLevel(
        logging.WARNING if stealth_mode else logging.DEBUG
    )
    logging.getLogger('athena.discovery').setLevel(
        logging.WARNING if stealth_mode else logging.INFO
    )

    # Suppress verbose third-party noise
    for noisy_lib in ('aiohttp', 'aiohttp.connector', 'urllib3',
                      'charset_normalizer', 'asyncio', 'werkzeug'):
        logging.getLogger(noisy_lib).setLevel(
            logging.ERROR if stealth_mode else logging.WARNING
        )

    # Attach filter directly to the asyncio logger so it suppresses DNS probe
    # noise even when no handlers are configured on the root logger (e.g.
    # during test runs where setup_logging() is not called).
    logging.getLogger('asyncio').addFilter(probe_filter)


# ============================================================================
# AUDIT LOGGER – GDPR / PCI COMPLIANCE
# ============================================================================


class AuditLogger:
    """Structured compliance audit trail for GDPR and PCI DSS requirements.

    All audit events are written as single-line JSON objects to a dedicated
    log file that is rotated daily and retained for ``AUDIT_LOG_RETENTION_DAYS``
    (default 90 days) to satisfy PCI DSS Requirement 10.

    The audit logger deliberately **does not propagate** to the root logger so
    that compliance records are always written to their own isolated file and
    cannot be accidentally filtered or swallowed by the ``SilentProbeFilter``.

    Compliance references
    ---------------------
    * GDPR Art. 5(2) – Accountability / documentation of processing activities
    * GDPR Art. 6    – Lawfulness of processing (log_data_access / log_consent)
    * GDPR Art. 30   – Records of processing activities
    * PCI DSS Req 10 – Log and monitor all access to system components
    """

    def __init__(self, audit_file: str = 'athena_audit.log') -> None:
        self._audit_file = audit_file
        self.logger = logging.getLogger('athena.audit')
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False  # audit events must never be filtered

        # Remove any existing handlers so that each instance controls its own file
        for h in self.logger.handlers[:]:
            h.close()
            self.logger.removeHandler(h)

        # Daily rotation; keep 90 days of history by default
        from modules.framework_config import FrameworkConfig
        retention = getattr(FrameworkConfig, 'AUDIT_LOG_RETENTION_DAYS', 90)

        handler = logging.handlers.TimedRotatingFileHandler(
            audit_file,
            when='midnight',
            backupCount=retention,
            encoding='utf-8',
            utc=True,
        )
        handler.setFormatter(_AuditFormatter())
        self.logger.addHandler(handler)

    # ------------------------------------------------------------------
    # Core event logger
    # ------------------------------------------------------------------

    def _emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Write a compliance event to the audit log."""
        payload['event_type'] = event_type
        payload.setdefault('timestamp', datetime.now(timezone.utc).isoformat())
        self.logger.info(json.dumps(payload, default=str))

    # ------------------------------------------------------------------
    # General security events
    # ------------------------------------------------------------------

    def log_action(
        self,
        user: str,
        action: str,
        target: str,
        status: str,
        details: str = '',
    ) -> None:
        """Record a general security-relevant action.

        Args:
            user:    Identifier of the actor (IP, username, service account).
            action:  Short uppercase action code, e.g. ``SCAN_START``.
            target:  Resource being acted upon (URL, hostname, user ID).
            status:  Outcome code, e.g. ``SUCCESS``, ``DENIED``, ``INITIATED``.
            details: Free-text additional context.
        """
        self._emit('SECURITY_ACTION', {
            'user': user,
            'action': action,
            'target': target,
            'status': status,
            'details': details,
        })

    # ------------------------------------------------------------------
    # Structured security-operation events
    # ------------------------------------------------------------------

    def log_operation(
        self,
        operator: str,
        action: str,
        target: str,
        result: str,
        engagement_id: str = '',
        module: str = 'core',
        authorization_decision: str = '',
        scope_decision: str = '',
        evidence_ref: str = '',
        details: str = '',
    ) -> None:
        """Record a security-relevant operation with the full audit schema.

        One JSON line per event, carrying every field required for
        auditability of security-relevant actions:

        * ``operator`` - human or service operator
        * ``engagement_id`` - engagement the action belongs to
        * ``target`` - resource acted upon
        * ``module`` - emitting module
        * ``action`` - short action code (e.g. ``STAGE_RUN``)
        * ``timestamp`` - ISO-8601 UTC
        * ``result`` - outcome (``COMPLETED`` / ``FAILED`` …)
        * ``authorization_decision`` - authorization gate outcome
        * ``scope_decision`` - scope gate outcome
        * ``evidence_ref`` - evidence / operation / artifact reference
        * ``details`` - free-text context (secret-like values redacted)
        """
        self._emit('SECURITY_ACTION', {
            'operator': operator,
            'engagement_id': engagement_id,
            'target': target,
            'module': module,
            'action': action,
            'result': result,
            'authorization_decision': authorization_decision,
            'scope_decision': scope_decision,
            'evidence_ref': evidence_ref,
            'details': self._redact(details),
        })

    @staticmethod
    def _redact(text: str) -> str:
        """Redact secret-like substrings so trails never store raw secrets.

        Loaded lazily to avoid an import cycle (``findings`` imports this
        module); silently degrades to the raw text when unavailable.
        """
        if not text:
            return text
        try:
            from .findings import SecretRedactor
            return SecretRedactor.redact(text)
        except Exception:
            return text

    def read_trail(self, limit: Optional[int] = None,
                   action: str = '') -> List[Dict[str, Any]]:
        """Read back recorded audit events (newest last).

        Args:
            limit:  only return the most recent ``limit`` events.
            action: optional action-code filter (e.g. ``STAGE_RUN``).

        Returns a list of parsed event dicts; never raises (missing or
        partially-written lines are skipped).
        """
        events: List[Dict[str, Any]] = []
        try:
            with open(self._audit_file, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        continue
        except OSError:
            return []
        if action:
            events = [e for e in events if e.get('action') == action]
        if limit is not None and limit > 0:
            events = events[-limit:]
        return events

    # ------------------------------------------------------------------
    # GDPR compliance events
    # ------------------------------------------------------------------

    def log_data_access(
        self,
        user: str,
        data_type: str,
        target: str,
        legal_basis: str,
        purpose: str = '',
    ) -> None:
        """Record a personal data access event (GDPR Art. 6 / Art. 30).

        Args:
            user:        Actor performing the access.
            data_type:   Category of data accessed (e.g. ``PII``, ``FINANCIAL``).
            target:      Resource or system where data was accessed.
            legal_basis: GDPR Art. 6 basis code – one of:
                         ``consent``, ``contract``, ``legal_obligation``,
                         ``vital_interests``, ``public_task``, ``legitimate_interests``.
            purpose:     Processing purpose description.
        """
        self._emit('GDPR_DATA_ACCESS', {
            'user': user,
            'data_type': data_type,
            'target': target,
            'legal_basis': legal_basis,
            'purpose': purpose,
        })

    def log_consent(
        self,
        user: str,
        target: str,
        scope: str,
        consent_type: str,
        granted: bool,
    ) -> None:
        """Record a GDPR consent grant or withdrawal (GDPR Art. 7).

        Args:
            user:         Data subject or acting user.
            target:       System or service to which consent applies.
            scope:        What the user is consenting to (e.g. ``scan:read``).
            consent_type: ``explicit`` | ``implied`` | ``withdrawal``.
            granted:      ``True`` = granted, ``False`` = withdrawn/revoked.
        """
        self._emit('GDPR_CONSENT', {
            'user': user,
            'target': target,
            'scope': scope,
            'consent_type': consent_type,
            'granted': granted,
        })

    def log_scope_change(
        self,
        user: str,
        old_scope: str,
        new_scope: str,
        justification: str,
    ) -> None:
        """Record a change in authorisation scope (GDPR Art. 5 / PCI DSS Req 10.2.5).

        Args:
            user:          Actor requesting the scope change.
            old_scope:     Previous authorisation scope.
            new_scope:     New authorisation scope.
            justification: Business or technical justification.
        """
        self._emit('SCOPE_CHANGE', {
            'user': user,
            'old_scope': old_scope,
            'new_scope': new_scope,
            'justification': justification,
        })

    # ------------------------------------------------------------------
    # PCI DSS compliance events
    # ------------------------------------------------------------------

    def log_pci_event(
        self,
        actor: str,
        card_system: str,
        action: str,
        outcome: str,
        details: str = '',
    ) -> None:
        """Record a PCI DSS Requirement 10 audit event.

        PCI DSS requires logging all access to cardholder data environments
        (CDE).  This method captures the mandatory fields for Req 10.3:
        individual user identification, type of event, date/time, success or
        failure, origination of event, and identity of affected resource.

        Args:
            actor:       User or process that triggered the event.
            card_system: The cardholder data system or component affected.
            action:      Action performed (e.g. ``READ``, ``MODIFY``, ``DELETE``).
            outcome:     ``SUCCESS`` | ``FAILURE`` | ``ATTEMPT``.
            details:     Additional free-text description.
        """
        self._emit('PCI_DSS_REQ10', {
            'actor': actor,
            'card_system': card_system,
            'action': action,
            'outcome': outcome,
            'details': details,
            'pci_req': '10.3',
        })


class _AuditFormatter(logging.Formatter):
    """Pass-through formatter – audit records are already JSON strings."""

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        return record.getMessage()


# ---------------------------------------------------------------------------
# Module-level singletons used across the framework
# ---------------------------------------------------------------------------

audit_logger = AuditLogger()
logger = logging.getLogger('athena')


# ---------------------------------------------------------------------------
# Structured operation emission helper
# ---------------------------------------------------------------------------


def audit_operation(audit, operator: str, action: str, target: str,
                    result: str, **fields: Any) -> None:
    """Emit a structured security-operation event through any audit backend.

    Backends implementing the structured schema (``log_operation``) get the
    full event; legacy backends (``log_action`` only) get a compatible event
    with the extra fields JSON-encoded into ``details``.  ``None`` audit
    backends are a no-op (audit must never crash the operation).

    Required schema fields:
    ``operator`` / ``engagement_id`` / ``target`` / ``module`` / ``action`` /
    ``timestamp`` / ``result`` / ``authorization_decision`` /
    ``scope_decision`` / ``evidence_ref``.
    """
    if audit is None:
        return
    if hasattr(audit, 'log_operation'):
        audit.log_operation(operator=operator, action=action, target=target,
                            result=result, **fields)
        return
    extra = json.dumps(fields, default=str)
    audit.log_action(user=operator, action=action, target=target,
                     status=result, details=extra)
