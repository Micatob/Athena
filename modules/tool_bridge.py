"""
modules.tool_bridge.py — adapters for external security tools.
================================================================
Athena's own checks are pure Python and need no binaries.  This module adds
*optional* external engines (nuclei, sqlmap, dalfox, wafw00f, httpx;
ffuf is deferred to a later session) behind one contract every adapter
must honour:

  1. **Clean degradation.**  A missing binary is a structured ``unavailable``
     status plus one console line - never a crash, never a traceback.
  2. **Evidence only.**  An adapter returns a finding only when the tool
     produced a concrete match (matched URL, matcher name, extracted value,
     template id).  No matches, no findings - the tool is not a rumour
     generator.
  3. **No shell.**  Commands are argv lists handed to ``create_subprocess_exec``,
     so target strings can never be interpreted as shell syntax.
  4. **Bounded.**  Every run has a wall-clock timeout and a findings cap, and
     the argv is recorded for the report (redacted of any credentials).

Findings produced here use the same ``type``/``url``/``severity``/
``description``/``evidence`` shape as the scanner's own findings, so they flow
through AI adjudication and the exploitation runner untouched.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

#: Nuclei template severity -> Athena severity.
SEVERITY_MAP = {
    'critical': 'CRITICAL',
    'high': 'HIGH',
    'medium': 'MEDIUM',
    'low': 'LOW',
    'info': 'INFO',
}

#: Hard ceiling so one noisy tool cannot flood the report.
MAX_FINDINGS = 200

#: Every severity.  ``info`` is where exposed panels, weak SSH/TLS and
#: missing-header findings live - excluding it would gut the run, and the
#: 2026-10-06 live benchmark (287s, 45 raw matches) says it is affordable.
DEFAULT_SEVERITY = 'critical,high,medium,low,info'

#: Templates we refuse to run from a single target scan: denial-of-service,
#: credential spraying, fuzzing and out-of-band submission.  Athena's own
#: modules own that ground and these turn a 5 minute scan into hours.
EXCLUDE_TAGS = 'dos,bruteforce,fuzz,submitit'

#: Default wall-clock budget for a tool run, seconds.
DEFAULT_TIMEOUT = 900.0

#: Requests/second handed to nuclei unless the caller says otherwise.
DEFAULT_RATE_LIMIT = 150

#: Candidate locations when ``PATH`` lookup fails (Windows ``Program Files``,
#: common Linux/Go install dirs).
_EXTRA_SEARCH_DIRS = (
    os.path.expandvars(r'%LOCALAPPDATA%\Programs\athena\tools'),
    os.path.expandvars(r'%LOCALAPPDATA%\Programs\athena-tools'),
    os.path.expandvars(r'%LOCALAPPDATA%\Programs\nuclei'),
    os.path.expandvars(r'%USERPROFILE%\go\bin'),
    os.path.expandvars(r'%PROGRAMFILES%\nuclei'),
    '/usr/local/bin',
    '/usr/bin',
    os.path.expanduser('~/go/bin'),
    os.path.expanduser('~/.local/bin'),
)

#: Nuclei needs its template repository to mean anything.
NUCLEI_TEMPLATE_DIR = os.path.expandvars(r'%USERPROFILE%\nuclei-templates')


def _templates_present() -> bool:
    """Return True if the nuclei template repository exists and is non-empty.

    Templates live one level down (``http/``, ``cves/``, ...), so only the
    directory listing matters here - not a top-level ``.yaml`` file.
    """
    try:
        with os.scandir(NUCLEI_TEMPLATE_DIR) as entries:
            return next(iter(entries), None) is not None
    except OSError:
        return False


async def _update_templates(binary: str, timeout: float) -> bool:
    """Run ``nuclei -update-templates`` once.  Returns True on success."""
    try:
        result = await _run_process(
            [binary, '-update-templates', '-silent'], timeout)
        return bool(result.get('ok'))
    except Exception:  # pragma: no cover - network/tool failure
        return False


def find_binary(name: str,
                extra_dirs: Sequence[str] = ()) -> Optional[str]:
    """Locate ``name`` on PATH, then in a few conventional install dirs.

    Returns an absolute path or ``None``; never raises.
    """
    try:
        found = shutil.which(name)
    except Exception:  # pragma: no cover - hostile PATH
        found = None
    if found:
        return found
    suffixes = ('.exe', '.cmd', '.bat') if os.name == 'nt' else ('',)
    for directory in tuple(extra_dirs) + _EXTRA_SEARCH_DIRS:
        if not directory:
            continue
        for suffix in suffixes:
            candidate = os.path.join(directory, name + suffix)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            if os.name == 'nt' and suffix and os.path.isfile(candidate):
                return candidate
    return None


def _unavailable(tool: str, binary: str, reason: str) -> Dict[str, Any]:
    return {
        'tool': tool,
        'status': 'unavailable',
        'binary': binary,
        'reason': reason,
        'findings': [],
        'matched': 0,
        'duration_s': 0.0,
        'argv': [],
    }


def count_nuclei_errors(raw: str) -> int:
    """Count connection/template error events in a nuclei JSONL batch.

    A run that printed errors and zero matches did not *disprove* anything -
    it could not reach the host.  Callers need this number so a clean miss
    and an unreachable target never read the same.
    """
    errors = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and (
                str(event.get('type') or '').lower() == 'error'
                or event.get('error')):
            errors += 1
    return errors


def parse_nuclei_jsonl(raw: str, target: str) -> List[Dict[str, Any]]:
    """Turn nuclei JSONL output into Athena findings.

    One finding per matched template/url pair, each carrying the matcher and
    any extracted value as evidence.  Malformed lines are skipped rather than
    aborting the batch.
    """
    findings: List[Dict[str, Any]] = []
    seen = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith('{'):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        # Connection/template failures are not findings - folding them in
        # would invent INFO-level "vulnerabilities" out of timeouts.
        if str(event.get('type') or '').lower() == 'error' or event.get('error'):
            continue

        info = event.get('info') or {}
        if not isinstance(info, dict):
            info = {}
        template = str(event.get('template-id') or event.get('templateID')
                       or 'unknown-template')
        matched = str(event.get('matched-at')
                      or event.get('matched')
                      or event.get('host')
                      or '').strip()
        if not matched:
            continue

        raw_sev = str(info.get('severity') or 'info').lower()
        severity = SEVERITY_MAP.get(raw_sev, 'INFO')
        name = str(info.get('name') or template)
        matcher = str(event.get('matcher-name') or event.get('matcher') or '')
        extracted = event.get('extracted-results') or []
        if isinstance(extracted, str):
            extracted = [extracted]
        kind = str(event.get('type') or event.get('template-id') or '')

        key = (template, matched, matcher)
        if key in seen:
            continue
        seen.add(key)

        evidence = {
            'tool': 'nuclei',
            'template': template,
            'matched_at': matched,
            'matcher': matcher,
            'kind': kind,
            'extracted': [str(e) for e in extracted[:10]],
            'reference': [str(r) for r in (info.get('reference') or [])[:5]],
        }
        curl = event.get('curl-command')
        if curl:
            evidence['curl'] = str(curl)
        description = str(info.get('description') or '').strip()
        if matcher:
            description = (f'{description} (matched: {matcher})'
                           if description else f'Matched: {matcher}')

        findings.append({
            'id': f'nuclei-{template}-{len(findings) + 1}',
            'type': name,
            'url': matched,
            'severity': severity,
            'description': description or f'Nuclei template {template} matched',
            'payload': matcher or '',
            'evidence': evidence,
            'source': 'nuclei',
            'confidence': 'high',
            'verified': False,
        })
        if len(findings) >= MAX_FINDINGS:
            break
    return findings


async def _run_process(argv: Sequence[str], timeout: float
                       ) -> Dict[str, Any]:
    """Run argv with no shell; capture output; enforce a wall-clock timeout."""
    started = asyncio.get_event_loop().time()
    stdout, stderr, returncode = b'', b'', -1
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return {'ok': False, 'stdout': '', 'stderr': str(exc),
                'returncode': None,
                'duration_s': 0.0, 'failed_to_start': True}
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(),
                                                timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:  # pragma: no cover - already dead
            pass
        try:
            await proc.wait()
        except Exception:  # pragma: no cover
            pass
        return {'ok': False, 'stdout': '', 'stderr': 'timeout',
                'returncode': None,
                'duration_s': asyncio.get_event_loop().time() - started,
                'timeout': True}
    returncode = proc.returncode
    return {
        'ok': returncode == 0,
        'stdout': (stdout or b'').decode('utf-8', 'replace'),
        'stderr': (stderr or b'').decode('utf-8', 'replace'),
        'returncode': returncode,
        'duration_s': asyncio.get_event_loop().time() - started,
    }


def _flag_rejected(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(tok in lowered for tok in
               ('unknown flag', 'unknown shorthand',
                'flag provided but not defined', 'invalid argument',
                'incorrect usage'))


async def _execute_nuclei(argv: List[str], timeout: float) -> Dict[str, Any]:
    """Run nuclei once, falling back for builds that lack ``-jsonl``."""
    try:
        result = await _run_process(argv, timeout)

        # Older nuclei builds do not know -jsonl; retry once with -json + file.
        if not result['ok'] and _flag_rejected(str(result.get('stderr', ''))):
            with tempfile.NamedTemporaryFile('w+', suffix='.json',
                                             delete=False) as handle:
                tmp_path = handle.name
            fallback = [a for a in argv if a != '-jsonl']
            fallback += ['-json', '-o', tmp_path]
            result = await _run_process(fallback, timeout)
            raw = ''
            try:
                with open(tmp_path, 'r', encoding='utf-8',
                          errors='replace') as fh:
                    raw = fh.read()
            except OSError:
                raw = ''
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            if result['ok'] and raw and not result['stdout'].strip():
                # -json writes an array; flatten it for the JSONL parser.
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, list):
                    result['stdout'] = '\n'.join(
                        json.dumps(item) for item in payload)
        return result
    except Exception:
        # any unexpected error is surfaced as a failed run
        return {'ok': False, 'stdout': '', 'stderr': 'internal error',
                'returncode': None, 'duration_s': 0.0}


async def run_nuclei(target: str,
                     binary: Optional[str] = None,
                     severity: str = DEFAULT_SEVERITY,
                     timeout: float = DEFAULT_TIMEOUT,
                     rate_limit: Optional[int] = None,
                     extra_args: Sequence[str] = (),
                     enabled: bool = True) -> Dict[str, Any]:
    """Scan ``target`` with nuclei and return a structured run summary.

    Never raises.  ``status`` is one of ``executed`` / ``unavailable`` /
    ``failed``; only ``executed`` can carry findings.

    The run uses ``-u target`` (single base URL) — nuclei's own templates
    handle path discovery.  Recon URL lists are intentionally NOT passed;
    passing many URLs would multiply runtime without proportional value.
    """
    tool = 'nuclei'
    if not enabled:
        return {**_unavailable(tool, '', 'disabled by --no-nuclei'),
                'status': 'disabled'}
    if not target:
        return {**_unavailable(tool, '', 'no target'),
                'status': 'skipped'}

    binary = binary or find_binary(tool)
    if not binary:
        return _unavailable(
            tool, tool,
            'nuclei is not installed - install free from '
            'https://github.com/projectdiscovery/nuclei (no API key needed)')

    # Ensure template repository exists; one-time self-install if missing.
    if not _templates_present():
        logger.info('Nuclei templates missing - running -update-templates')
        if not await _update_templates(binary, min(timeout, 600.0)):
            return _unavailable(
                tool, binary,
                'nuclei templates missing and auto-update failed; '
                'run: nuclei -update-templates')

    # Rate-limited by default: an unthrottled template run trips the target's
    # WAF mid-scan and silently returns zero matches (observed 2026-10-06).
    if rate_limit is None:
        rate_limit = DEFAULT_RATE_LIMIT

    argv: List[str] = [
        binary,
        '-u', target,
        '-severity', severity,
        '-exclude-tags', EXCLUDE_TAGS,
        '-jsonl',
        '-silent',
        '-no-color',
        '-nc',
        '-timeout', '8',
        '-retries', '1',
        '-rate-limit', str(int(rate_limit)),
    ]
    if extra_args:
        argv += list(extra_args)

    result = await _execute_nuclei(argv, timeout)

    if not result['ok']:
        if result.get('timeout'):
            status, reason = 'failed', f'timed out after {timeout:g}s'
        elif result.get('failed_to_start'):
            status, reason = 'failed', str(result.get('stderr'))[:200]
        else:
            status = 'failed'
            reason = (str(result.get('stderr')).strip()
                      or f'exit code {result.get("returncode")}').splitlines()[0:1]
            reason = reason[0] if isinstance(reason, list) else str(reason)
        logger.warning('nuclei run failed: %s', reason)
        return {
            'tool': tool,
            'status': status,
            'binary': binary,
            'reason': reason[:300],
            'findings': [],
            'matched': 0,
            'errors': count_nuclei_errors(str(result.get('stdout') or '')),
            'duration_s': result.get('duration_s', 0.0),
            'argv': ['<binary>', *argv[1:]],
            'returncode': result.get('returncode'),
        }

    stdout = str(result.get('stdout') or '')
    findings = parse_nuclei_jsonl(stdout, target)
    return {
        'tool': tool,
        'status': 'executed',
        'binary': binary,
        'reason': '',
        'findings': findings,
        'matched': len(findings),
        'errors': count_nuclei_errors(stdout),
        'duration_s': result.get('duration_s', 0.0),
        'argv': ['<binary>', *argv[1:]],
        'returncode': result.get('returncode'),
        'severity_filter': severity,
    }


#: Every external engine Athena can call.  ``nuclei`` is the template
#: scanner; ``sqlmap`` confirms SQL injection; ``dalfox`` confirms XSS;
#: ``wafw00f`` fingerprints the WAF (tuning signal, not a vuln);
#: ``httpx`` probes/validates HTTP hosts (recon enrichment, not a vuln).
#: ``ffuf`` is intentionally NOT here yet - it lands in a later session.
SUPPORTED_TOOLS = ('nuclei', 'sqlmap', 'dalfox', 'wafw00f', 'httpx')

#: Where to point the operator when a binary is missing.
TOOL_INSTALL_HINTS = {
    'nuclei': 'install free from https://github.com/projectdiscovery/nuclei (no API key needed)',
    'sqlmap': 'install free from https://github.com/sqlmapproject/sqlmap (Kali: sudo apt install sqlmap)',
    'dalfox': 'install free from https://github.com/hahwul/dalfox (Kali: sudo apt install dalfox)',
    'wafw00f': 'install free from https://github.com/EnableSecurity/wafw00f (Kali: sudo apt install wafw00f)',
    'httpx': 'install free from https://github.com/projectdiscovery/httpx (Kali: sudo apt install httpx-toolkit or go install)',
}

#: Per-tool argv used to ask for a version string.  pd tools answer
#: ``-version``; python tools answer ``--version``; dalfox answers ``-V``.
_VERSION_ARGV = {
    'nuclei': ['-version'],
    'sqlmap': ['--version'],
    'dalfox': ['-V'],
    'wafw00f': ['--version'],
    'httpx': ['-version'],
}

#: Wall-clock budgets per tool (seconds).  sqlmap/dalfox do live
#: injection attempts, so they get minutes; wafw00f/httpx are quick probes.
SQLMAP_TIMEOUT = 300.0
DALFOX_TIMEOUT = 300.0
WAFW00F_TIMEOUT = 60.0
HTTPX_TIMEOUT = 120.0

#: Caps so one noisy engine cannot stall the scan or flood the report.
SQLMAP_MAX_URLS = 3
DALFOX_MAX_URLS = 10
HTTPX_MAX_URLS = 50


def _looks_like_python_httpx(blob: str) -> bool:
    """Detect the Python ``httpx`` package's CLI (name collision).

    The Python package (a hard Athena dependency) installs a binary also
    called ``httpx`` with a ``Usage: httpx [OPTIONS] URL`` CLI - it answers
    ``-version`` with ``No such option`` instead of a version.  Without
    this check Athena would hand ProjectDiscovery flags to the wrong tool.
    """
    lowered = (blob or '').lower()
    return ('options] url' in lowered or 'no such option' in lowered
            or 'usage: httpx' in lowered)


async def _httpx_is_pd(binary: str) -> bool:
    """Return True when ``binary`` is ProjectDiscovery httpx.  Never raises."""
    try:
        result = await _run_process([binary, '-version'], 10.0)
        blob = str(result.get('stdout') or '') + str(result.get('stderr') or '')
        if _looks_like_python_httpx(blob):
            return False
        lowered = blob.lower()
        if 'projectdiscovery' in lowered or 'tech-detect' in lowered:
            return True
        return bool(re.search(r'v?\d+\.\d+\.\d+', blob))
    except Exception:  # pragma: no cover - diagnostics must not explode
        return False


def _find_pd_httpx_candidate() -> Optional[str]:
    """Scan Athena tools dirs for PD httpx without executing anything.

    Why: ``shutil.which('httpx')`` returns Python's httpx CLI when both are
    installed. This returns the first file match in the known tools dirs so
    callers can probe it with ``_httpx_is_pd`` instead of giving up.
    """
    try:
        suffixes = ('.exe', '.cmd', '.bat') if os.name == 'nt' else ('',)
        for directory in _EXTRA_SEARCH_DIRS:
            if not directory:
                continue
            try:
                d = os.path.expandvars(directory)
            except Exception:
                continue
            for suffix in suffixes:
                candidate = os.path.join(d, 'httpx' + suffix)
                try:
                    if os.path.isfile(candidate):
                        return candidate
                except Exception:
                    continue
    except Exception:
        pass
    return None


async def tool_status(tool: str = 'nuclei') -> Dict[str, Any]:
    """Describe an external tool for ``--list-tools`` diagnostics.

    Cheap enough to run on demand: one version call and (for nuclei) a
    template-directory check.  Never raises.
    """
    status: Dict[str, Any] = {
        'tool': tool, 'installed': False, 'binary': None,
        'version': None, 'templates': None,
    }
    try:
        binary = find_binary(tool)
        if not binary:
            return status
        if tool == 'httpx' and binary and not await _httpx_is_pd(binary):
            # PATH hit is Python's httpx CLI (name collision). Scan the
            # Athena tools dirs for the real ProjectDiscovery build before
            # reporting unavailable.
            alt = _find_pd_httpx_candidate()
            if alt:
                binary = alt
            else:
                status['binary'] = binary
                status['note'] = ('found httpx is the Python httpx package, not '
                                  'ProjectDiscovery httpx')
                return status
        if tool == 'httpx' and not await _httpx_is_pd(binary):
            status['binary'] = binary
            status['note'] = ('found httpx is the Python httpx package, not '
                              'ProjectDiscovery httpx')
            return status
        status['installed'] = True
        status['binary'] = binary
        version_flags = _VERSION_ARGV.get(tool, ['-version'])
        result = await _run_process([binary, *version_flags], 15.0)
        blob = str(result.get('stdout') or '') + str(result.get('stderr') or '')
        match = re.search(r'v?\d+\.\d+\.\d+', blob)
        status['version'] = match.group(0) if match else (blob.strip().splitlines()[0][:40] if blob.strip() else None)
        if tool == 'nuclei':
            status['templates'] = NUCLEI_TEMPLATE_DIR if _templates_present() else None
    except Exception:  # pragma: no cover - diagnostics must not explode
        pass
    return status


def nuclei_notice(summary: Optional[Dict[str, Any]]) -> str:
    """One console line describing a nuclei run (or why it did not happen)."""
    if not summary:
        return ''
    status = str(summary.get('status', ''))
    if status == 'executed':
        matched = int(summary.get('matched', 0))
        errors = int(summary.get('errors', 0) or 0)
        line = (f"  [+] Nuclei: {matched} template match(es) "
                f"({summary.get('severity_filter', '')}), "
                f"{summary.get('duration_s', 0.0):.0f}s")
        if errors:
            line += f" | {errors} error(s) - see report"
        return line
    if status == 'disabled':
        return '  [*] Nuclei disabled (--no-nuclei)'
    if status == 'unavailable':
        return f"  [*] Nuclei unavailable: {summary.get('reason', '')}"
    return f"  [!] Nuclei failed: {summary.get('reason', 'unknown error')}"


# ---------------------------------------------------------------------------
# sqlmap — SQL injection confirmation
# ---------------------------------------------------------------------------

#: sqlmap marks an injectable parameter with a ``Parameter:`` header
#: followed by one or more ``Type:``/``Title:``/``Payload:`` lines.
_SQLMAP_PARAM_RE = re.compile(
    r'Parameter\s*:\s*(?P<param>[^\n]+?)\s*\((?P<method>GET|POST|PUT|COOKIE|HEADER|URI)[^\)]*\)',
    re.IGNORECASE)
_SQLMAP_TYPE_RE = re.compile(r'^\s*Type\s*:\s*(?P<itype>[^\n]+)', re.IGNORECASE | re.MULTILINE)
_SQLMAP_TITLE_RE = re.compile(r'^\s*Title\s*:\s*(?P<title>[^\n]+)', re.IGNORECASE | re.MULTILINE)
_SQLMAP_PAYLOAD_RE = re.compile(r'^\s*Payload\s*:\s*(?P<payload>[^\n]+)', re.IGNORECASE | re.MULTILINE)

_NOT_INJECTABLE_MARKERS = (
    'all tested parameters do not appear to be injectable',
    'all tested parameters appear to be not injectable',
    'no parameter(s) found for testing',
)


def parse_sqlmap_stdout(raw: str, url: str) -> List[Dict[str, Any]]:
    """Turn sqlmap stdout into Athena findings (evidence-only).

    One finding per injectable ``Parameter:`` block.  Text without a
    parameter block is never a finding - sqlmap's "looks injectable"
    chatter without a named parameter is not proof.
    """
    findings: List[Dict[str, Any]] = []
    if not raw:
        return findings
    lowered = raw.lower()
    if any(marker in lowered for marker in _NOT_INJECTABLE_MARKERS):
        return findings
    for match in _SQLMAP_PARAM_RE.finditer(raw):
        block = raw[match.start():match.start() + 2000]
        type_match = _SQLMAP_TYPE_RE.search(block)
        if not type_match:
            continue
        itype = type_match.group('itype').strip()
        title_match = _SQLMAP_TITLE_RE.search(block)
        payload_match = _SQLMAP_PAYLOAD_RE.search(block)
        param = match.group('param').strip()
        method = match.group('method').strip().upper()
        title = title_match.group('title').strip() if title_match else itype
        payload = payload_match.group('payload').strip() if payload_match else ''
        evidence = {
            'tool': 'sqlmap',
            'parameter': param,
            'method': method,
            'injection_type': itype,
            'title': title,
        }
        if payload:
            evidence['payload'] = payload[:500]
        description = f'sqlmap confirmed SQL injection in parameter {param!r} ({method}): {title}'
        findings.append({
            'id': f'sqlmap-sqli-{len(findings) + 1}',
            'type': 'SQL Injection',
            'url': url,
            'severity': 'CRITICAL',
            'description': description,
            'payload': payload[:500],
            'evidence': evidence,
            'source': 'sqlmap',
            'confidence': 'high',
            'verified': True,
        })
        if len(findings) >= MAX_FINDINGS:
            break
    return findings


def sqlmap_candidate_urls(urls: Sequence[str], limit: int = SQLMAP_MAX_URLS) -> List[str]:
    """Pick URLs worth handing to sqlmap: query-string params first."""
    with_params = [u for u in urls if isinstance(u, str) and '?' in u and '=' in u]
    others = [u for u in urls if isinstance(u, str) and u not in with_params]
    picked = (with_params + others)[:max(0, int(limit))]
    return picked


async def run_sqlmap(url: str,
                     binary: Optional[str] = None,
                     timeout: float = SQLMAP_TIMEOUT,
                     extra_args: Sequence[str] = (),
                     enabled: bool = True) -> Dict[str, Any]:
    """Confirm SQL injection in ``url`` with sqlmap.  Never raises."""
    tool = 'sqlmap'
    if not enabled:
        return {**_unavailable(tool, '', 'disabled by --no-sqlmap'),
                'status': 'disabled'}
    if not url:
        return {**_unavailable(tool, '', 'no target'), 'status': 'skipped'}
    binary = binary or find_binary(tool)
    if not binary:
        return _unavailable(tool, tool, f'sqlmap is not installed - {TOOL_INSTALL_HINTS[tool]}')
    tmpdir = tempfile.mkdtemp(prefix='athena-sqlmap-')
    argv: List[str] = [
        binary, '-u', url,
        '--batch', '--level', '1', '--risk', '1',
        '--smart', '--timeout', '10', '--retries', '1',
        '--threads', '1', '--output-dir', tmpdir,
        '--disable-coloring',
    ]
    if extra_args:
        argv += list(extra_args)
    try:
        result = await _run_process(argv, timeout)
    except Exception as exc:  # pragma: no cover - never break the scan
        return {'tool': tool, 'status': 'failed', 'binary': binary,
                'reason': str(exc)[:300], 'findings': [], 'matched': 0,
                'duration_s': 0.0, 'argv': ['<binary>', *argv[1:]]}
    finally:
        try:
            import shutil as _shutil
            _shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass
    if not result.get('ok'):
        if result.get('timeout'):
            reason = f'timed out after {timeout:g}s'
        elif result.get('failed_to_start'):
            reason = str(result.get('stderr'))[:200]
        else:
            reason = (str(result.get('stderr')).strip()
                      or f"exit code {result.get('returncode')}")
            reason = reason.splitlines()[0] if reason else 'unknown error'
        logger.warning('sqlmap run failed for %s: %s', url, reason)
        return {'tool': tool, 'status': 'failed', 'binary': binary,
                'reason': reason[:300], 'findings': [], 'matched': 0,
                'duration_s': result.get('duration_s', 0.0),
                'argv': ['<binary>', *argv[1:]],
                'returncode': result.get('returncode')}
    findings = parse_sqlmap_stdout(str(result.get('stdout') or ''), url)
    return {'tool': tool, 'status': 'executed', 'binary': binary, 'reason': '',
            'findings': findings, 'matched': len(findings),
            'duration_s': result.get('duration_s', 0.0),
            'argv': ['<binary>', *argv[1:]],
            'returncode': result.get('returncode'), 'target': url}


def sqlmap_notice(summary: Optional[Dict[str, Any]]) -> str:
    """One console line describing a sqlmap run."""
    if not summary:
        return ''
    status = str(summary.get('status', ''))
    if status == 'executed':
        matched = int(summary.get('matched', 0))
        return (f"  [+] Sqlmap: {matched} injectable parameter(s) "
                f"at {summary.get('target', '')} "
                f"({summary.get('duration_s', 0.0):.0f}s)")
    if status == 'disabled':
        return '  [*] Sqlmap disabled (--no-sqlmap)'
    if status == 'unavailable':
        return f"  [*] Sqlmap unavailable: {summary.get('reason', '')}"
    if status == 'skipped':
        return ''
    return f"  [!] Sqlmap failed: {summary.get('reason', 'unknown error')}"


# ---------------------------------------------------------------------------
# dalfox — reflected/stored XSS confirmation
# ---------------------------------------------------------------------------

def _dalfox_finding_url(item: Dict[str, Any], fallback: str) -> str:
    for key in ('url', 'target', 'request_url', 'matched_at'):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return fallback


def _dalfox_is_confirmed(item: Dict[str, Any]) -> bool:
    """Only V (verified XSS) counts.  R/A/I are explicitly not claims."""
    for key in ('result_type', 'result-type', 'type', 'kind', 'detection_method', 'method'):
        value = str(item.get(key) or '').strip().upper()
        if value in ('V', 'VULNERABLE', 'VERIFIED', 'CONFIRMED', 'XSS'):
            return True
        if value in ('R', 'REFLECTED', 'A', 'AST', 'I', 'INFO', 'INFORMATIONAL'):
            return False
    # No explicit marker: a PoC/payload reaching an executable sink is proof.
    text = json.dumps(item).lower()
    if 'alert(' in text or 'poc' in text or 'payload' in text:
        return True
    return False


def parse_dalfox_json(raw: str, target: str) -> List[Dict[str, Any]]:
    """Turn dalfox JSON/JSONL output into Athena findings (V-only).

    Accepts the ``{"findings": [...]}`` envelope, a bare list, or JSONL
    (first line ``meta``, rest findings).  Malformed lines are skipped.
    """
    items: List[Any] = []
    if not raw or not raw.strip():
        return []
    text = raw.strip()
    try:
        payload = json.loads(text)
        if isinstance(payload, dict) and isinstance(payload.get('findings'), list):
            items = payload['findings']
        elif isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict):
            items = [payload]
    except json.JSONDecodeError:
        items = []
    if not items:
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith('{'):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and 'meta' in event and len(event) == 1:
                continue
            if isinstance(event, dict):
                if isinstance(event.get('findings'), list):
                    items.extend(event['findings'])
                else:
                    items.append(event)
    findings: List[Dict[str, Any]] = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        if not _dalfox_is_confirmed(item):
            continue
        url = _dalfox_finding_url(item, target)
        if not url:
            continue
        param = str(item.get('param') or item.get('parameter') or item.get('name') or '')
        payload_str = str(item.get('poc') or item.get('payload') or item.get('evidence') or '')
        method = str(item.get('method') or item.get('detection_method') or 'V')
        key = (url, param, payload_str[:80])
        if key in seen:
            continue
        seen.add(key)
        evidence = {'tool': 'dalfox', 'param': param, 'method': method,
                    'raw': {k: str(v)[:300] for k, v in item.items()
                            if k in ('severity', 'confidence', 'type', 'result_type', 'sink', 'source')}}
        if payload_str:
            evidence['poc'] = payload_str[:500]
        findings.append({
            'id': f'dalfox-xss-{len(findings) + 1}',
            'type': 'Cross-Site Scripting (XSS)',
            'url': url,
            'severity': 'HIGH',
            'description': (f"Dalfox verified XSS in parameter {param!r}" if param
                            else 'Dalfox verified reflected/stored XSS') + f' at {url}',
            'payload': payload_str[:500],
            'evidence': evidence,
            'source': 'dalfox',
            'confidence': 'high',
            'verified': True,
        })
        if len(findings) >= MAX_FINDINGS:
            break
    return findings


async def run_dalfox(target: str,
                     binary: Optional[str] = None,
                     timeout: float = DALFOX_TIMEOUT,
                     extra_args: Sequence[str] = (),
                     enabled: bool = True) -> Dict[str, Any]:
    """Scan one URL for XSS with dalfox.  Never raises."""
    tool = 'dalfox'
    if not enabled:
        return {**_unavailable(tool, '', 'disabled by --no-dalfox'),
                'status': 'disabled'}
    if not target:
        return {**_unavailable(tool, '', 'no target'), 'status': 'skipped'}
    binary = binary or find_binary(tool)
    if not binary:
        return _unavailable(tool, tool, f'dalfox is not installed - {TOOL_INSTALL_HINTS[tool]}')
    argv: List[str] = [binary, 'scan', target, '--format', 'json',
                       '--silence', '--no-color']
    if extra_args:
        argv += list(extra_args)
    try:
        result = await _run_process(argv, timeout)
    except Exception as exc:  # pragma: no cover
        return {'tool': tool, 'status': 'failed', 'binary': binary,
                'reason': str(exc)[:300], 'findings': [], 'matched': 0,
                'duration_s': 0.0, 'argv': ['<binary>', *argv[1:]]}
    # Dalfox exits 1 when findings exist (CI-gate convention) - that is
    # success with evidence, not failure.
    stdout = str(result.get('stdout') or '')
    findings = parse_dalfox_json(stdout, target)
    # Exit 2 with a well-formed empty-findings envelope means dalfox ran but
    # got no scannable response (blocked / timeout / refused).  That is an
    # executed attempt against an unresponsive host - never a clean "no XSS"
    # and never a crash worth a scary [!] line.
    if (not findings and result.get('returncode') == 2
            and '"findings"' in stdout and 'dalfox_version' in stdout):
        return {'tool': tool, 'status': 'executed', 'binary': binary,
                'reason': ('no scannable response (blocked, timeout, or refused) - '
                           'not a clean XSS miss'),
                'findings': [], 'matched': 0,
                'duration_s': result.get('duration_s', 0.0),
                'argv': ['<binary>', *argv[1:]],
                'returncode': 2, 'target': target}
    if findings:
        return {'tool': tool, 'status': 'executed', 'binary': binary, 'reason': '',
                'findings': findings, 'matched': len(findings),
                'duration_s': result.get('duration_s', 0.0),
                'argv': ['<binary>', *argv[1:]],
                'returncode': result.get('returncode'), 'target': target}
    if not result.get('ok'):
        if result.get('timeout'):
            reason = f'timed out after {timeout:g}s'
        else:
            reason = (str(result.get('stderr')).strip()
                      or f"exit code {result.get('returncode')}")
            reason = reason.splitlines()[0] if reason else 'unknown error'
        # Exit 1 with no parseable findings and no stderr is "no XSS found",
        # not a crash - report it as an executed clean miss.
        if result.get('returncode') == 1 and not reason:
            reason = ''
        if reason:
            logger.warning('dalfox run failed for %s: %s', target, reason)
            return {'tool': tool, 'status': 'failed', 'binary': binary,
                    'reason': reason[:300], 'findings': [], 'matched': 0,
                    'duration_s': result.get('duration_s', 0.0),
                    'argv': ['<binary>', *argv[1:]],
                    'returncode': result.get('returncode')}
    return {'tool': tool, 'status': 'executed', 'binary': binary, 'reason': '',
            'findings': [], 'matched': 0,
            'duration_s': result.get('duration_s', 0.0),
            'argv': ['<binary>', *argv[1:]],
            'returncode': result.get('returncode'), 'target': target}


def dalfox_notice(summary: Optional[Dict[str, Any]]) -> str:
    """One console line describing a dalfox run."""
    if not summary:
        return ''
    status = str(summary.get('status', ''))
    if status == 'executed':
        matched = int(summary.get('matched', 0))
        reason = str(summary.get('reason', '') or '')
        probed = summary.get('urls_probed')
        scope = (f"across {probed} URL(s)" if probed
                 else f"at {summary.get('target', '')}")
        if reason:
            return f"  [*] Dalfox: 0 findings {scope} ({reason})"
        return (f"  [+] Dalfox: {matched} XSS finding(s) "
                f"{scope} "
                f"({summary.get('duration_s', 0.0):.0f}s)")
    if status == 'disabled':
        return '  [*] Dalfox disabled (--no-dalfox)'
    if status == 'unavailable':
        return f"  [*] Dalfox unavailable: {summary.get('reason', '')}"
    if status == 'skipped':
        return ''
    return f"  [!] Dalfox failed: {summary.get('reason', 'unknown error')}"


# ---------------------------------------------------------------------------
# wafw00f — WAF fingerprint (tuning signal, never a vulnerability)
# ---------------------------------------------------------------------------

def parse_wafw00f_text(raw: str, target: str) -> Dict[str, Any]:
    """Parse wafw00f stdout.  Returns ``{'detected': bool, 'waf': str}``."""
    if not raw:
        return {'detected': False, 'waf': ''}
    lowered = raw.lower()
    if 'no waf' in lowered or 'not behind' in lowered or 'not detected' in lowered:
        return {'detected': False, 'waf': ''}
    match = re.search(r'is behind\s+(?:a\s+)?([^\n\(\)]+)', raw, re.IGNORECASE)
    if match:
        waf = match.group(1).strip().rstrip('.')
        if waf and len(waf) < 120:
            return {'detected': True, 'waf': waf}
    match = re.search(r'WAF[^:]*:\s*([^\n]+)', raw, re.IGNORECASE)
    if match:
        waf = match.group(1).strip().rstrip('.')
        if waf and 'not' not in waf.lower() and len(waf) < 120:
            return {'detected': True, 'waf': waf}
    if 'identified: true' in lowered or 'waf identified' in lowered:
        return {'detected': True, 'waf': 'unknown (see raw output)'}
    return {'detected': False, 'waf': ''}


def parse_wafw00f_json(raw: str, target: str) -> Dict[str, Any]:
    """Parse wafw00f ``-f json`` output; falls back to text parsing."""
    if not raw or not raw.strip():
        return {'detected': False, 'waf': ''}
    try:
        payload = json.loads(raw.strip())
    except json.JSONDecodeError:
        return parse_wafw00f_text(raw, target)
    candidates: List[Any] = []
    if isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict):
        for key in ('results', 'targets', 'data'):
            if isinstance(payload.get(key), list):
                candidates = payload[key]
                break
        else:
            candidates = [payload]
    for entry in candidates:
        if not isinstance(entry, dict):
            continue
        blob = json.dumps(entry).lower()
        waf = str(entry.get('firewall') or entry.get('waf') or entry.get('detected_waf')
                  or entry.get('manufacturer') or '')
        detected = bool(entry.get('detected', entry.get('isbehind', entry.get('behind'))))
        if waf and waf.lower() not in ('none', 'no', 'false', 'n/a', 'unknown'):
            return {'detected': True, 'waf': waf[:120]}
        if detected:
            return {'detected': True, 'waf': waf[:120] if waf else 'unknown (see raw output)'}
        if 'cloudflare' in blob or 'akamai' in blob or 'modsecurity' in blob or 'aws' in blob:
            return {'detected': True, 'waf': 'unknown (see raw output)'}
    return parse_wafw00f_text(raw, target)


async def run_wafw00f(target: str,
                      binary: Optional[str] = None,
                      timeout: float = WAFW00F_TIMEOUT,
                      extra_args: Sequence[str] = (),
                      enabled: bool = True) -> Dict[str, Any]:
    """Fingerprint the WAF in front of ``target``.  Never raises.

    A detected WAF is reported as one INFO finding (a tuning signal for
    payload selection), never as a vulnerability.  No WAF means zero
    findings and an executed clean miss.
    """
    tool = 'wafw00f'
    if not enabled:
        return {**_unavailable(tool, '', 'disabled by --no-wafw00f'),
                'status': 'disabled'}
    if not target:
        return {**_unavailable(tool, '', 'no target'), 'status': 'skipped'}
    binary = binary or find_binary(tool)
    if not binary:
        return _unavailable(tool, tool, f'wafw00f is not installed - {TOOL_INSTALL_HINTS[tool]}')
    argv: List[str] = [binary, target, '--no-colors']
    if extra_args:
        argv += list(extra_args)
    try:
        result = await _run_process(argv, timeout)
    except Exception as exc:  # pragma: no cover
        return {'tool': tool, 'status': 'failed', 'binary': binary,
                'reason': str(exc)[:300], 'findings': [], 'matched': 0,
                'duration_s': 0.0, 'argv': ['<binary>', *argv[1:]]}
    stdout = str(result.get('stdout') or '')
    parsed = parse_wafw00f_text(stdout, target)
    findings: List[Dict[str, Any]] = []
    if parsed['detected']:
        findings.append({
            'id': 'wafw00f-waf-1',
            'type': 'WAF Detected',
            'url': target,
            'severity': 'INFO',
            'description': f"WAF fingerprint: {parsed['waf']} in front of {target} - tune payloads/rate accordingly",
            'payload': '',
            'evidence': {'tool': 'wafw00f', 'waf': parsed['waf'], 'raw': stdout[:1000]},
            'source': 'wafw00f',
            'confidence': 'high',
            'verified': False,
        })
    if not result.get('ok') and not findings and result.get('returncode') not in (0, None):
        reason = (str(result.get('stderr')).strip() or stdout.strip()
                  or f"exit code {result.get('returncode')}")
        reason = reason.splitlines()[0] if reason else 'unknown error'
        if result.get('timeout'):
            reason = f'timed out after {timeout:g}s'
        logger.warning('wafw00f run failed for %s: %s', target, reason)
        return {'tool': tool, 'status': 'failed', 'binary': binary,
                'reason': reason[:300], 'findings': [], 'matched': 0,
                'duration_s': result.get('duration_s', 0.0),
                'argv': ['<binary>', *argv[1:]],
                'returncode': result.get('returncode')}
    return {'tool': tool, 'status': 'executed', 'binary': binary, 'reason': '',
            'findings': findings, 'matched': len(findings),
            'waf': parsed.get('waf', ''), 'waf_detected': parsed['detected'],
            'duration_s': result.get('duration_s', 0.0),
            'argv': ['<binary>', *argv[1:]],
            'returncode': result.get('returncode'), 'target': target}


def wafw00f_notice(summary: Optional[Dict[str, Any]]) -> str:
    """One console line describing a wafw00f run."""
    if not summary:
        return ''
    status = str(summary.get('status', ''))
    if status == 'executed':
        if summary.get('waf_detected'):
            return (f"  [+] Wafw00f: WAF detected ({summary.get('waf', 'unknown')}) "
                    f"at {summary.get('target', '')}")
        return f"  [*] Wafw00f: no WAF detected at {summary.get('target', '')}"
    if status == 'disabled':
        return '  [*] Wafw00f disabled (--no-wafw00f)'
    if status == 'unavailable':
        return f"  [*] Wafw00f unavailable: {summary.get('reason', '')}"
    if status == 'skipped':
        return ''
    return f"  [!] Wafw00f failed: {summary.get('reason', 'unknown error')}"


# ---------------------------------------------------------------------------
# httpx — HTTP probing / technology enrichment (recon, never a vuln)
# ---------------------------------------------------------------------------

def parse_httpx_jsonl(raw: str) -> List[Dict[str, Any]]:
    """Turn httpx ``-json`` output into normalized host records.

    Each record keeps url, status, title, webserver, tech and ip.  httpx
    is recon enrichment - this function never invents vulnerability
    findings; callers store records under ``hosts`` for discovery/CVE use.
    """
    hosts: List[Dict[str, Any]] = []
    if not raw or not raw.strip():
        return hosts
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        url = str(event.get('url') or event.get('input') or '').strip()
        if not url:
            continue
        tech: List[str] = []
        for key in ('tech', 'technologies', 'technology'):
            value = event.get(key)
            if isinstance(value, list):
                tech.extend(str(v) for v in value)
            elif isinstance(value, str) and value:
                tech.append(value)
        # httpx nests tech detections as [{"name": ..., "version": ...}] sometimes
        normalized_tech: List[str] = []
        for entry in event.get('tech', []) if isinstance(event.get('tech'), list) else []:
            if isinstance(entry, dict) and entry.get('name'):
                name = str(entry['name'])
                version = str(entry.get('version') or '').strip()
                normalized_tech.append(f'{name} {version}'.strip())
            elif isinstance(entry, str):
                normalized_tech.append(entry)
        if normalized_tech:
            tech = normalized_tech
        hosts.append({
            'url': url,
            'input': str(event.get('input') or ''),
            'status': event.get('status-code', event.get('status_code', event.get('status'))),
            'title': str(event.get('title') or '')[:200],
            'webserver': str(event.get('webserver') or event.get('server') or '')[:200],
            'tech': tech[:20],
            'ip': str(event.get('ip') or event.get('host-ip') or ''),
            'cdn': bool(event.get('cdn', False)),
        })
        if len(hosts) >= HTTPX_MAX_URLS * 4:
            break
    return hosts


async def run_httpx(target: str,
                    binary: Optional[str] = None,
                    timeout: float = HTTPX_TIMEOUT,
                    extra_args: Sequence[str] = (),
                    enabled: bool = True) -> Dict[str, Any]:
    """Probe ``target`` with httpx and return normalized host records.

    Never raises and never returns vulnerability findings - hosts go in
    ``hosts`` for discovery enrichment (technologies -> CVE mapping).
    """
    tool = 'httpx'
    if not enabled:
        return {**_unavailable(tool, '', 'disabled by --no-httpx'),
                'status': 'disabled'}
    if not target:
        return {**_unavailable(tool, '', 'no target'), 'status': 'skipped'}
    binary = binary or find_binary(tool)
    if not binary:
        return _unavailable(tool, tool, f'httpx is not installed - {TOOL_INSTALL_HINTS[tool]}')
    if not await _httpx_is_pd(binary):
        alt = _find_pd_httpx_candidate()
        if alt and alt != binary and await _httpx_is_pd(alt):
            binary = alt
        else:
            return _unavailable(tool, binary, 'PATH httpx resolves to Python httpx lib, not ProjectDiscovery httpx '
                                              '(PD flags rejected) - install PD build + ensure it precedes Python Scripts on PATH '
                                              '(Kali: sudo apt install httpx-toolkit; Win: go install github.com/projectdiscovery/httpx/cmd/httpx@latest)')
    argv: List[str] = [binary, '-u', target, '-json', '-silent', '-nc',
                       '-tech-detect', '-status-code', '-title',
                       '-web-server', '-ip', '-follow-redirects',
                       '-timeout', '10', '-threads', '25', '-rate-limit', '50']
    if extra_args:
        argv += list(extra_args)
    try:
        result = await _run_process(argv, timeout)
    except Exception as exc:  # pragma: no cover
        return {'tool': tool, 'status': 'failed', 'binary': binary,
                'reason': str(exc)[:300], 'findings': [], 'matched': 0,
                'hosts': [], 'duration_s': 0.0, 'argv': ['<binary>', *argv[1:]]}
    stdout = str(result.get('stdout') or '')
    # Older httpx builds may reject one of the probe flags; retry once bare.
    if not result.get('ok') and _flag_rejected(str(result.get('stderr') or '')):
        argv = [binary, '-u', target, '-json', '-silent']
        result = await _run_process(argv, timeout)
        stdout = str(result.get('stdout') or '')
    if not result.get('ok') and not stdout.strip():
        if result.get('timeout'):
            reason = f'timed out after {timeout:g}s'
        else:
            reason = (str(result.get('stderr')).strip()
                      or f"exit code {result.get('returncode')}")
            reason = reason.splitlines()[0] if reason else 'unknown error'
        logger.warning('httpx run failed for %s: %s', target, reason)
        return {'tool': tool, 'status': 'failed', 'binary': binary,
                'reason': reason[:300], 'findings': [], 'matched': 0,
                'hosts': [], 'duration_s': result.get('duration_s', 0.0),
                'argv': ['<binary>', *argv[1:]],
                'returncode': result.get('returncode')}
    hosts = parse_httpx_jsonl(stdout)
    return {'tool': tool, 'status': 'executed', 'binary': binary, 'reason': '',
            'findings': [], 'matched': 0, 'hosts': hosts,
            'hosts_probed': len(hosts),
            'duration_s': result.get('duration_s', 0.0),
            'argv': ['<binary>', *argv[1:]],
            'returncode': result.get('returncode'), 'target': target}


def httpx_notice(summary: Optional[Dict[str, Any]]) -> str:
    """One console line describing an httpx run."""
    if not summary:
        return ''
    status = str(summary.get('status', ''))
    if status == 'executed':
        probed = int(summary.get('hosts_probed', len(summary.get('hosts') or [])) or 0)
        return (f"  [+] Httpx: probed {probed} host(s) "
                f"at {summary.get('target', '')} "
                f"({summary.get('duration_s', 0.0):.0f}s)")
    if status == 'disabled':
        return '  [*] Httpx disabled (--no-httpx)'
    if status == 'unavailable':
        return f"  [*] Httpx unavailable: {summary.get('reason', '')}"
    if status == 'skipped':
        return ''
    return f"  [!] Httpx failed: {summary.get('reason', 'unknown error')}"


def tool_notice(summary: Optional[Dict[str, Any]]) -> str:
    """Dispatch a run summary to its one-line console notice."""
    if not summary:
        return ''
    tool = str(summary.get('tool', ''))
    if tool == 'nuclei':
        return nuclei_notice(summary)
    if tool == 'sqlmap':
        return sqlmap_notice(summary)
    if tool == 'dalfox':
        return dalfox_notice(summary)
    if tool == 'wafw00f':
        return wafw00f_notice(summary)
    if tool == 'httpx':
        return httpx_notice(summary)
    return f"  [*] {tool}: {summary.get('status', '')}"
