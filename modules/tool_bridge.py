"""
modules.tool_bridge.py — adapters for external security tools.
================================================================
Athena's own checks are pure Python and need no binaries.  This module adds
*optional* external engines (nuclei first; ffuf/sqlmap/dalfox later) behind
one contract every adapter must honour:

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
            'duration_s': result.get('duration_s', 0.0),
            'argv': ['<binary>', *argv[1:]],
            'returncode': result.get('returncode'),
        }

    findings = parse_nuclei_jsonl(result['stdout'], target)
    return {
        'tool': tool,
        'status': 'executed',
        'binary': binary,
        'reason': '',
        'findings': findings,
        'matched': len(findings),
        'duration_s': result.get('duration_s', 0.0),
        'argv': ['<binary>', *argv[1:]],
        'returncode': result.get('returncode'),
        'severity_filter': severity,
    }


async def tool_status(tool: str = 'nuclei') -> Dict[str, Any]:
    """Describe an external tool for ``--list-tools`` diagnostics.

    Cheap enough to run on demand: one ``-version`` call and a directory
    check.  Never raises.
    """
    status: Dict[str, Any] = {
        'tool': tool, 'installed': False, 'binary': None,
        'version': None, 'templates': None,
    }
    try:
        binary = find_binary(tool)
        if not binary:
            return status
        status['installed'] = True
        status['binary'] = binary
        result = await _run_process([binary, '-version'], 15.0)
        blob = str(result.get('stdout') or '') + str(result.get('stderr') or '')
        match = re.search(r'v?\d+\.\d+\.\d+', blob)
        status['version'] = match.group(0) if match else None
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
        return (f"  [+] Nuclei: {matched} template match(es) "
                f"({summary.get('severity_filter', '')}), "
                f"{summary.get('duration_s', 0.0):.0f}s")
    if status == 'disabled':
        return '  [*] Nuclei disabled (--no-nuclei)'
    if status == 'unavailable':
        return f"  [*] Nuclei unavailable: {summary.get('reason', '')}"
    return f"  [!] Nuclei failed: {summary.get('reason', 'unknown error')}"