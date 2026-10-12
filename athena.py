import asyncio
import sys
import os
import re
import json
import argparse
import html
import threading
import time
from contextlib import contextmanager
import urllib.parse
from collections import defaultdict, deque
from uuid import uuid4
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set, Tuple
from modules.logging_config import setup_logging
from modules.framework_config import FrameworkConfig, load_config
from modules.discovery import DiscoveryModule
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.reporting import ReportGenerator
from modules.bruteforce import BruteforceModule
from modules.protocol_scanner import SMBEnumerator, SNMPEnumerator, SMTPEnumerator, POP3Enumerator, IMAPEnumerator, ServiceBruteforcer
from modules.cve_mapper import CVEMapper, VersionCVEResult
from modules.plugin_system import PluginLoader
from modules.operations_guide import show_guide, generate_guide_json
from modules.orchestration import (
    PipelineOrchestrator, StructuredError, STAGE_BY_KEY, stage_list,
)
from modules.operation_control import OperationGate
from modules.cleanup_manager import CleanupManager
from modules import console as con
from modules.console import cprint

try:
    from modules.post_exploitation.orchestrator import PostOrchestrator
    from modules.post_exploitation import SessionState
    HAS_POST = True
except ImportError:
    HAS_POST = False

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    from flask import Flask, request, jsonify
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False


STATE_FILE = ".athena_scan_state.json"


class ScanState:
    def __init__(self, target: str, mode: str):
        self.target = target
        self.mode = mode
        self.start_time = datetime.now().isoformat()
        self.completed_urls: Set[str] = set()
        self.results: Dict[str, Any] = {}
        self.paused = False
        self.cancelled = False

    def save(self):
        data = {
            'target': self.target, 'mode': self.mode,
            'start_time': self.start_time,
            'completed_urls': list(self.completed_urls),
            'results': self.results,
        }
        with open(STATE_FILE, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    @classmethod
    def load(cls) -> Optional['ScanState']:
        if not os.path.exists(STATE_FILE):
            return None
        try:
            with open(STATE_FILE) as f:
                data = json.load(f)
            state = cls(data['target'], data['mode'])
            state.start_time = data.get('start_time', '')
            state.completed_urls = set(data.get('completed_urls', []))
            state.results = data.get('results', {})
            return state
        except Exception:
            return None

    def clear(self):
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='athena',
        description='Athena Security Suite - Advanced Penetration Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python athena.py --target example.com --scan all
  python athena.py -t example.com -m discovery
  python athena.py -t example.com -m 3 -o html
  python athena.py -t example.com -m full -p stealth -v
  python athena.py -t example.com --scan syn,udp --rate 500 --jitter 50
  python athena.py -f targets.txt -m full
  python athena.py --resume
  python athena.py --guide
  python athena.py --api
        """
    )
    parser.add_argument('-t', '--target', help='Target URL/IP/hostname')
    parser.add_argument('-f', '--target-file', help='File with targets (one per line, CIDR, or IP range)')
    parser.add_argument('-m', '--mode',
                        choices=['full', 'discovery', 'vuln', 'bruteforce', 'recon', 'all',
                                 '1', '2', '3', '4'],
                        default='full',
                        help='Scan mode (default: full). Numeric aliases: 1=full, 2=discovery, '
                             '3=vuln, 4=api server')
    parser.add_argument('-p', '--profile', choices=['stealth', 'balanced', 'aggressive', 'debug'],
                        help='Scan profile')
    parser.add_argument('--unsafe', action='store_true',
                        help='Disable safe mode (authorized testing only)')
    parser.add_argument('--scan', default='tcp_connect',
                        help='Scan types: tcp_connect,syn,udp,ack,fin,null,xmas (comma-separated)')
    parser.add_argument('--ports', help='Port range (e.g. 1-1000) or "top100", "top1000", "all"')
    parser.add_argument('--rate', type=int, default=1000, help='Max packets per second (rate limiting)')
    parser.add_argument('--concurrent', type=int, default=200, help='Concurrent connections')
    parser.add_argument('--jitter', type=int, default=0, help='Random delay ms between probes')
    parser.add_argument('--proxy', help='Proxy URL (http://user:pass@host:port)')
    parser.add_argument('--tor', action='store_true', help='Route through Tor')
    parser.add_argument('--random-agent', action='store_true', default=True, help='Rotate user agents')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', choices=['html', 'json', 'csv', 'pdf', 'all'], default='html',
                        help='Output format (default: html)')
    parser.add_argument('--resume', action='store_true', help='Resume from last interrupted scan')
    parser.add_argument('--pause', action='store_true', help='Pause after each phase')
    parser.add_argument('--guide', nargs='?', const='', help='Show PTES operations guide')
    parser.add_argument('--list-plugins', action='store_true', help='List available plugins')
    parser.add_argument('--export', help='Export results to specified path')

    exploit_group = parser.add_argument_group('Automated Exploitation')
    exploit_group.add_argument('--no-auto-exploit', action='store_true',
                               help='Skip automatic verification of detected vulnerabilities')
    exploit_group.add_argument('--exploit-aggressive', action='store_true',
                               help='Disable safe mode for automated exploitation (may cause side effects)')
    exploit_group.add_argument('--exploit-max', type=int, default=100,
                               help='Max findings to verify automatically '
                                    '(default: 100, 0 = unlimited)')
    exploit_group.add_argument('--exploit-delay', type=float, default=1.0,
                               help='Seconds to wait between exploit attempts (default: 1.0)')
    exploit_group.add_argument('--exploit-concurrency', type=int, default=6,
                               help='Findings verified in parallel (default: 6, '
                                    '1 = strictly sequential)')

    tool_group = parser.add_argument_group('External Tools')
    tool_group.add_argument('--no-nuclei', action='store_true',
                            help='Skip the external nuclei template engine '
                                 '(runs automatically when nuclei is installed)')
    tool_group.add_argument('--no-sqlmap', action='store_true',
                            help='Skip sqlmap SQL-injection confirmation '
                                 '(runs automatically when sqlmap is installed)')
    tool_group.add_argument('--no-dalfox', action='store_true',
                            help='Skip dalfox XSS confirmation '
                                 '(runs automatically when dalfox is installed)')
    tool_group.add_argument('--no-wafw00f', action='store_true',
                            help='Skip wafw00f WAF fingerprinting '
                                 '(runs automatically when wafw00f is installed)')
    tool_group.add_argument('--no-httpx', action='store_true',
                            help='Skip httpx HTTP probing/recon enrichment '
                                 '(runs automatically when httpx is installed)')
    tool_group.add_argument('--no-kev', action='store_true',
                             help='Skip CISA KEV cross-referencing of mapped CVEs '
                                  '(on by default, cached feed, offline-safe)')

    display_group = parser.add_argument_group('Display')
    display_group.add_argument('--no-color', action='store_true',
                               help='Plain console output (no ANSI colors). '
                                    'Colors also auto-disable when piped to a '
                                    'file or when NO_COLOR is set')

    api_group = parser.add_argument_group('REST API Server')
    api_group.add_argument('--api', action='store_true', help='Start the REST API server')
    api_group.add_argument('--api-host', help='Bind host for API server (default: SERVER_HOST or 0.0.0.0)')
    api_group.add_argument('--api-port', type=int, help='Bind port for API server (default: SERVER_PORT or 5000)')

    post_group = parser.add_argument_group('Post-Exploitation')
    post_group.add_argument('--post', action='store_true', help='Run post-exploitation chain after scanning')
    post_group.add_argument('--post-shell', choices=['reverse', 'bind', 'web'],
                            help='Shell type for post-exploitation')
    post_group.add_argument('--post-host', default='0.0.0.0',
                            help='Listen host for reverse shell (default: 0.0.0.0)')
    post_group.add_argument('--post-port', type=int, default=4444,
                            help='Listen/connect port for shell (default: 4444)')
    post_group.add_argument('--post-web-url', help='Web shell URL')
    post_group.add_argument('--post-web-param', default='cmd',
                            help='Web shell command parameter (default: cmd)')
    post_group.add_argument('--post-web-method', choices=['GET', 'POST'], default='GET',
                            help='Web shell HTTP method (default: GET)')
    post_group.add_argument('--post-manual', action='store_true',
                            help='Step through post-exploitation phases interactively')
    post_group.add_argument('--post-only', choices=['foothold', 'enumeration', 'privesc',
                            'lateral', 'data_collection', 'persistence', 'cleanup'],
                            help='Run only a single post-exploitation phase')
    post_group.add_argument('--post-skip', choices=['foothold', 'enumeration', 'privesc',
                            'lateral', 'data_collection', 'persistence', 'cleanup'],
                            help='Skip a post-exploitation phase')
    post_group.add_argument('--post-list-sessions', action='store_true',
                            help='List saved post-exploitation sessions')
    post_group.add_argument('--post-interactive', action='store_true',
                            help='Open interactive shell session')
    post_group.add_argument('--post-wait', type=float, default=10.0,
                            help='Seconds to wait for an inbound/pivoted session '
                                 'instead of a fixed 2s sleep (default: 10)')
    post_group.add_argument('--post-payload', choices=['bash', 'python', 'powershell'],
                            help='Print a reconnecting reverse-shell payload for '
                                 '--post-host/--post-port and exit')
    post_group.add_argument('--post-payload-retries', type=int, default=30,
                            help='Callback retry count for --post-payload (default: 30)')
    post_group.add_argument('--post-payload-interval', type=int, default=5,
                            help='Seconds between callback retries (default: 5)')
    post_group.add_argument('--c2-url', help='C2 callback URL for heartbeat/persistence')
    post_group.add_argument('--exfil-url', help='Exfiltration URL for data upload')
    post_group.add_argument('--scope-file',
                            help='Engagement scope file (JSON) defining targets, '
                                 'exclusions and allowed techniques')
    post_group.add_argument('--engagement-id',
                            help='Engagement ID to bind post-exploitation to '
                                 '(looked up in engagements.json)')
    post_group.add_argument('--no-auto-assess', action='store_true',
                            help='Disable the structured host/privilege/network '
                                 'assessment stage')

    orchestration_group = parser.add_argument_group('Pipeline Orchestration')
    orchestration_group.add_argument('--stage', action='append', metavar='STAGE',
                                     help='Run only the given pipeline stage(s) '
                                          'independently (repeatable): '
                                          'engagement,recon,enumeration,discovery,'
                                          'scanning,validation,initial_access,'
                                          'post_exploitation_assessment,'
                                          'attack_path_analysis,impact_assessment,'
                                          'reporting')
    orchestration_group.add_argument('--list-stages', action='store_true',
                                     help='List the pipeline stages and exit')
    orchestration_group.add_argument('--list-tools', action='store_true',
                                     help='Show external tools (nuclei, sqlmap, '
                                          'dalfox, wafw00f, httpx) that '
                                          'Athena detected, then exit')
    orchestration_group.add_argument('--preflight', action='store_true',
                                     help='Explain operations before executing '
                                          '(authorization, scope, expected evidence)')
    return parser.parse_args()


def expand_targets(target_str: str) -> List[str]:
    targets = []
    target_str = target_str.strip()
    if '/' in target_str and target_str.count('.') >= 2:
        try:
            import ipaddress
            network = ipaddress.ip_network(target_str, strict=False)
            targets = [str(ip) for ip in network.hosts()][:256]
        except ValueError:
            targets = [target_str]
    elif '-' in target_str and target_str.count('.') >= 2:
        parts = target_str.rsplit('.', 1)
        if len(parts) == 2 and '-' in parts[1]:
            base = parts[0]
            range_parts = parts[1].split('-')
            try:
                start, end = int(range_parts[0]), int(range_parts[1])
                targets = [f"{base}.{i}" for i in range(start, end + 1)]
            except ValueError:
                targets = [target_str]
        else:
            targets = [target_str]
    else:
        targets = [target_str]
    return targets


def load_targets_from_file(filepath: str) -> List[str]:
    all_targets = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                all_targets.extend(expand_targets(line))
    return all_targets


def resolve_targets(args) -> List[str]:
    targets = []
    if args.target:
        targets.extend(expand_targets(args.target))
    if args.target_file:
        targets.extend(load_targets_from_file(args.target_file))
    if not targets:
        cprint("[!] No target specified. Use -t TARGET or -f TARGET_FILE")
        sys.exit(1)
    normalized = []
    for t in targets:
        if not t.startswith(('http://', 'https://')):
            try:
                import ipaddress
                ipaddress.ip_address(t)
                normalized.append(t)
            except ValueError:
                normalized.append(f"https://{t}")
        else:
            normalized.append(t)
    return normalized


def parse_ports(port_str: str) -> List[int]:
    # IMPORTANT-ONLY is the default (empty list = discovery's curated set).
    # --ports all sets the full-sweep flag consumed by discovery.scan_ports.
    if not port_str or port_str == 'top100' or port_str == 'top1000':
        return []
    if port_str == 'all':
        try:
            import os as _os
            _os.environ['ATHENA_FULL_PORTS'] = '1'
        except Exception:
            pass
        return []
    if '-' in port_str:
        parts = port_str.split('-')
        return list(range(int(parts[0]), int(parts[1]) + 1))
    return [int(p.strip()) for p in port_str.split(',') if p.strip().isdigit()]


class ProgressBar:
    def __init__(self, total: int, desc: str = "Scanning"):
        self.total = total
        self.desc = desc
        self.pbar = None
        if HAS_TQDM:
            self.pbar = tqdm(total=total, desc=desc, unit="items", ncols=80)

    def update(self, n: int = 1):
        if self.pbar:
            self.pbar.update(n)
        else:
            cprint(f"  [*] {self.desc}: {n}/{self.total}", end='\r')

    def close(self):
        if self.pbar:
            self.pbar.close()


async def run_discovery(target: str, output_format: str = 'html',
                        scan_types: List[str] = None, ports: List[int] = None,
                        concurrent: int = 200, rate: int = 1000, jitter: int = 0,
                        stages: List[str] = None) -> Dict[str, Any]:
    title = ('DISCOVERY & RECONNAISSANCE'
             if stages is None else 'RECONNAISSANCE (light)')
    con.phase(f"PHASE 1: {title}")
    discovery = DiscoveryModule()
    try:
        results = await discovery.run(target, stages=stages)
        cprint(f"  [+] Harvesting emails...")
        urls = results.get('urls', [])
        emails = await discovery.harvest_emails(target, urls)
        if emails:
            results['emails'] = emails
            cprint(f"  [+] Emails harvested: {len(emails)}")
            for e in emails[:5]:
                try:
                    cprint(f"      - {e.get('email')} (from {e.get('source','')[:60]})")
                except Exception:
                    pass
        else:
            cprint(f"  [*] Emails: none found in first {min(len(urls),30)} pages")
        # Always surface DNS/TLS/hidden-asset summaries (were silent 0.2s/0.5s/31s)
        try:
            _dns = results.get('dns_records') or {}
            if _dns:
                _ip = _dns.get('ip') or (', '.join(_dns.get('a_records', [])[:2]) if _dns.get('a_records') else 'n/a')
                cprint(f"  [+] DNS: {_dns.get('domain','')} -> {_ip} | MX:{len(_dns.get('mx_records',[]))} "
                      f"TXT:{len(_dns.get('txt_records',[]))} NS:{len(_dns.get('ns_records',[]))}")
                if _dns.get('spf_analysis'):
                    cprint(f"      SPF: {_dns.get('spf_analysis')}")
                if _dns.get('dmarc_analysis'):
                    cprint(f"      DMARC: {_dns.get('dmarc_analysis')}")
            _tls = results.get('tls_certificate') or {}
            if _tls:
                if _tls.get('issues'):
                    for iss in _tls['issues'][:3]:
                        cprint(f"  [!] TLS: {iss}")
                else:
                    cprint(f"  [+] TLS: {_tls.get('version','?')} cipher={_tls.get('cipher','?')} "
                          f"expiry={_tls.get('valid_until','?')}")
            _ha = results.get('hidden_assets') or {}
            if _ha:
                cprint(f"  [+] Hidden assets: {len(_ha.get('hidden_directories',[]))} dirs, "
                      f"{len(_ha.get('backup_files',[]))} backups, "
                      f"{len(_ha.get('sensitive_files',[]))} sensitive")
            elif stages is None or 'hidden_assets' in (stages or []):
                cprint(f"  [*] Hidden assets: none confirmed (see wildcard-filtered counts above)")
            _lh = results.get('listing_harvest') or {}
            if _lh.get('findings'):
                cprint(f"  [+] Listing harvest: {len(_lh['findings'])} file(s) "
                      f"content-confirmed from {len(_lh.get('listings', []))} open "
                      f"listing(s) ({_lh.get('files_seen', 0)} files seen)")
            _sec = results.get('security_endpoints') or []
            cprint(f"  [+] Security endpoints: {len(_sec)} reachable (robots/security.txt/sitemap)")
        except Exception:
            pass
        if scan_types:
            cprint(f"  [+] Advanced port scanning ({', '.join(scan_types)})...")
            adv_ports = ports or None
            adv_results = await discovery.scan_ports_advanced(
                target, scan_types=scan_types, ports=adv_ports,
                concurrent=concurrent, rate_limit=rate, jitter=jitter/1000.0
            )
            results['advanced_ports'] = adv_results
            # Reconcile basic vs advanced counts explicitly (was 12 vs 10 confusion)
            try:
                _basic = results.get('ports') or []
                _adv_ports = (adv_results.get('ports') or {}) if isinstance(adv_results, dict) else {}
                _adv_open = sum(1 for v in _adv_ports.values() if any(x.get('open') for x in v.values())) if _adv_ports else 0
                cprint(f"  [*] Port reconciliation: basic={len(_basic) if isinstance(_basic,list) else _basic} "
                      f"advanced_tcp={_adv_open} (UDP-only 53 explains deltas; trust union)")
            except Exception:
                pass
        return results
    finally:
        await discovery.close()


def _scan_targets(discovery_results: Dict[str, Any]) -> List[str]:
    """URLs the vulnerability scanner should test, from whatever recon ran.

    Returns an empty list when discovery never ran - ``run_vuln_scan``
    then falls back to the bare target, which is the pre-recon behaviour.
    """
    if not isinstance(discovery_results, dict) or not discovery_results:
        return []
    urls: List[str] = []
    for key in ('urls', 'security_endpoints'):
        for entry in discovery_results.get(key) or []:
            if isinstance(entry, str):
                urls.append(entry)
            elif isinstance(entry, dict) and entry.get('url'):
                urls.append(str(entry['url']))
    for panel in discovery_results.get('admin_panels') or []:
        if isinstance(panel, dict) and panel.get('url'):
            urls.append(str(panel['url']))
    # Preserve order and drop duplicates; recon already restricts these to
    # the target's own host.
    return list(dict.fromkeys(urls))


def _merge_httpx_into_discovery(discovery_results: Dict[str, Any],
                                httpx_summary: Dict[str, Any]) -> None:
    """Fold httpx host records into discovery (recon enrichment only).

    Adds unseen technologies (with versions when httpx detected them) so
    CVE mapping can fire on servers the crawler missed.  Never overwrites
    existing entries and never raises.
    """
    try:
        if not isinstance(discovery_results, dict) or not isinstance(httpx_summary, dict):
            return
        hosts = httpx_summary.get('hosts') or []
        if not hosts:
            return
        techs = discovery_results.setdefault('technologies', [])
        tech_conf = discovery_results.setdefault('technologies_with_confidence', [])
        seen = {str(t).lower() for t in techs if isinstance(t, str)}
        seen_conf = {(str(e.get('technology', '')).lower(), str(e.get('version', '')).lower())
                     for e in tech_conf if isinstance(e, dict)}
        for host in hosts:
            if not isinstance(host, dict):
                continue
            ws = str(host.get('webserver') or '').strip()
            if ws and ws.lower() not in seen:
                techs.append(ws)
                seen.add(ws.lower())
            for entry in host.get('tech') or []:
                name, _, version = str(entry).partition(' ')
                name, version = name.strip(), version.strip()
                if not name:
                    continue
                key = (name.lower(), version.lower())
                if key in seen_conf:
                    continue
                seen_conf.add(key)
                tech_conf.append({'technology': name, 'version': version, 'confidence': 2})
                if name.lower() not in seen:
                    techs.append(name)
                    seen.add(name.lower())
    except Exception:  # pragma: no cover - enrichment must not explode
        pass


def _discovery_health(discovery_results: Dict[str, Any]) -> Dict[str, Any]:
    """Decide whether discovery actually produced an inventory.

    A resolver outage aborts crawl, ports, subdomains and paths at once while
    the run keeps printing stage banners, so nothing *looks* wrong unless you
    read every ``[time]`` line.  This turns "everything empty" into a signal
    the console and the final banner can act on.
    """
    results = discovery_results or {}
    signals = {
        'urls': len(results.get('urls') or []),
        'subdomains': len(results.get('subdomains') or []),
        'ports': len(results.get('ports') or results.get('open_ports') or []),
        'paths': len(results.get('discovered_paths') or results.get('paths') or []),
        'technologies': len(results.get('technologies') or []),
    }
    empty = [name for name, count in signals.items() if count == 0]
    return {
        'signals': signals,
        'empty': empty,
        'healthy': len(empty) < len(signals),
    }


async def run_waf_gate(target: str, args=None) -> Dict[str, Any]:
    """WAF detection FIRST — before discovery, scanning or bruteforce.

    Runs the native detector (no binary needed) and, when installed,
    wafw00f for a richer fingerprint. Returns a dict stored on
    ``discovery_results['waf']`` and passed to the vuln scanner so rates
    and payloads are tuned before a single injection is sent.
    Never raises — a failed gate means 'unknown', never a crash.
    """
    con.phase("PHASE 0: WAF GATE (runs first)")
    waf_info: Dict[str, Any] = {'verdict': 'unknown', 'waf': '', 'tuning': ''}
    try:
        from modules.waf_detector import detect_waf, waf_notice
        waf_info = await detect_waf(target)
        cprint(waf_notice(waf_info))
    except Exception as exc:
        cprint(f"  [!] Native WAF gate failed: {exc}")
        waf_info = {'verdict': 'unknown', 'waf': '', 'tuning': str(exc)[:200]}
    # wafw00f enrichment when installed (tuning signal, not a vuln)
    try:
        if args is None or not getattr(args, 'no_wafw00f', False):
            from modules.tool_bridge import run_wafw00f, wafw00f_notice
            summary = await run_wafw00f(target, enabled=True)
            notice = wafw00f_notice(summary)
            if notice:
                cprint(notice)
            if isinstance(summary, dict) and summary.get('status') == 'executed':
                waf_info['wafw00f'] = summary
                if summary.get('waf_detected') and waf_info.get('verdict') == 'none':
                    waf_info['verdict'] = 'likely'
                    waf_info['waf'] = summary.get('waf', 'WAF (wafw00f)')
                    waf_info['tuning'] = ('wafw00f fingerprinted a WAF — '
                                          'low-rate + bypass payloads apply.')
                    cprint(f"  [!] WAF gate upgraded to LIKELY via wafw00f: {waf_info['waf']}")
    except Exception as exc:
        cprint(f"  [*] wafw00f enrichment skipped: {exc}")
    # Tune global scan behaviour up-front
    try:
        verdict = str(waf_info.get('verdict', ''))
        if verdict in ('confirmed', 'likely', 'hard-block'):
            from modules.framework_config import FrameworkConfig as _FC
            # Force stealth delays + lower concurrency while WAF is up
            _FC.STEALTH_MODE = True
            _FC.STEALTH_MIN_DELAY = max(float(getattr(_FC, 'STEALTH_MIN_DELAY', 0.1)), 0.4)
            _FC.STEALTH_MAX_DELAY = max(float(getattr(_FC, 'STEALTH_MAX_DELAY', 0.5)), 1.5)
            try:
                _FC.SCANNING_THREADS = min(int(getattr(_FC, 'SCANNING_THREADS', 40)), 20)
            except Exception:
                pass
            cprint(f"  [*] Scan tuned for WAF: stealth ON, delays "
                  f"{_FC.STEALTH_MIN_DELAY}-{_FC.STEALTH_MAX_DELAY}s, "
                  f"threads<={getattr(_FC, 'SCANNING_THREADS', 20)}")
    except Exception:
        pass
    return waf_info


async def show_tool_status() -> None:
    """Print the external tools Athena can call, then return."""
    try:
        from modules.tool_bridge import tool_status, SUPPORTED_TOOLS, TOOL_INSTALL_HINTS
    except Exception as exc:  # pragma: no cover - import guard
        cprint(f"[!] Tool bridge unavailable: {exc}")
        return

    cprint(f"{'=' * 60}")
    cprint("  EXTERNAL TOOLS")
    cprint(f"{'=' * 60}")
    try:
        tools = tuple(SUPPORTED_TOOLS)
        hints = dict(TOOL_INSTALL_HINTS) if isinstance(TOOL_INSTALL_HINTS, dict) else {}
    except Exception:  # pragma: no cover - import guard fallback
        tools = ('nuclei',)
        hints = {}
    for tool in tools:
        try:
            status = await tool_status(tool)
        except Exception:
            continue
        if status['installed']:
            version = status['version'] or 'unknown version'
            cprint(f"  [+] {tool}: {version}")
            cprint(f"      binary: {status['binary']}")
            if tool == 'nuclei':
                templates = status.get('templates')
                if templates:
                    cprint(f"      templates: {templates}")
                else:
                    cprint("      templates: MISSING - run: nuclei -update-templates")
        else:
            cprint(f"  [-] {tool}: not installed")
            note = status.get('note', '')
            if note:
                cprint(f"      note: {note}")
            hint = hints.get(tool, '')
            if hint:
                cprint(f"      {hint}")
    cprint("  [*] Athena runs these automatically when present; "
          "--no-<tool> skips them (e.g. --no-nuclei, --no-sqlmap).\n")


@contextmanager
def _phase(label: str):
    """Console line showing how long a scan phase actually took."""
    t0 = time.monotonic()
    try:
        yield
    finally:
        cprint(f"  [time] {label}: {time.monotonic() - t0:.1f}s")


async def run_vuln_scan(target: str, urls: List[str] = None,
                         stealth: bool = False,
                         waf_info: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    con.phase("PHASE 2: VULNERABILITY SCANNING")
    if waf_info and str(waf_info.get('verdict', '')) in ('confirmed', 'likely', 'hard-block'):
        cprint(f"  [*] Vuln scan WAF-aware: {waf_info.get('waf','WAF')} "
              f"({waf_info.get('verdict')}) — bypass payloads + low rate")
        stealth = True
    if not urls:
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        urls = [target.rstrip('/') + '/']
    scanner = VulnerabilityScanner(stealth_mode=stealth, waf_info=waf_info)
    try:
        results = await scanner.scan_all(urls)
        return results
    finally:
        await scanner.close()


async def run_external_scan(target: str, stealth: bool = False,
                            args: argparse.Namespace = None,
                            native_findings: List[Dict[str, Any]] = None
                            ) -> Optional[Dict[str, Any]]:
    """Run external template engines (nuclei) and report what happened.

    A missing binary prints one line and returns ``None`` - the scan then
    continues exactly as it did before the tool bridge existed.  Findings
    returned here use the scanner's own shape, so they join AI triage and the
    exploitation runner untouched.

    When nuclei reports nothing while Athena reported critical/high findings,
    the disagreement is printed and stored on the summary instead of being
    silently averaged away - two scanners that disagree 142-to-0 means at
    least one of them is wrong, and the operator must know which.
    """
    try:
        from modules.tool_bridge import run_nuclei, nuclei_notice
    except Exception as exc:  # pragma: no cover - import guard
        cprint(f"  [!] Tool bridge unavailable: {exc}")
        return None
    try:
        # Profile-aware nuclei rate: stealth=50 (quiet), balanced=150,
        # aggressive=None(default 150+). Old code used 50 for balanced too
        # (since balanced stealth=True) -> 350s blew up to 796s.
        try:
            _prof2 = (getattr(args, 'profile', None) or os.getenv('AETHELRED_PROFILE', 'balanced')).lower()
        except Exception:
            _prof2 = 'balanced'
        if _prof2 == 'stealth':
            _nrate = 50
        elif _prof2 == 'balanced':
            _nrate = 150
        else:
            _nrate = None
        summary = await run_nuclei(
            target,
            rate_limit=_nrate,
            enabled=not getattr(args, 'no_nuclei', False),
        )
    except Exception as exc:  # pragma: no cover - never break the scan
        cprint(f"  [!] Nuclei bridge error: {exc}")
        return None
    notice = nuclei_notice(summary)
    if notice:
        cprint(notice)
    if summary and summary.get('status') == 'executed':
        _flag_tool_disagreement(summary, native_findings)
    return summary


def _flag_tool_disagreement(summary: Dict[str, Any],
                            native_findings: List[Dict[str, Any]] = None) -> None:
    """Print + record when nuclei and the native scanner contradict each other."""
    if int(summary.get('matched') or 0):
        return
    native = [
        f for f in (native_findings or [])
        if isinstance(f, dict)
        and str(f.get('severity', '')).upper() in ('CRITICAL', 'HIGH')
    ]
    if not native:
        return

    errors = int(summary.get('errors') or 0)
    if errors:
        note = (f"nuclei reported {errors} error(s) and 0 matches - "
                f"0 matches is INCONCLUSIVE (target likely unreachable), "
                f"not a clean miss")
    else:
        note = (f"nuclei matched 0 templates while Athena reported "
                f"{len(native)} critical/high finding(s) - the scanners "
                f"disagree; treat unproven native findings as unverified")
    cprint(f"  [!] Tool disagreement: {note}")
    summary['corroboration'] = note
    summary['native_critical_high'] = len(native)


async def _quick_reachable(url: str, timeout: float = 10.0) -> bool:
    """One cheap GET to decide whether fan-out engines should even start.

    A host already blocking us answers with timeouts/refusals; hammering it
    with 10 more dalfox runs only extends the block and burns scan time.
    Any HTTP status (including WAF 403 or server 500) counts as reachable:
    the host answered. Only network errors/timeouts count as unreachable.
    """
    try:
        import aiohttp
        async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={'User-Agent': 'Mozilla/5.0 Athena-reachability-check'}) as session:
            async with session.get(url, ssl=False,
                                   allow_redirects=True) as resp:
                await resp.read()
                return True
    except Exception:
        return False


async def run_extended_tools(target: str,
                             args: argparse.Namespace = None,
                             scan_urls: List[str] = None) -> List[Dict[str, Any]]:
    """Run sqlmap/dalfox/wafw00f/httpx and report what happened.

    Each engine is optional: a missing binary prints one skip line and the
    scan continues exactly as before.  Evidence-backed findings (sqlmap,
    dalfox) use the scanner's own shape so they join AI triage and the
    exploitation runner untouched; wafw00f/httpx contribute context
    (WAF presence, probed hosts) with zero vulnerability findings.

    Never raises - a bridge error for one tool never blocks the others.
    """
    try:
        from modules.tool_bridge import (
            sqlmap_candidate_urls, tool_notice,
            SQLMAP_MAX_URLS, DALFOX_MAX_URLS,
        )
    except Exception as exc:  # pragma: no cover - import guard
        cprint(f"  [!] Extended tool bridge unavailable: {exc}")
        return []
    urls = [u for u in (scan_urls or []) if isinstance(u, str) and u.startswith(('http://', 'https://'))]
    if target and target not in urls:
        urls = [target] + urls
    if not urls and target:
        urls = [target]

    sqlmap_urls = sqlmap_candidate_urls(urls, SQLMAP_MAX_URLS) if urls else ([target] if target else [])
    dalfox_urls = [u for u in urls[:DALFOX_MAX_URLS]] if urls else ([target] if target else [])

    # Reachability gate: a host already blocking us (timeouts/refusals) gets
    # no 10-URL dalfox fan-out - that only extends the block. wafw00f/httpx
    # still try their single probe each below.
    reachable = await _quick_reachable(target) if target else True
    if target and not reachable:
        cprint(f"  [*] Target not answering (timeout/refused) - sqlmap/dalfox "
               f"fan-out skipped to avoid hammering a blocking host")
    _skip = {'tool': '', 'status': 'skipped', 'binary': '',
             'reason': 'target unreachable - fan-out skipped', 'findings': [],
             'matched': 0, 'duration_s': 0.0, 'argv': []}

    # sqlmap probes one URL per scan (bounded runtime); dalfox fans out over
    # up to DALFOX_MAX_URLS candidate URLs sequentially inside this phase.
    async def _run_sqlmap_phase():
        if not sqlmap_urls:
            return None
        if not reachable:
            return {**_skip, 'tool': 'sqlmap'}
        try:
            from modules.tool_bridge import run_sqlmap as _rs
            return await _rs(sqlmap_urls[0],
                             enabled=not getattr(args, 'no_sqlmap', False))
        except Exception as exc:
            cprint(f"  [!] Sqlmap bridge error: {exc}")
            return None

    async def _run_dalfox_phase():
        results: List[Dict[str, Any]] = []
        if not dalfox_urls:
            return results
        if not reachable:
            return [{**_skip, 'tool': 'dalfox'}]
        try:
            from modules.tool_bridge import run_dalfox as _rd
            disabled = bool(getattr(args, 'no_dalfox', False))
            for url in dalfox_urls:
                try:
                    summary = await _rd(url, enabled=not disabled)
                except Exception as exc:
                    cprint(f"  [!] Dalfox bridge error: {exc}")
                    continue
                if summary:
                    results.append(summary)
                if any(int(s.get('matched', 0) or 0) > 0 for s in results):
                    break  # one confirmed XSS is enough signal; keep phase bounded
        except Exception as exc:  # pragma: no cover
            cprint(f"  [!] Dalfox bridge error: {exc}")
        return results

    async def _run_waf_phase():
        try:
            from modules.tool_bridge import run_wafw00f as _rw
            return await _rw(target, enabled=not getattr(args, 'no_wafw00f', False))
        except Exception as exc:
            cprint(f"  [!] Wafw00f bridge error: {exc}")
            return None

    async def _run_httpx_phase():
        try:
            from modules.tool_bridge import run_httpx as _rh
            return await _rh(target, enabled=not getattr(args, 'no_httpx', False))
        except Exception as exc:
            cprint(f"  [!] Httpx bridge error: {exc}")
            return None

    sqlmap_summary, dalfox_list, waf_summary, httpx_summary = await asyncio.gather(
        _run_sqlmap_phase(), _run_dalfox_phase(), _run_waf_phase(), _run_httpx_phase())

    ordered: List[Dict[str, Any]] = []
    if sqlmap_summary:
        ordered.append(sqlmap_summary)
    # Collapse repeated dalfox unavailable/disabled into ONE record for
    # console + report (was printing 10x identical lines, one per URL).
    if dalfox_list:
        _statuses = {str(s.get('status', '')) for s in dalfox_list}
        if _statuses <= {'unavailable', 'disabled', 'skipped'}:
            ordered.append(dalfox_list[0])
        elif all(str(s.get('status')) == 'executed'
                 and int(s.get('matched', 0) or 0) == 0 for s in dalfox_list):
            # Repeated clean misses / unresponsive hosts: one summary row
            # with the probe count, not ten identical lines.
            _first = dict(dalfox_list[0])
            _first['urls_probed'] = len(dalfox_list)
            ordered.append(_first)
        else:
            # Keep executed/failed runs (they carry per-URL evidence)
            ordered.extend([s for s in dalfox_list if str(s.get('status')) not in ('unavailable', 'disabled', 'skipped')]
                           or dalfox_list[:1])
    if waf_summary:
        ordered.append(waf_summary)
    if httpx_summary:
        ordered.append(httpx_summary)
    for summary in ordered:
        try:
            notice = tool_notice(summary)
        except Exception:
            notice = ''
        if notice:
            cprint(notice)
    return ordered


async def run_bruteforce(target: str, discovery_results: Dict[str, Any] = None) -> Dict[str, Any]:
    con.phase("PHASE 3: BRUTEFORCING & AUTH TESTING")
    results: Dict[str, Any] = {'web_logins': [], 'service_creds': [], 'default_creds': [],
                               'admin_panels': [], 'spray_lockouts': []}
    login_forms = (discovery_results or {}).get('login_forms', [])
    admin_panels = (discovery_results or {}).get('admin_panels', [])
    ports = (discovery_results or {}).get('ports', [])
    scan_results = discovery_results or {}

    # Prioritize admin panels (cPanel, webmail, WHM) over regular login forms
    admin_login_forms = [f for f in login_forms if f.get('priority') == 'high' or f.get('form_type') == 'admin_login']
    regular_login_forms = [f for f in login_forms if f not in admin_login_forms]
    
    # Sort regular forms to skip low-value targets
    filtered_forms = [f for f in regular_login_forms if not any(kw in f.get('url', '').lower() for kw in ['register', 'signup', 'forgot', 'reset', 'create'])]
    
    if admin_login_forms:
        cprint(f"  [*] HIGH-VALUE TARGETS: {len(admin_login_forms)} admin panel login forms (cPanel/Webmail/WHM)")
        for i, form in enumerate(admin_login_forms, 1):
            source = form.get('source', 'UNKNOWN')
            cprint(f"      {i}. [{source}] {form['url']}")
    
    if admin_panels:
        # Dedupe: normalize trailing slash + case so /webmail, /webmail/,
        # /wp-login.php x2 don't count as 3 findings.
        _seen = set()
        _deduped = []
        for p in admin_panels or []:
            try:
                _u = str(p.get('url', '')).rstrip('/').lower()
                if not _u or _u in _seen:
                    continue
                _seen.add(_u)
                _deduped.append(p)
            except Exception:
                continue
        if len(_deduped) != len(admin_panels):
            cprint(f"  [*] Deduplicated admin panels: {len(admin_panels)} -> {len(_deduped)} unique")
        admin_panels = _deduped
        cprint(f"  [*] Discovered {len(admin_panels)} unique admin panels:")
        results['admin_panels'] = admin_panels
        for panel in admin_panels[:15]:
            panel_type = panel.get('panel_type', 'UNKNOWN')
            cprint(f"      - [{panel_type}] {panel['url']} (HTTP {panel['status']})")
        if len(admin_panels) > 15:
            cprint(f"      ... and {len(admin_panels)-15} more (see HTML report)")
    
    # Combine: admin panels first, then filtered regular forms
    all_forms = admin_login_forms + filtered_forms
    
    if all_forms:
        cprint(f"\n  [*] Bruteforcing {len(all_forms)} login forms ({len(admin_login_forms)} admin, {len(filtered_forms)} regular)...")
        
        # Use AI to analyze and prioritize forms
        from modules.ai_integration import AIIntegration
        ai_engine = AIIntegration()
        
        if ai_engine.enabled:
            cprint(f"  [*] AI analyzing target priority ({ai_engine.provider.value})...")
            try:
                prioritized = await ai_engine.prioritize_bruteforce_targets(all_forms)
                if prioritized:
                    all_forms = prioritized
                    cprint(f"  [+] AI prioritized targets for optimal efficiency")
            except Exception as e:
                cprint(f"  [-] AI prioritization failed, using default order: {e}")
        
        bf = BruteforceModule()
        try:
            # Admin panels (cPanel/Webmail/WHM) get the anti-lockout spray:
            # sequential attempts, 4-9s gaps, lockout abort, session-verified
            # success. Fast parallel hammering only earns an IP ban.
            if admin_login_forms:
                cprint(f"\n  [*] Phase 3a: Slow credential spray on admin panels "
                      f"(anti-lockout: sequential, 4-9s gaps, session-verified hits)...")
                spray = await bf.slow_spray(admin_login_forms)
                results['web_logins'].extend(spray.get('credentials', []))
                results['spray_lockouts'] = spray.get('lockouts', [])
                _st = spray.get('stats', {})
                _ncreds = len(spray.get('credentials', []))
                _nlock = len(spray.get('lockouts', []))
                cprint(f"  [*] Spray summary: {_st.get('attempts', 0)} attempt(s), "
                      f"{_st.get('forms', 0)} form(s), {_ncreds} verified success(es), "
                      f"{_nlock} lockout(s)")
                if _nlock:
                    cprint(f"  [!] Panel lockout active — remaining guesses must wait "
                          f"for the block to lift (manual retry, do not re-spray)")

            if filtered_forms:
                cprint(f"\n  [*] Phase 3b: Standard bruteforce on regular login forms...")
                creds = await bf.bruteforce_login_forms(filtered_forms)
                results['web_logins'].extend(creds)
        finally:
            await bf.close()
    else:
        # Distinguish "0 forms found (WAF-blind)" from "forms filtered".
        # Old message claimed registration-filtering when there was nothing.
        if not login_forms:
            cprint(f"  [*] No login forms captured (crawler WAF-blocked on 403; "
                  f"see [!] WAF warning above). High-value panels above remain manual targets - "
                  f"no automated credential attempts made (safe-mode, no false bruteforce).")
        else:
            cprint(f"  [*] No login forms to bruteforce after filtering registration/signup/forgot forms "
                  f"({len(login_forms)} raw forms seen, {len(filtered_forms)} after filter)")

    host = target.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    # TLS-aware + anonymous-first service testing on every important open port.
    # Plain bruteforce without TLS fails on modern mail servers (they refuse
    # AUTH over cleartext) — the SMTP/POP3/IMAP bruteforcers upgrade via
    # STARTTLS or wrap implicit-TLS ports. Anonymous/open access (FTP anon,
    # SMB guest, SMTP open relay, Redis NOAUTH, SNMP public) is probed FIRST
    # because it needs no guessing and is the real-world win.
    service_bf = ServiceBruteforcer()
    port_service_map = {
        21: 'ftp', 22: 'ssh', 23: 'telnet',
        25: 'smtp', 587: 'smtp', 465: 'smtp',
        110: 'pop3', 995: 'pop3', 143: 'imap', 993: 'imap',
        445: 'smb', 139: 'smb', 161: 'snmp',
        3306: 'mysql', 5432: 'postgresql', 1433: 'mssql', 6379: 'redis',
    }
    anon_services = {'ftp', 'smb', 'smtp', 'redis', 'snmp'}
    results['anonymous_findings'] = []
    for port, service in port_service_map.items():
        if port in ports:
            # 1. Anonymous / open access first (no guessing)
            if service in anon_services:
                try:
                    anon = await service_bf.check_anonymous(host, port, service)
                    if anon.get('anonymous'):
                        cprint(f"    [+] ANONYMOUS {service.upper()} on {host}:{port} — {anon.get('detail')}")
                        results['anonymous_findings'].append(anon)
                    else:
                        cprint(f"  [*] {service.upper()} {host}:{port}: {anon.get('detail','no anon access')}")
                except Exception as exc:
                    cprint(f"  [*] {service.upper()} anon check skipped on {port}: {exc}")
            # 2. TLS-aware default-credential test (STARTTLS/implicit-TLS inside)
            transport = ''
            if service in ('smtp', 'pop3', 'imap'):
                transport = ' (TLS-aware: STARTTLS/implicit-TLS)'
            cprint(f"  [*] Checking default credentials on {service}://{host}:{port}{transport}")
            try:
                creds = await service_bf.bruteforce_service(host, port, service, ['root', 'admin'], ['root', 'admin'])
            except Exception as exc:
                cprint(f"    [-] {service} bruteforce error on {port}: {exc}")
                continue
            results['service_creds'].extend(creds)
            for c in creds:
                if c.success:
                    cprint(f"    [+] Default credentials found: {c.username}:{c.password} on {service} ({host}:{port})")
    if not any(p in ports for p in port_service_map):
        cprint(f"  [*] No bruteforceable services among open ports {sorted(ports)[:20]} — web-form phase above is authoritative")

    return results


async def run_enumeration(target: str, ports: List[int] = None) -> Dict[str, Any]:
    con.phase("PHASE: ENUMERATION")
    results: Dict[str, Any] = {}
    host = target.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    port_map = {445: 'smb', 161: 'snmp', 25: 'smtp', 587: 'smtp', 465: 'smtp', 139: 'smb',
                110: 'pop3', 995: 'pop3', 143: 'imap', 993: 'imap'}

    if ports:
        for port in ports:
            service = port_map.get(port)
            # Key per host:port so 25/465/587 don't overwrite each other
            # (bug: last SMTP port wiped earlier results, report showed No).
            key = f"{service}_{port}" if service in ('smtp', 'pop3', 'imap') else (service or f"port_{port}")
            if service == 'smb':
                cprint(f"  [*] SMB enumeration on {host}:{port}")
                smb = SMBEnumerator()
                results[key] = await smb.enumerate(host, port)
                if results[key].get('accessible'):
                    cprint(f"    [+] SMB accessible: {results[key].get('os_version', 'unknown')}")
            elif service == 'snmp':
                cprint(f"  [*] SNMP enumeration on {host}:{port}")
                snmp = SNMPEnumerator()
                results[key] = await snmp.enumerate(host, port)
                if results[key].get('accessible'):
                    cprint(f"    [+] SNMP accessible, community: {results[key].get('community', 'N/A')}")
            elif service == 'smtp':
                cprint(f"  [*] SMTP enumeration on {host}:{port}")
                smtp = SMTPEnumerator()
                results[key] = await smtp.enumerate(host, port)
                if results[key].get('accessible'):
                    cprint(f"    [+] SMTP accessible ({results[key].get('transport', 'plain')}): {results[key].get('banner', '')[:60]}")
                # Back-compat alias: keep 'smtp' pointing at first accessible one
                if results[key].get('accessible') and not results.get('smtp', {}).get('accessible'):
                    results['smtp'] = results[key]
            elif service == 'pop3':
                cprint(f"  [*] POP3 enumeration on {host}:{port}")
                pop3 = POP3Enumerator()
                results[key] = await pop3.enumerate(host, port)
                if results[key].get('accessible'):
                    cprint(f"    [+] POP3 accessible: {results[key].get('banner', '')[:60]}")
                if results[key].get('accessible') and not results.get('pop3', {}).get('accessible'):
                    results['pop3'] = results[key]
            elif service == 'imap':
                cprint(f"  [*] IMAP enumeration on {host}:{port}")
                imap = IMAPEnumerator()
                results[key] = await imap.enumerate(host, port)
                if results[key].get('accessible'):
                    cprint(f"    [+] IMAP accessible: {results[key].get('banner', '')[:60]}")
                if results[key].get('accessible') and not results.get('imap', {}).get('accessible'):
                    results['imap'] = results[key]

    return results


async def run_cve_mapping(technologies: List[Dict[str, Any]]) -> List[VersionCVEResult]:
    con.phase("PHASE: CVE MAPPING")
    if not technologies:
        cprint(f"  [*] CVE mapping: no versioned technologies to map (tech detection empty)")
        return []
    try:
        _names = ', '.join([f"{t.get('technology','?')} {t.get('version','')}".strip() for t in technologies[:8]])
        cprint(f"  [*] Mapping {len(technologies)} technologies: {_names}")
    except Exception:
        pass
    cprint(f"  [*] Live NVD lookup: CPE match first, keyword fallback "
          f"(rate-limited 5 req/30s; set NVD_API_KEY for 50/30s)")
    mapper = CVEMapper()
    results = await mapper.map_versions(technologies)
    _with = sum(1 for r in results if r.cves)
    for r in results:
        if r.cves:
            cprint(f"  [+] {r.technology} {r.version}: {len(r.cves)} CVEs (max CVSS: {r.max_cvss})")
            for cve in r.cves[:3]:
                cprint(f"      - {cve.cve_id}: {cve.description[:80]}...")
    if not results:
        cprint(f"  [*] CVE mapping: no versioned technologies detected "
              f"(banner strings without versions cannot be mapped reliably)")
    elif not _with:
        cprint(f"  [*] CVE mapping: 0 CVEs for {len(results)} versioned technology(ies) "
              f"(live NVD queried; a clean result means no published matches, "
              f"not 'DB too small')")
    else:
        cprint(f"  [+] CVE mapping: {_with}/{len(results)} technologies matched, "
              f"{sum(len(r.cves) for r in results)} total candidate CVEs (live NVD + curated)")
    return results


def _service_banner_techs(enumeration: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Versions that only exist in service banners (Exim, Dovecot, OpenSSH).

    The web crawler never sees SMTP/POP3/IMAP banners, so versioned mail
    servers were invisible to CVE mapping (Exim 4.100.1 on the last scan
    mapped nothing).  Banner versions feed the same NVD lookup.
    """
    patterns = [
        (r'ESMTP\s+Exim\s+(\d+(?:\.\d+)+)', 'Exim'),
        (r'\bExim\s+(\d+(?:\.\d+)+)', 'Exim'),
        (r'Dovecot[ /\-]v?(\d+(?:\.\d+)+)', 'Dovecot'),
        (r'OpenSSH[_\s]v?(\d+(?:\.\d+p?\d+))', 'OpenSSH'),
        (r'Postfix\s*[-\s]v?(\d+(?:\.\d+)+)', 'Postfix'),
        (r'\bApache/(\d+(?:\.\d+)+)', 'Apache'),
        (r'\bnginx/(\d+(?:\.\d+)+)', 'nginx'),
    ]
    techs: List[Dict[str, Any]] = []
    seen = set()
    for data in (enumeration or {}).values():
        if not isinstance(data, dict) or not data.get('accessible'):
            continue
        banner = str(data.get('banner', ''))
        if not banner:
            continue
        for rx, product in patterns:
            m = re.search(rx, banner, re.IGNORECASE)
            if m and product.lower() not in seen:
                seen.add(product.lower())
                techs.append({'technology': product,
                              'version': m.group(1),
                              'confidence': 4,
                              'source': 'service_banner'})
    return techs


def generate_report(target: str, discovery: Dict[str, Any], vulnerabilities: List[Dict[str, Any]],
                    bruteforce: Dict[str, Any] = None, enumeration: Dict[str, Any] = None,
                    cve_results: List[VersionCVEResult] = None,
                    output_format: str = 'html', output_path: str = None,
                    ai_analysis: Dict[str, Any] = None,
                    exploitation: Dict[str, Any] = None,
                    external_tools: List[Dict[str, Any]] = None) -> str:
    report_gen = ReportGenerator()
    report_data = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'discovery': discovery,
        'vulnerabilities': vulnerabilities,
        'exploitation': (exploitation.get('attempts', [])
                         if isinstance(exploitation, dict)
                         else (exploitation or [])),
    }
    if ai_analysis:
        report_data['ai_analysis'] = ai_analysis
    if external_tools:
        # Collapse duplicate unavailable tool records (dalfox x10) so the
        # HTML table shows one row per tool-status, not one per probed URL.
        try:
            _seen_tool = set()
            _collapsed = []
            for s in external_tools:
                if not isinstance(s, dict):
                    continue
                _k = (str(s.get('tool', '')), str(s.get('status', '')))
                if _k[1] in ('unavailable', 'disabled', 'skipped') and _k in _seen_tool:
                    continue
                _seen_tool.add(_k)
                _collapsed.append(s)
            external_tools = _collapsed
        except Exception:
            pass
        report_data['external_tools'] = external_tools
    if bruteforce:
        report_data['bruteforce'] = bruteforce
    if enumeration:
        report_data['enumeration'] = enumeration
    if cve_results:
        cve_dicts = []
        for r in (cve_results or []):
            if r is None or not hasattr(r, 'technology'):
                continue
            cve_dicts.append({
                'technology': r.technology, 'version': r.version,
                'confidence': r.confidence,
                'cves': [{'cve_id': c.cve_id, 'description': c.description,
                          'cvss_score': c.cvss_score, 'exploit_available': c.exploit_available,
                          'kev': bool(getattr(c, 'kev', False)),
                          'kev_due_date': getattr(c, 'kev_due_date', '') or '',
                          'kev_name': getattr(c, 'kev_name', '') or ''}
                         for c in (r.cves or []) if c is not None],
                'max_cvss': r.max_cvss,
            })
        report_data['cve_mapping'] = cve_dicts
        try:
            kev_ids = [c.get('cve_id') for d in cve_dicts for c in d.get('cves', [])
                       if isinstance(c, dict) and c.get('kev')]
            if kev_ids:
                report_data['kev_summary'] = {'kev_count': len(kev_ids),
                                              'kev_ids': sorted(set(kev_ids))}
        except Exception:
            pass

    report = report_gen.generate_comprehensive_report(report_data)

    safe_name = target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
    if not output_path:
        output_path = f"report_{safe_name}"

    if output_format in ('html', 'all'):
        html_content = _generate_html_report(report)
        html_path = f"{output_path}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        cprint(f"  [+] HTML report: {html_path}")

    if output_format in ('json', 'all'):
        json_path = f"{output_path}.json"
        report_gen.export_to_json(report, json_path)
        cprint(f"  [+] JSON report: {json_path}")

    if output_format in ('csv', 'all'):
        csv_path = f"{output_path}.csv"
        report_gen.export_to_csv(report_data, csv_path)
        cprint(f"  [+] CSV report: {csv_path}")

    if output_format in ('pdf', 'all'):
        pdf_path = f"{output_path}.pdf"
        ok = report_gen.generate_pdf_report(report, pdf_path)
        if ok:
            cprint(f"  [+] PDF report: {pdf_path}")
        else:
            cprint("  [!] PDF report skipped (reportlab not installed) - "
                  "run: pip install reportlab, or use -o html/json/csv")

    return output_path


def _generate_html_report(report: Dict[str, Any]) -> str:
    report = report if isinstance(report, dict) else {}
    audit = report.get('athena_security_audit') or report
    if not isinstance(audit, dict):
        audit = {}
    summary = audit.get('audit_summary') or {}
    if not isinstance(summary, dict):
        summary = {}
    sev = summary.get('severity_breakdown') or {}
    if not isinstance(sev, dict):
        sev = {}
    vulns = audit.get('detailed_analysis') or {}
    if not isinstance(vulns, dict):
        vulns = {}

    critical_count = sev.get('critical', 0)
    high_count = sev.get('high', 0)
    medium_count = sev.get('medium', 0)

    # Expanded vulnerability cards: broad description, proof, remediation.
    # Inconclusive runner results are grouped into a single note per type —
    # never full rows (they are "not sure", not findings).
    vuln_rows = ''
    inconclusive_note_total = 0
    for vtype, vinfo in vulns.items():
        if not isinstance(vinfo, dict):
            continue
        s = vinfo.get('severity', 'UNKNOWN')
        color = {'CRITICAL': '#ff4444', 'HIGH': '#ff8800', 'MEDIUM': '#ffbb33', 'LOW': '#ffdd55'}.get(s, '#999')
        assets = '<br>'.join(f"<code>{html.escape(str(a))}</code>" for a in (vinfo.get('assets_affected') or [])[:5])
        techniques = ''.join(f"<li>{html.escape(str(t))}</li>" for t in (vinfo.get('attack_techniques') or []))
        tools = html.escape(', '.join(vinfo.get('tools') or []))
        gains = html.escape(str(vinfo.get('attacker_gains', '')))
        desc_full = html.escape(str(vinfo.get('description', '')))
        remediation = html.escape(str(vinfo.get('remediation', '')))
        timeline = html.escape(str(vinfo.get('timeline', 'Scheduled')))
        vcount = int(vinfo.get('verified_count', 0) or 0)

        confirmed_findings = [f for f in (vinfo.get('confirmed_findings') or []) if isinstance(f, dict)]
        # Split proven vs unverified vs inconclusive
        proven = [f for f in confirmed_findings if f.get('verified')]
        inconc = [f for f in confirmed_findings if str(f.get('verification_status', '')).lower() == 'inconclusive']
        unver = [f for f in confirmed_findings if not f.get('verified') and str(f.get('verification_status', '')).lower() != 'inconclusive']
        inconclusive_note_total += len(inconc)

        def _row(f, badge, badge_color):
            return (f"<tr><td><span class=\"sev-badge\" style=\"background:{badge_color}\">{badge}</span></td>"
                    f"<td><code>{html.escape(str(f.get('url', '')))}</code></td>"
                    f"<td><code>{html.escape(str(f.get('payload', ''))[:300])}</code></td>"
                    f"<td>{html.escape(str(f.get('description', ''))[:600])}"
                    + (f"<br><em>Evidence: {html.escape(str(f.get('evidence', ''))[:300])}</em>" if f.get('evidence') else '')
                    + (f"<br><span class=\"conf\">confidence: {html.escape(str(f.get('confidence', '')))}</span>" if f.get('confidence') else '')
                    + "</td></tr>")

        findings_html = ''
        if proven:
            findings_html += ('<div class="confirmed-findings proven"><strong>'
                              f'Confirmed proof ({len(proven)}): double-probed, differential evidence — trusted.</strong>'
                              '<table class="findings-table">'
                              '<tr><th>Status</th><th>Affected URL</th><th>Payload / proof</th><th>What was proven + evidence</th></tr>')
            for f in proven[:10]:
                findings_html += _row(f, 'CONFIRMED', '#2e7d32')
            findings_html += '</table></div>'
        if unver:
            findings_html += ('<div class="confirmed-findings unverified"><strong>'
                              f'Unverified observations ({len(unver)}): scanner detection, needs manual re-test — treat as leads, not breaches.</strong>'
                              '<table class="findings-table">'
                              '<tr><th>Status</th><th>Affected URL</th><th>Payload</th><th>Why it is only a lead</th></tr>')
            for f in unver[:8]:
                findings_html += _row(f, 'UNVERIFIED', '#8a6d00')
            findings_html += '</table></div>'
        if inconc:
            findings_html += (f'<div class="inconclusive-note">Inconclusive re-tests for this type: '
                              f'<strong>{len(inconc)}</strong> — the exploitation runner could not reproduce them '
                              f'(no proof). They are <strong>not listed as findings</strong>; re-test manually before acting.</div>')

        vuln_rows += f"""
        <tr class="vuln-card">
            <td><span class="sev-badge" style="background:{color}">{html.escape(str(s))}</span><br>
                <span class="conf">proven: {vcount}</span></td>
            <td><strong>{html.escape(str(vtype))}</strong></td>
            <td class="assets">{assets or '<em>—</em>'}</td>
            <td class="desc"><p class="desc-text">{desc_full}</p>
                {findings_html}
                <details class="attack-details" open>
                    <summary>How an attacker compromises this (step-by-step)</summary>
                    <ol class="attack-steps">{techniques}</ol>
                    <p><strong>Attacker gains:</strong> {gains}</p>
                    <p><strong>Tools an attacker uses:</strong> {tools}</p>
                </details>
                <div class="remediation"><strong>Fix:</strong> {remediation}<br>
                <em>Timeline: {timeline}</em></div>
            </td>
        </tr>"""

    tech_items = ''
    _df = audit.get('discovery_findings') or {}
    if not isinstance(_df, dict):
        _df = {}
    for t in (_df.get('technologies_with_confidence') or []):
        if not isinstance(t, dict):
            continue
        tech_items += f"<li>{t.get('technology')} (confidence: {t.get('confidence')})</li>"
    if not tech_items:
        for t in (_df.get('technologies') or []):
            if t is None:
                continue
            tech_items += f"<li>{t}</li>"

    rec_items = ''
    for r in (audit.get('remediation_recommendations') or []):
        if not isinstance(r, dict):
            continue
        rec_items += f"""
        <div class="rec-item">
            <strong>{r.get('issue')}</strong> ({r.get('severity')})<br>
            {r.get('recommendation')}
            <em>Timeline: {r.get('timeline')}</em>
        </div>"""

    no_findings = audit.get('no_vulnerabilities_found', False)
    asset_summary = summary.get('assets_discovered') or {}
    if not isinstance(asset_summary, dict):
        asset_summary = {}
    asset_text = (f"{asset_summary.get('open_ports', 0)} open ports, "
                  f"{asset_summary.get('urls', 0)} URLs, "
                  f"{asset_summary.get('subdomains', 0)} subdomains, "
                  f"{asset_summary.get('technologies', 0)} technologies")

    discovery_findings = audit.get('discovery_findings') or {}
    if not isinstance(discovery_findings, dict):
        discovery_findings = {}
    # "not scanned" (recon phase never ran in this mode) is a different
    # claim from "scanned, nothing found" - never conflate the two.
    recon_ran = bool(discovery_findings.get('ran'))
    empty_msg = ('<em>Not scanned in this mode (run -m full or -m discovery)</em>'
                 if not recon_ran else '<em>None detected</em>')
    port_items = ''.join(f"<li>{p}</li>" for p in discovery_findings.get('open_ports', [])[:50])
    url_items = ''.join(f"<li>{html.escape(str(u))}</li>" for u in discovery_findings.get('urls', [])[:50])
    sub_items = ''.join(f"<li>{html.escape(str(s))}</li>" for s in discovery_findings.get('subdomains', [])[:50])
    if not recon_ran:
        tech_items = tech_items or '<em>Not scanned in this mode (run -m full or -m discovery)</em>'

    # Dedupe admin panels for display (defense in depth; source already dedupes)
    _admin_seen = set()
    _admin_unique = []
    for p in (discovery_findings.get('admin_panels') or []):
        try:
            if not isinstance(p, dict):
                continue
            _k = str((p or {}).get('url', '')).rstrip('/').lower()
            if not _k or _k in _admin_seen:
                continue
            _admin_seen.add(_k)
            _admin_unique.append(p)
        except Exception:
            continue
    admin_items = ''.join(
        f"<li><strong>[{html.escape(str(p.get('panel_type', 'UNKNOWN')))}]</strong> "
        f"<code>{html.escape(str(p.get('url', '')))}</code> "
        f"(HTTP {html.escape(str(p.get('status', '')))})</li>"
        for p in _admin_unique[:50] if isinstance(p, dict)
    )
    admin_section = (f"<h2>Admin Panels &amp; High-Value Targets</h2><ul>{admin_items}</ul>"
                     if admin_items else "")

    # --- DNS & email hygiene (SPF/DMARC proven from live DNS lookups) ---
    dns_data = discovery_findings.get('dns_records') or {}
    if not isinstance(dns_data, dict):
        dns_data = {}
    tls_data = discovery_findings.get('tls_certificate') or {}
    if not isinstance(tls_data, dict):
        tls_data = {}
    dns_section = ''
    if dns_data or tls_data:
        def _kv_row(label, value, danger=False):
            color = ' style="color:#ff4444;font-weight:bold;"' if danger else ''
            return (f"<tr><td><strong>{html.escape(str(label))}</strong></td>"
                    f"<td{color}>{value}</td></tr>")
        _rows = ''
        if dns_data:
            _dmarc = str(dns_data.get('dmarc_analysis')
                         or ('DMARC record present' if dns_data.get('dmarc_record')
                             else 'Not queried'))
            _spf = str(dns_data.get('spf_analysis')
                       or ('SPF record present' if dns_data.get('spf_record')
                           else 'Not queried'))
            _ip = str(dns_data.get('ip')
                      or (', '.join(str(a) for a in (dns_data.get('a_records') or [])[:3]) or 'n/a'))
            _mx = [m for m in (dns_data.get('mx_records') or []) if m is not None]
            _mx_text = (', '.join(str(m.get('exchange', m)) if isinstance(m, dict) else str(m) for m in _mx[:4])
                        if _mx else 'none (email receiving may be external)')
            _rows += _kv_row('Domain', html.escape(str(dns_data.get('domain', ''))))
            _rows += _kv_row('IP (A record)', html.escape(_ip))
            _rows += _kv_row('Mail exchangers (MX)',
                             html.escape(str(_mx_text)) if _mx else _mx_text,
                             danger=not bool(_mx))
            _rows += _kv_row('SPF', html.escape(_spf),
                             danger='no spf' in _spf.lower() or 'missing' in _spf.lower())
            _rows += _kv_row('DMARC', html.escape(_dmarc),
                             danger=('no dmarc' in _dmarc.lower()
                                     or 'missing' in _dmarc.lower()))
        if tls_data:
            _issues = tls_data.get('issues') or []
            _tls_txt = (f"{tls_data.get('version', '?')} / "
                        f"expires {tls_data.get('valid_until', '?')}")
            if _issues:
                _tls_txt += f" — {len(_issues)} issue(s): {html.escape(str(_issues[0]))[:150]}"
            _rows += _kv_row('TLS certificate', html.escape(_tls_txt),
                             danger=bool(_issues))
        dns_section = f"""
    <h2>DNS &amp; Email Security (live lookups)</h2>
    <table><thead><tr><th>Check</th><th>Result</th></tr></thead>
    <tbody>{_rows}</tbody></table>"""

    # --- Confirmed exposed files: listing harvest + direct-probed backups ---
    file_rows = ''
    _lh = discovery_findings.get('listing_harvest') or {}
    for f in (_lh.get('findings') or []):
        file_rows += (
            f"<tr><td><span class=\"sev-badge\" style=\"background:#2e7d32\">CONFIRMED</span></td>"
            f"<td>Directory-listing harvest</td>"
            f"<td><code>{html.escape(str(f.get('url', '')))}</code></td>"
            f"<td>{html.escape(str(f.get('description', '')))}</td>"
            f"<td><code>{html.escape(str(f.get('evidence', '')))}</code></td></tr>")
    _ha = discovery_findings.get('hidden_assets') or {}
    for b in (_ha.get('backup_files') or [])[:30]:
        file_rows += (
            f"<tr><td><span class=\"sev-badge\" style=\"background:#2e7d32\">CONFIRMED</span></td>"
            f"<td>Backup direct-probe ({html.escape(str(b.get('backup_type', '')))})</td>"
            f"<td><code>{html.escape(str(b.get('url', '')))}</code></td>"
            f"<td>{html.escape(str(b.get('what_it_leaks', 'Backup file accessible')))}</td>"
            f"<td><code>{html.escape(str(b.get('proof', '')))}</code></td></tr>")
    exposed_section = ''
    if file_rows:
        exposed_section = f"""
    <h2>Confirmed Exposed Files (direct fetch + content proof)</h2>
    <p>Every row below was <strong>fetched and content-sniffed</strong> (archive
    magic, SQL/PHP markers, KEY=VALUE config) — not guessed from a status code.</p>
    <table><thead><tr><th>Status</th><th>Method</th><th>URL</th><th>What it is</th><th>Proof</th></tr></thead>
    <tbody>{file_rows}</tbody></table>"""

    # --- WAF gate section (Phase 0, runs first) ---
    _waf = (audit.get('discovery_findings', {}) or {}).get('waf') or audit.get('waf') or {}
    # discovery stores waf under discovery_results['waf']; surface it here
    try:
        _dw = (report.get('athena_security_audit', {}).get('discovery_findings', {}) or {}).get('waf')
        if _dw and not _waf:
            _waf = _dw
    except Exception:
        pass
    waf_section = ''
    if _waf and isinstance(_waf, dict) and _waf.get('verdict'):
        _wv = html.escape(str(_waf.get('verdict', '')))
        _wn = html.escape(str(_waf.get('waf', 'unknown') or 'unknown'))
        _wt = html.escape(str(_waf.get('tuning', '')))
        _wconf = html.escape(str(_waf.get('confidence', '')))
        _wcolor = {'confirmed': '#ff4444', 'likely': '#ff8800', 'hard-block': '#ff8800', 'none': '#2e7d32'}.get(str(_waf.get('verdict', '')), '#888')
        waf_section = f"""
    <h2>WAF Gate (Phase 0 — ran first)</h2>
    <table><thead><tr><th>Verdict</th><th>WAF</th><th>Confidence</th><th>Tuning applied</th></tr></thead>
    <tbody><tr><td><span class="sev-badge" style="background:{_wcolor}">{_wv.upper()}</span></td>
    <td>{_wn}</td><td>{_wconf}</td><td>{_wt}</td></tr></tbody></table>"""

    # --- Consolidated phase sections (credentials, services, CVEs, AI) ---
    bf = audit.get('bruteforce_findings', {}) or {}
    bf_section = ''
    web_creds = bf.get('successful_web_logins', [])
    svc_creds = bf.get('successful_service_logins', [])
    anon_acc = bf.get('anonymous_access', []) or []
    if web_creds or svc_creds or anon_acc or bf.get('admin_panels') or bf.get('spray_lockouts'):
        rows = ''
        for cred in web_creds[:20]:
            rows += (f"<tr><td>Web form</td><td><code>{html.escape(str(cred.get('url', '')))}</code></td>"
                     f"<td>{html.escape(str(cred.get('username', '')))}</td>"
                     f"<td><code>{html.escape(str(cred.get('password', '')))}</code></td></tr>")
        for cred in svc_creds[:20]:
            target = f"{cred.get('host', '')}:{cred.get('port', '')}"
            rows += (f"<tr><td>{html.escape(str(cred.get('service', '')))}</td>"
                     f"<td><code>{html.escape(str(target))}</code></td>"
                     f"<td>{html.escape(str(cred.get('username', '')))}</td>"
                     f"<td><code>{html.escape(str(cred.get('password', '')))}</code></td></tr>")
        cred_table = (
            f"<table><thead><tr><th>Service</th><th>Target</th>"
            f"<th>Username</th><th>Password</th></tr></thead><tbody>{rows}</tbody></table>"
        ) if rows else "<p><em>No valid credentials recovered.</em></p>"
        anon_html = ''
        if anon_acc:
            anon_rows = ''.join(
                f"<tr><td><span class=\"sev-badge\" style=\"background:#ff4444\">ANON</span></td>"
                f"<td>{html.escape(str(a.get('service', '')))}</td>"
                f"<td><code>{html.escape(str(a.get('host', '')))}:{html.escape(str(a.get('port', '')))}</code></td>"
                f"<td>{html.escape(str(a.get('detail', '')))}</td></tr>"
                for a in anon_acc[:20] if isinstance(a, dict))
            anon_html = (f"<h3>Anonymous / open access (no guessing needed — highest priority)</h3>"
                         f"<table><thead><tr><th>Result</th><th>Service</th><th>Target</th><th>Detail</th></tr></thead>"
                         f"<tbody>{anon_rows}</tbody></table>")
        else:
            anon_html = ("<p><em>No anonymous/open service access found (FTP anon, SMB guest, SMTP open relay, "
                         "Redis NOAUTH, SNMP public all probed with TLS awareness).</em></p>")
        lockouts = bf.get('spray_lockouts', []) or []
        lockout_html = ''
        if lockouts:
            lk_rows = ''.join(
                f"<tr><td><span class=\"sev-badge\" style=\"background:#8a6d00\">LOCKOUT</span></td>"
                f"<td><code>{html.escape(str(l.get('url', '')))}</code></td>"
                f"<td>{html.escape(str(l.get('detail', '')))}</td></tr>"
                for l in lockouts if isinstance(l, dict))
            lockout_html = (f"<h3>Panel lockouts triggered (spray aborted - retry manually later)</h3>"
                            f"<table><thead><tr><th>Result</th><th>Target</th><th>Detail</th></tr>"
                            f"<tbody>{lk_rows}</tbody></table>")
        bf_section = f"""
    <h2>Authentication &amp; Credential Testing</h2>
    <p>Login forms tested plus TLS-aware service auth (SMTP/POP3/IMAP upgrade via STARTTLS or implicit TLS; "
    "plain bruteforce without TLS fails on modern servers and is not attempted blindly). "
    "Anonymous/open access is probed <strong>before</strong> guessing. Admin panels use a slow anti-lockout "
    "spray (sequential, 4-9s gaps) where every hit is re-verified with a follow-up session check. "
    "Any credential row below is a confirmed login.</p>
    {anon_html}
    {lockout_html}
    {cred_table}"""

    enum = audit.get('service_enumeration', {}) or {}
    if enum:
        enum_rows = ''.join(
            f"<tr><td>{html.escape(str(svc))}</td>"
            f"<td>{'Yes' if data.get('accessible') else 'No'}</td>"
            f"<td><code>{html.escape(str(data.get('banner', ''))[:200])}</code></td></tr>"
            for svc, data in enum.items() if isinstance(data, dict)
        )
        enum_section = f"""
    <h2>Service Enumeration</h2>
    <table><thead><tr><th>Service</th><th>Accessible</th><th>Banner</th></tr></thead>
    <tbody>{enum_rows}</tbody></table>"""
    else:
        enum_section = ''

    cve_rows_list = [e for e in (audit.get('cve_mapping') or []) if isinstance(e, dict)]
    if cve_rows_list:
        rows = ''
        for entry in cve_rows_list:
            cves = [c for c in (entry.get('cves') or []) if isinstance(c, dict)]
            cve_items = ''
            for c in cves[:5]:
                kev_badge = ''
                if c.get('kev'):
                    due = html.escape(str(c.get('kev_due_date', '')))
                    kev_badge = (' <strong style="color:#ff4444;">[KEV - exploited in the wild'
                                 + (f', patch due {due}' if due else '') + ']</strong>')
                cve_items += (
                    f"<li><code>{html.escape(str(c.get('cve_id', '')))}</code> "
                    f"(CVSS {html.escape(str(c.get('cvss_score', '')))}) - "
                    f"{html.escape(str(c.get('description', ''))[:160])}{kev_badge}</li>")
            rows += (f"<tr><td>{html.escape(str(entry.get('technology', '')))}</td>"
                     f"<td>{html.escape(str(entry.get('version', '') or 'unknown'))}</td>"
                     f"<td><ul>{cve_items or '<li><em>No mapped CVEs</em></li>'}</ul></td></tr>")
        kev_note = ''
        try:
            kev_total = sum(1 for e in cve_rows_list for c in (e.get('cves') or []) if isinstance(c, dict) and c.get('kev'))
            if kev_total:
                kev_note = (f"<p><strong style=\"color:#ff4444;\">{kev_total} CVE(s) are on the "
                            f"CISA KEV catalog (exploited in the wild) - patch first.</strong></p>")
        except Exception:
            kev_note = ''
        cve_section = f"""
    <h2>CVE Mapping (version-based)</h2>
    {kev_note}
    <table><thead><tr><th>Technology</th><th>Version</th><th>Candidate CVEs</th></tr></thead>
    <tbody>{rows}</tbody></table>"""
    else:
        cve_section = ''

    tools = [e for e in (audit.get('external_tools') or []) if isinstance(e, dict)]
    if tools:
        tool_rows = ''
        for entry in tools:
            status = str(entry.get('status', ''))
            try:
                matched = int(entry.get('matched', 0) or 0)
            except (TypeError, ValueError):
                matched = 0
            if status == 'executed':
                tool_name = str(entry.get('tool', ''))
                if tool_name == 'nuclei':
                    detail = (f"{matched} template match(es) "
                              f"(severity filter: {entry.get('severity_filter', '')})")
                    if int(entry.get('errors') or 0):
                        detail += (f"; {int(entry['errors'])} error(s) - "
                                   f"unreachable templates are not a clean miss")
                    if entry.get('corroboration'):
                        detail += f"; {entry['corroboration']}"
                elif tool_name == 'sqlmap':
                    detail = (f"{matched} injectable parameter(s) "
                              f"at {entry.get('target', '')}")
                elif tool_name == 'dalfox':
                    detail = (f"{matched} XSS finding(s) "
                              f"at {entry.get('target', '')}")
                elif tool_name == 'wafw00f':
                    if entry.get('waf_detected'):
                        detail = f"WAF detected: {entry.get('waf', 'unknown')}"
                    else:
                        detail = 'no WAF detected'
                elif tool_name == 'httpx':
                    probed = entry.get('hosts_probed', len(entry.get('hosts') or []))
                    detail = f"{probed} host(s) probed (recon enrichment)"
                else:
                    detail = f"{matched} finding(s)"
                    if entry.get('corroboration'):
                        detail += f"; {entry['corroboration']}"
            else:
                detail = str(entry.get('reason', '') or status)
            tool_rows += (f"<tr><td>{html.escape(str(entry.get('tool', '')))}</td>"
                          f"<td>{html.escape(status)}</td>"
                          f"<td>{html.escape(detail)}</td>"
                          f"<td><code>{html.escape(str(entry.get('binary', '')))}</code></td></tr>")
        tool_section = f"""
    <h2>External Tool Runs</h2>
    <table><thead><tr><th>Tool</th><th>Status</th><th>Result</th><th>Binary</th></tr></thead>
    <tbody>{tool_rows}</tbody></table>"""
    else:
        tool_section = ''

    ai = audit.get('ai_assistant') or {}
    if not isinstance(ai, dict):
        ai = {}
    ai_section = ''
    if ai:
        _cons = ai.get('consolidation') or {}
        if not isinstance(_cons, dict):
            _cons = {}
        fp_rows = ''.join(
            f"<tr><td>{html.escape(str(f.get('type', '')))}</td>"
            f"<td><code>{html.escape(str(f.get('url', '')))}</code></td>"
            f"<td>{html.escape(str(f.get('reason', ''))[:200])}</td>"
            f"<td>{f.get('confidence', '')}</td></tr>"
            for f in (ai.get('false_positive_details') or [])[:20] if isinstance(f, dict)
        )
        ai_section = f"""
    <h2>AI Advisory Notes</h2>
    <p>Provider: <code>{html.escape(str(ai.get('provider', '')))}</code>
       / <code>{html.escape(str(ai.get('model', '')))}</code>.
       <strong>Advisory only</strong> - the model flags suspected false
       positives for review; flagged findings are excluded from active
       testing/exploitation but never deleted (see the table below).
       Deterministic validation remains authoritative.
        Statements: {ai.get('statement_count', 0)}.
        Consolidated {_cons.get('raw_findings', 0)} raw detections into
        {_cons.get('unique_findings', 0)} unique findings.</p>
    {'<table><thead><tr><th>Type</th><th>URL</th><th>AI reason</th><th>Conf.</th></tr></thead><tbody>' + fp_rows + '</tbody></table>' if fp_rows else '<p><em>No false-positive hypotheses raised.</em></p>'}"""

    exploit_section = ''
    attempts = [a for a in (audit.get('exploitation_attempts') or []) if isinstance(a, dict)]
    if attempts:
        attempt_rows = ''
        badge = {'confirmed': '#2e7d32', 'possible': '#b8860b', 'inconclusive': '#4a4a5a'}
        for a in attempts:
            attempt_status = str(a.get('status', 'inconclusive'))
            colour = badge.get(attempt_status, '#4a4a5a')
            attempt_rows += (
                f"<tr><td><span class=\"sev-badge\" style=\"background:{colour}\">"
                f"{html.escape(attempt_status.upper())}</span></td>"
                f"<td>{html.escape(str(a.get('type', '')))}</td>"
                f"<td><code>{html.escape(str(a.get('url', '')))}</code></td>"
                f"<td>{html.escape(str(a.get('detail', '')))}</td></tr>")
        exploit_section = f"""
    <h2>Automated Exploitation</h2>
    <p>Every row below was actively re-tested by the exploitation runner
       (scope-gated, evidence required). <strong>confirmed</strong> = the handler
       reproduced the issue and produced proof; <strong>inconclusive</strong> =
       no proof could be produced, treat the finding as unverified.</p>
    <p>Attempted: <strong>{summary.get('exploitation_attempted', 0)}</strong> |
       Confirmed: <strong>{summary.get('exploitation_confirmed', 0)}</strong> |
       Possible: <strong>{summary.get('exploitation_possible', 0)}</strong> |
       Inconclusive: <strong>{summary.get('exploitation_inconclusive', 0)}</strong> |
       Demonstrations in this report: <strong>{summary.get('successful_demonstrations', 0)}</strong></p>
    <table>
        <thead><tr><th>Result</th><th>Type</th><th>URL</th><th>Evidence / reason</th></tr></thead>
        <tbody>{attempt_rows}</tbody>
    </table>"""
    elif summary.get('exploitation_attempted', 0) == 0 and 'exploitation_attempted' in summary:
        exploit_section = """
    <h2>Automated Exploitation</h2>
    <p><em>No findings were actively re-tested: nothing matched a supported
    exploit handler, or exploitation was disabled/not authorized for this
    target. Findings below are scanner detections only.</em></p>"""

    banner = ""
    trunc = summary.get('findings_truncated', {})
    if trunc:
        banner = f"""
    <div style="background:#3a2a0f;border:1px solid #b8860b;padding:16px;border-radius:8px;margin-bottom:30px;">
        <strong style="color:#ffbb33;">Findings itemization capped</strong>
        <p style="margin-top:6px;color:#e0d6b8;">{html.escape(str(trunc.get('note', '')))}</p>
    </div>"""
    if no_findings:
        banner = f"""
    <div style="background:#0f2a1c;border:1px solid #2e7d32;padding:20px;border-radius:8px;margin-bottom:30px;">
        <strong style="color:#66bb6a;font-size:1.2em;">No vulnerabilities detected</strong>
        <p style="margin-top:8px;color:#c8e6c9;">The automated assessment did not identify any exploitable
        vulnerabilities on the target. Discovered assets: <strong>{asset_text}</strong>.</p>
    </div>"""

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Athena Security Audit - {audit.get('target', 'Unknown')}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0a0a0f; color: #e0e0e0; line-height: 1.65; font-size: 15px; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
.header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 40px; border-radius: 10px; margin-bottom: 30px; text-align: center; }}
.header h1 {{ color: #00d2ff; font-size: 2em; }}
.header .meta {{ color: #888; margin-top: 10px; }}
.summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
.card {{ background: #1a1a2e; padding: 20px; border-radius: 8px; text-align: center; }}
.card.critical {{ border-top: 3px solid #ff4444; }}
.card.high {{ border-top: 3px solid #ff8800; }}
.card.medium {{ border-top: 3px solid #ffbb33; }}
.card .number {{ font-size: 2.5em; font-weight: bold; }}
.card.critical .number {{ color: #ff4444; }}
.card.high .number {{ color: #ff8800; }}
.card.medium .number {{ color: #ffbb33; }}
.card .label {{ color: #888; font-size: 0.9em; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; }}
th {{ background: #1a1a2e; padding: 12px; text-align: left; font-weight: 600; color: #00d2ff; }}
td {{ padding: 10px 12px; border-bottom: 1px solid #222; }}
tr:hover {{ background: #111122; }}
.sev-badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; color: #fff; font-size: 0.8em; font-weight: bold; }}
h2 {{ color: #00d2ff; margin: 30px 0 15px; padding-bottom: 8px; border-bottom: 1px solid #222; }}
.rec-item {{ background: #1a1a2e; padding: 15px; border-radius: 6px; margin-bottom: 10px; border-left: 3px solid #00d2ff; }}
.rec-item em {{ display: block; color: #888; margin-top: 5px; font-size: 0.9em; }}
.attack-details {{ margin-top: 10px; padding: 10px; background: #14142a; border-radius: 6px; }}
.attack-details summary {{ cursor: pointer; color: #00d2ff; font-weight: 600; }}
.attack-steps {{ margin: 10px 0 10px 20px; }}
.attack-steps li {{ padding: 3px 0; }}
ul {{ list-style: none; }}
li {{ padding: 4px 0; }}
li::before {{ content: "▸"; color: #00d2ff; margin-right: 8px; }}
.chart {{ margin: 20px 0; height: 20px; border-radius: 10px; overflow: hidden; display: flex; }}
.chart .segment {{ height: 100%; transition: width 0.5s; }}
.confirmed-findings {{ margin: 12px 0; padding: 12px; background: #0d1117; border-radius: 8px; border: 1px solid #30363d; }}
.confirmed-findings.proven {{ border-color: #2e7d32; }}
.confirmed-findings.unverified {{ border-color: #8a6d00; }}
.findings-table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.9em; table-layout: fixed; }}
.findings-table th {{ background: #161b22; padding: 8px 10px; text-align: left; font-weight: 600; color: #58a6ff; border-bottom: 1px solid #30363d; }}
.findings-table th:nth-child(1) {{ width: 110px; }} .findings-table th:nth-child(2) {{ width: 26%; }}
.findings-table th:nth-child(3) {{ width: 26%; }} .findings-table th:nth-child(4) {{ width: auto; }}
.findings-table td {{ padding: 8px 10px; border-bottom: 1px solid #21262d; word-break: break-word; vertical-align: top; line-height: 1.5; }}
.findings-table tr:hover {{ background: #1c2128; }}
.findings-table code {{ color: #79c0ff; font-size: 0.88em; background: #161b22; padding: 2px 5px; border-radius: 3px; word-break: break-all; }}
.vuln-card td.desc {{ min-width: 0; }}
.desc-text {{ font-size: 1.02em; line-height: 1.7; margin-bottom: 10px; color: #e8e8e8; }}
.assets code {{ display: inline-block; margin: 2px 0; }}
.conf {{ font-size: 0.8em; color: #9aa; }}
.remediation {{ margin-top: 10px; padding: 10px 12px; background: #0f2a1c; border-left: 3px solid #2e7d32; border-radius: 6px; }}
.inconclusive-note {{ margin-top: 8px; padding: 8px 10px; background: #1a1a2e; border: 1px dashed #555; border-radius: 6px; color: #aaa; font-size: 0.9em; }}
table.vuln-main {{ table-layout: fixed; }}
table.vuln-main th:nth-child(1) {{ width: 90px; }} table.vuln-main th:nth-child(2) {{ width: 170px; }}
table.vuln-main th:nth-child(3) {{ width: 220px; }} table.vuln-main th:nth-child(4) {{ width: auto; }}
table.vuln-main td {{ vertical-align: top; }}
@media print {{ body {{ background: #fff; color: #000; }} .header {{ background: #eee; }} .card {{ background: #f5f5f5; }} th {{ background: #ddd; color: #000; }} .rec-item {{ background: #f5f5f5; border-left-color: #333; }} .confirmed-findings {{ background: #f0f0f0; border-color: #ccc; }} .findings-table th {{ background: #e0e0e0; color: #000; }} }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Athena Security Audit Report</h1>
        <div class="meta">Target: {audit.get('target', 'Unknown')}</div>
        <div class="meta">Date: {audit.get('timestamp', 'N/A')}</div>
        <div class="meta">Risk Rating: <strong>{summary.get('risk_rating', 'N/A')}</strong></div>
    </div>
    {banner}

    <div class="summary-cards">
        <div class="card critical"><div class="number">{critical_count}</div><div class="label">Critical</div></div>
        <div class="card high"><div class="number">{high_count}</div><div class="label">High</div></div>
        <div class="card medium"><div class="number">{medium_count}</div><div class="label">Medium</div></div>
        <div class="card"><div class="number">{summary.get('total_vulnerabilities', 0)}</div><div class="label">Total</div></div>
    </div>

    <div class="chart">
        <div class="segment critical" style="width:{critical_count / max(summary.get('total_vulnerabilities', 1), 1) * 100}%;background:#ff4444"></div>
        <div class="segment high" style="width:{high_count / max(summary.get('total_vulnerabilities', 1), 1) * 100}%;background:#ff8800"></div>
        <div class="segment medium" style="width:{medium_count / max(summary.get('total_vulnerabilities', 1), 1) * 100}%;background:#ffbb33"></div>
    </div>

    <h2>Technologies Detected</h2>
    <ul>{tech_items}</ul>

    <h2>Discovered Assets</h2>
    <table>
        <thead><tr><th>Type</th><th>Details</th></tr></thead>
        <tbody>
            <tr><td><strong>Open Ports</strong></td><td>{port_items or empty_msg}</td></tr>
            <tr><td><strong>URLs</strong></td><td>{url_items or empty_msg}</td></tr>
            <tr><td><strong>Subdomains</strong></td><td>{sub_items or empty_msg}</td></tr>
        </tbody>
    </table>

    {waf_section}

    {admin_section}

    {dns_section}

    {exposed_section}

    {bf_section}

    {enum_section}

    {cve_section}

    {tool_section}

    <h2>Vulnerability Details</h2>
    <p>Each card below is a full pentest write-up: <strong>broad description</strong> (what it is + why it matters + business impact), "
    "affected URLs, <strong>confirmed proof</strong> (double-probed differentials) vs <strong>unverified leads</strong>, "
    "step-by-step attacker replay, gains, tools, and the <strong>fix + timeline</strong>. "
    "Inconclusive re-tests are counted in a note, never listed as findings.</p>
    <table class="vuln-main">
        <thead><tr><th>Severity</th><th>Type</th><th>Affected</th><th>Full description, proof, attacker replay &amp; fix</th></tr></thead>
        <tbody>{vuln_rows}</tbody>
    </table>

    {exploit_section}

    <h2>Remediation Recommendations</h2>

    {rec_items}

    {ai_section}

    <h2>Compliance</h2>
    <pre style="background:#1a1a2e;padding:15px;border-radius:6px;overflow-x:auto;">{json.dumps(audit.get('compliance_audit', {}), indent=2, default=str)}</pre>
</div>
</body>
</html>"""


def ai_filter_notice(original: int, kept: int, filtered: int) -> str:
    """Console line saying exactly what AI triage did to the finding set."""
    return (f"  [*] AI triage: {filtered} finding(s) flagged as likely false "
            f"positives ({original} -> {kept} kept); excluded from active "
            "testing, exploitation and attack-path analysis - full list "
            "retained in the report")


def ai_degraded_notice(failures: int) -> str:
    """Console line for partial provider failures (404, rate limit, ...)."""
    return (f"  [!] AI degraded: {failures} provider call(s) failed; "
            "deterministic validation remains authoritative")


def print_ai_degraded(ai_analysis: Dict[str, Any]) -> int:
    """Emit the AI-degraded notice for an analysis run; returns the count."""
    failures = int((ai_analysis or {}).get("provider_call_failures") or 0)
    if failures:
        cprint(ai_degraded_notice(failures))
    return failures


async def run_ai_analysis(target: str, discovery: Dict[str, Any],
                          vulnerabilities: List[Dict[str, Any]],
                          context: Optional[Dict[str, Any]] = None
                          ) -> Dict[str, Any]:
    """Optional AI-assisted analysis of scan results (Gemini / Groq / DeepSeek).

    Deterministic tools stay authoritative: AI output is advisory only
    (FACT / INFERENCE / HYPOTHESIS / RECOMMENDATION statements) and never
    reclassifies findings.  False-positive suggestions are hypotheses that
    still require deterministic validation.  Returns ``{}`` when no API key
    is configured, so AI is purely additive.
    """
    from modules.ai_integration import (AIIntegration, configured_providers,
                                        ensemble_triage,
                                        provider_call_failures)

    engine = AIIntegration()
    if not engine.enabled:
        return {}
    failures_seen = provider_call_failures()

    # A single None upstream (failed merge) must never kill AI triage
    # with AttributeError — same crash class as the reporting dedup fix.
    _clean_vulns = [v for v in (vulnerabilities or []) if isinstance(v, dict)]
    findings_payload = [
        {"id": str(i),
         "title": str(v.get("title") or v.get("type") or "finding"),
         "type": v.get("type", ""),
         "severity": v.get("severity", ""), "url": v.get("url", ""),
         "payload": v.get("payload", ""),
         "description": str(v.get("description", ""))[:300]}
        for i, v in enumerate(_clean_vulns)
    ]
    cprint(f"\n  [*] AI-assisted analysis ({engine.provider.value}:{engine.model}) ...")

    # Consolidate identical detections (same type + URL) before any LLM call:
    # a full scan emits thousands of raw rows for a handful of distinct
    # findings, and the model should reason about the distinct findings only.
    groups: Dict[Tuple[str, str], List[int]] = {}
    for i, f in enumerate(findings_payload):
        groups.setdefault((f["type"], f["url"]), []).append(i)
    group_list = list(groups.values())
    consolidated = [findings_payload[members[0]] for members in group_list]
    # consolidated position -> raw indices it stands for
    members_by_position = {pos: members for pos, members in enumerate(group_list)}

    def _expand(position: Optional[int]) -> List[int]:
        if position is None:
            return []
        return members_by_position.get(position, [])

    ai_analysis: Dict[str, Any] = {
        "target": target,
        "provider": engine.provider.value,
        "model": engine.model,
        "statements": [],
        "false_positive_hypotheses": [],
        "validated_findings": [],
        "filtered_indices": [],
        "filtered_findings": [],
        "consolidation": {
            "raw_findings": len(findings_payload),
            "unique_findings": len(consolidated),
        },
    }

    filtered_detail: Dict[int, Dict[str, Any]] = {}

    def _record_false_positive(position: Optional[int], statement, source: str) -> None:
        """Map a verdict on a consolidated finding to every raw duplicate."""
        for raw_index in _expand(position):
            if raw_index in filtered_detail:
                continue
            finding = findings_payload[raw_index]
            filtered_detail[raw_index] = {
                "index": raw_index,
                "type": finding.get("type", ""),
                "url": finding.get("url", ""),
                "severity": finding.get("severity", ""),
                "confidence": statement.confidence,
                "reason": (statement.metadata.get("reason")
                           or statement.metadata.get("reasoning", "")),
                "source": source,
            }

    # One false-positive pass over the consolidated findings.  The ensemble
    # (one call per configured provider) only earns its extra API budget
    # when more than a single provider is configured.
    cprint(f"  [*] Validating {len(consolidated)} consolidated findings "
          f"(from {len(findings_payload)} raw detections) for false positives...")
    validated = await engine.validate_findings(consolidated)
    if validated:
        fp_printed = 0
        for stmt in validated.statements:
            if stmt.metadata.get("verdict") != "likely_false_positive":
                continue
            position = stmt.metadata.get("finding_index")
            _record_false_positive(position, stmt, "validation")
            raw_indices = _expand(position)
            _raw = (_clean_vulns[raw_indices[0]]
                    if raw_indices and raw_indices[0] < len(_clean_vulns) else {})
            sample = _raw if isinstance(_raw, dict) else {}
            if fp_printed < 10:
                cprint(f"      [AI-FP] Potential false positive: "
                      f"{sample.get('type')} at {sample.get('url')}")
                fp_printed += 1
        hidden_fp = len(validated.statements) - fp_printed
        if hidden_fp > 0:
            cprint(f"      [AI-FP] ... and {hidden_fp} more hypothesis/FP "
                  "statement(s) (full list in the report)")
        ai_analysis["validated_findings"] = [
            s.to_dict() for s in validated.statements
        ]
        ai_analysis["statements"].append({
            "content": validated.reasoning,
            "reasoning_type": "hypothesis",
            "confidence": validated.confidence,
            "source_module": "ai_finding_validation",
        })

    triage: List[Any] = []
    if len(configured_providers()) > 1:
        triage = await ensemble_triage(consolidated)
    ai_analysis["false_positive_hypotheses"] = [s.to_dict() for s in triage]

    for s in triage:
        if s.metadata.get("verdict") == "likely_false_positive":
            _record_false_positive(s.metadata.get("finding_index"), s,
                                   f"triage:{s.metadata.get('provider', '')}")

    corr = await engine.correlate_findings(findings_payload, [])
    ai_analysis["statements"].extend(s.to_dict() for s in corr.statements)

    recon = await engine.analyze_recon(discovery)
    ai_analysis["statements"].extend(s.to_dict() for s in recon)

    steps = await engine.suggest_next_steps(findings_payload, context)
    ai_analysis["statements"].extend(s.to_dict() for s in steps)

    ai_analysis["filtered_indices"] = sorted(filtered_detail)
    ai_analysis["filtered_findings"] = [
        filtered_detail[i] for i in sorted(filtered_detail)
    ]

    # Compact console output: capped, one line per statement, so a noisy scan
    # cannot flood the terminal with hundreds of correlation lines.  The full
    # list always lands in the report.
    fp_statements = [s for s in triage
                     if s.metadata.get("verdict") == "likely_false_positive"]
    queue: List[Tuple[str, Any]] = (
        [("[AI]", s) for s in corr.statements]
        + [("[AI]", s) for s in steps]
        + [("[AI-FP?]", s) for s in fp_statements]
    )
    max_lines = 15
    for label, stmt in queue[:max_lines]:
        cprint(f"      {label} {stmt.content[:150]}")
    if len(queue) > max_lines:
        cprint(f"      [AI] ... and {len(queue) - max_lines} more advisory "
              "statement(s) (full list in the report)")
    cprint("      [*] AI output is advisory; verdicts are hypotheses. "
          "Flagged findings are excluded from active testing, never deleted.")
    # Every engine in this pass (including the per-provider ones created by
    # ensemble_triage) contributes to the process-wide failure counter.
    ai_analysis["provider_call_failures"] = max(
        0, provider_call_failures() - failures_seen)
    return ai_analysis


async def run_auto_exploitation(target: str, vulnerabilities: List[Dict[str, Any]],
                                args: argparse.Namespace) -> Dict[str, Any]:
    """Verify detected vulnerabilities automatically, inside engagement scope.

    Returns the runner summary (``status``/``confirmed``/``possible``/
    ``inconclusive``/``attempts``) so the report and the post-exploitation
    stage can consume the evidence. Never raises: a failure to run is
    reported as a denied/skipped summary, not a crash.
    """
    from modules.exploitation_runner import ExploitationRunner

    # Reachability gate: verifying findings against a host that already
    # blocks us burns request_timeout per finding (40s x N) for nothing but
    # timeout lines. Skip with one honest line instead.
    if target and not await _quick_reachable(target):
        cprint(f"  [*] Automated exploitation skipped: target not answering "
               f"(timeout/refused) - verification deferred to avoid hammering "
               f"a blocking host")
        return {
            'status': 'denied',
            'scope_reason': ('target unreachable (timeout/refused) - '
                             'verification skipped'),
            'mode': 'aggressive' if getattr(args, 'exploit_aggressive', False) else 'safe',
            'attempted': 0, 'confirmed': 0, 'possible': 0, 'inconclusive': 0,
            'attempts': [], 'duration_ms': 0,
            'detected': len(vulnerabilities or []), 'candidates': 0,
            'max_findings': getattr(args, 'exploit_max', 100),
            'coverage_pct': 0.0, 'capped': False,
        }

    engagement = _resolve_exploitation_engagement(target, args)

    ai_engine = None
    try:
        from modules.ai_integration import AIIntegration
        candidate = AIIntegration()
        if candidate.enabled:
            ai_engine = candidate
    except Exception:
        ai_engine = None

    runner = ExploitationRunner(
        engagement=engagement,
        ai=ai_engine,
        max_findings=getattr(args, 'exploit_max', 100),
        delay=getattr(args, 'exploit_delay', 1.0),
        aggressive=bool(getattr(args, 'exploit_aggressive', False)),
        concurrency=getattr(args, 'exploit_concurrency', 6),
    )
    try:
        summary = await runner.execute(target, vulnerabilities)
    except Exception as exc:
        cprint(f"[!] Automated exploitation aborted: {exc}")
        summary = {
            'status': 'denied',
            'scope_reason': f'automated exploitation failed: {exc}',
            'mode': 'aggressive' if getattr(args, 'exploit_aggressive', False) else 'safe',
            'attempted': 0, 'confirmed': 0, 'possible': 0, 'inconclusive': 0,
            'attempts': [], 'duration_ms': 0,
            'detected': len(vulnerabilities), 'candidates': 0,
            'max_findings': getattr(args, 'exploit_max', 100),
            'coverage_pct': 0.0, 'capped': False,
        }
    finally:
        await runner.close()

    status = summary.get('status')
    if status == 'executed':
        cprint(f"  [+] Automated exploitation: {summary['confirmed']} confirmed, "
              f"{summary['possible']} possible, {summary['inconclusive']} inconclusive "
              f"({summary['attempted']} attempted, mode={summary['mode']})")
        detected = int(summary.get('detected') or 0)
        candidates = int(summary.get('candidates') or 0)
        coverage = summary.get('coverage_pct', 0.0)
        if detected:
            line = (f"  [*] Verification coverage: {summary['attempted']} of "
                    f"{detected} detected findings ({coverage}%); "
                    f"{candidates} had a verification handler")
            if summary.get('capped'):
                line += (f" - capped by --exploit-max "
                         f"{summary.get('max_findings')}")
            cprint(line)
        marks = {'confirmed': '+', 'possible': '~', 'inconclusive': '-'}
        _attempts = [a for a in (summary.get('attempts') or [])
                     if isinstance(a, dict)]
        for attempt in _attempts:
            attempt_status = str(attempt.get('status', 'inconclusive'))
            mark = marks.get(attempt_status, '-')
            detail = str(attempt.get('detail', '')).strip()
            cprint(f"      [{mark}] {attempt_status}: {attempt.get('type', '')} "
                  f"at {attempt.get('url', '')}")
            if detail:
                cprint(f"          {detail[:300]}")
    elif status == 'denied':
        cprint(f"  [*] Automated exploitation skipped: {summary.get('scope_reason', '')}")
    else:
        cprint("  [*] Automated exploitation: no supported findings to attempt")

    return summary


async def run_scan_session(targets: List[str], args: argparse.Namespace) -> None:
    scan_types_map = {
        'tcp_connect': 'tcp_connect', 'syn': 'syn_stealth', 'syn_stealth': 'syn_stealth',
        'udp': 'udp', 'ack': 'ack', 'fin': 'fin', 'null': 'null', 'xmas': 'xmas',
    }
    scan_types = [scan_types_map.get(s.strip(), s.strip()) for s in args.scan.split(',')]

    state = ScanState.load() if args.resume else None

    for target in targets:
        con.phase("ATHENA SECURITY SUITE")
        cprint(f"  Target: {target}")
        cprint(f"  Profile: {args.profile or os.getenv('AETHELRED_PROFILE', 'balanced')}")
        cprint(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        cprint(f"{'='*60}\n")

        discovery_results: Dict[str, Any] = {}
        vulnerabilities: List[Dict[str, Any]] = []
        bruteforce_results: Dict[str, Any] = {}
        enumeration_results: Dict[str, Any] = {}
        external_tools: List[Dict[str, Any]] = []
        scan_partial = False

        # PHASE 0 — WAF gate runs FIRST on every mode that touches HTTP.
        waf_info: Dict[str, Any] = {}
        if args.mode in ('full', 'all', 'discovery', 'recon', 'vuln'):
            with _phase('waf gate'):
                waf_info = await run_waf_gate(target, args)
            discovery_results['waf'] = waf_info

        if args.mode in ('full', 'all', 'discovery', 'recon'):
            with _phase('discovery'):
                discovery_results = await run_discovery(
                    target, args.output, scan_types,
                    parse_ports(args.ports) if args.ports else None,
                    args.concurrent, args.rate, args.jitter
                )
            if args.pause:
                input("  [*] Paused. Press Enter to continue...")

        elif args.mode == 'vuln':
            # Light recon so the scan works from a real asset inventory
            # (crawled URLs, subdomains, ports, tech) instead of a single
            # guessed URL - and so the report's asset table is not empty.
            from modules.discovery import DiscoveryModule as _Disc
            with _phase('light discovery'):
                discovery_results = await run_discovery(
                    target, args.output, scan_types,
                    parse_ports(args.ports) if args.ports else None,
                    args.concurrent, args.rate, args.jitter,
                    stages=list(_Disc.LIGHT_STAGES),
                )
            if args.pause:
                input("  [*] Paused. Press Enter to continue...")

        # Discovery failing quietly is the worst failure mode: the run keeps
        # going on the default endpoint set and still prints SCAN COMPLETE.
        if discovery_results:
            health = _discovery_health(discovery_results)
            if not health['healthy']:
                scan_partial = True
                cprint("\n  [!] DISCOVERY DEGRADED - nothing found for: "
                      f"{', '.join(health['empty'])}")
                cprint("  [!] Likely causes: DNS resolver failure, host "
                      "unreachable, or request filtering.")
                cprint("  [!] Later phases fall back to the target URL only. "
                      "This run will be marked PARTIAL.\n")

        if args.mode in ('full', 'all', 'vuln'):
            # Align with FrameworkConfig: stealth AND balanced are stealthy,
            # aggressive/debug are not. Was `profile==stealth` only, so
            # balanced printed stealth=OFF despite framework STEALTH_MODE=True.
            _prof = (args.profile or os.getenv('AETHELRED_PROFILE', 'balanced')).lower()
            stealth = _prof in ('stealth', 'balanced')
            # Feed every URL recon actually found (crawl, admin panels,
            # well-known endpoints) into the scanner instead of falling back
            # to the bare target URL.
            scan_urls = _scan_targets(discovery_results)
            with _phase('vulnerability scan'):
                vulnerabilities = await run_vuln_scan(target, scan_urls, stealth, waf_info=waf_info)
            # Directory-listing harvest: files proven by content-sniff join
            # the finding set as CONFIRMED (HTTP 200 + magic/marker proof),
            # so the report shows real disclosed files, not leads.
            _harvest = [h for h in ((discovery_results.get('listing_harvest') or {}).get('findings') or []) if isinstance(h, dict)]
            if _harvest:
                for _i, _hf in enumerate(_harvest, 1):
                    _ev = str(_hf.get('evidence', ''))
                    _ev_low = _ev.lower()
                    _sev = 'MEDIUM' if 'non-html file content' in _ev_low else 'HIGH'
                    vulnerabilities.append({
                        'id': f'listing-harvest-{_i}',
                        'type': 'Exposed Sensitive File',
                        'url': _hf.get('url', ''),
                        'severity': _sev,
                        'description': (f"{_hf.get('description', 'Exposed file')} "
                                        f"({str(_hf.get('path', ''))}) — {_ev}"),
                        'verified': True,
                        'confidence': 'high',
                        'evidence': {'proof': _ev},
                        'payload': '',
                        'source': 'listing_harvest',
                    })
                cprint(f"  [+] Listing harvest: {len(_harvest)} content-confirmed "
                      f"file(s) added as verified findings")
            # External template engine (nuclei): installed -> runs against the
            # base target (nuclei's own templates handle path discovery),
            # missing -> one clean skip line.  Its matches are evidence-backed
            # and go through AI triage like our own findings.
            with _phase('nuclei'):
                nuclei_summary = await run_external_scan(
                    target, stealth, args, native_findings=vulnerabilities)
            if nuclei_summary:
                external_tools.append(nuclei_summary)
                extra = nuclei_summary.get('findings') or []
                extra = [v for v in extra if isinstance(v, dict)]
                if extra:
                    cprint(f"  [+] Nuclei contributed {len(extra)} new finding(s)")
                    vulnerabilities = list(vulnerabilities or []) + list(extra)
            # Optional engines (sqlmap/dalfox confirm vulns; wafw00f/httpx add
            # context).  Missing binaries print one skip line each; findings
            # join AI triage and the exploitation runner untouched.
            with _phase('external tools'):
                try:
                    extended = await run_extended_tools(target, args, scan_urls)
                except Exception as exc:  # pragma: no cover - never break scan
                    cprint(f"  [!] Extended tools aborted: {exc}")
                    extended = []
            for summary in extended or []:
                if not isinstance(summary, dict):
                    continue
                external_tools.append(summary)
                extra = [v for v in (summary.get('findings') or []) if isinstance(v, dict)]
                if extra:
                    cprint(f"  [+] {summary.get('tool', 'tool')} contributed "
                          f"{len(extra)} new finding(s)")
                    vulnerabilities = list(vulnerabilities or []) + list(extra)
                # httpx enriches recon: fold probed tech into discovery so
                # CVE mapping sees versions the crawler missed.
                if isinstance(summary, dict) and summary.get('tool') == 'httpx':
                    _merge_httpx_into_discovery(discovery_results, summary)
            if args.pause:
                input("  [*] Paused. Press Enter to continue...")

        if args.mode in ('full', 'all', 'bruteforce', 'recon'):
            with _phase('bruteforce'):
                bruteforce_results = await run_bruteforce(target, discovery_results)

        if args.mode in ('full', 'all', 'recon', 'discovery'):
            ports = discovery_results.get('ports', [])
            with _phase('service enumeration'):
                enumeration_results = await run_enumeration(target, ports)

        cve_results = []
        kev_summary: Dict[str, Any] = {}
        if args.mode in ('full', 'all', 'recon'):
            tech_list = discovery_results.get('technologies_with_confidence', [])
            if not tech_list:
                tech_list = [{'technology': t, 'version': '', 'confidence': 1} for t in discovery_results.get('technologies', [])]
            # Service banners carry versions the web crawler never sees
            # (Exim 4.100.1, Dovecot, OpenSSH) — feed them to CVE mapping.
            for _bt in _service_banner_techs(enumeration_results or {}):
                if not any(str(t.get('technology', '')).lower().startswith(_bt['technology'].lower())
                           for t in tech_list):
                    tech_list.append(_bt)
            if tech_list:
                cve_results = await run_cve_mapping(tech_list)
            # CISA KEV cross-reference: flag mapped CVEs exploited in the
            # wild (cached feed, offline-safe, opt-out with --no-kev).
            if cve_results and not getattr(args, 'no_kev', False):
                try:
                    from modules.kev import load_kev_catalog, annotate_cve_results
                    _catalog = load_kev_catalog()
                    kev_summary = annotate_cve_results(cve_results, _catalog) or {}
                    if int(kev_summary.get('kev_count', 0) or 0):
                        cprint(f"  [+] CISA KEV: {kev_summary['kev_count']} mapped CVE(s) "
                              f"are exploited in the wild "
                              f"({', '.join(kev_summary.get('kev_ids', [])[:5])})")
                except Exception as exc:  # pragma: no cover - never break scan
                    cprint(f"  [!] KEV enrichment skipped: {exc}")
            if kev_summary:
                (discovery_results.setdefault('kev', {}).update(kev_summary)
                 if isinstance(discovery_results, dict) else None)

        # Run AI analysis and filter false positives
        ai_analysis = {}
        if vulnerabilities or discovery_results:
            ai_analysis = await run_ai_analysis(
                target, discovery_results, vulnerabilities,
                {"mode": args.mode}
            )
            
            # Drop findings the AI flagged as likely false positives.  The
            # wording must match what happens: they leave the *active* set
            # (no exploitation, no attack path) but stay in the report.
            filtered_indices = ai_analysis.get("filtered_indices", [])
            if filtered_indices:
                original_count = len(vulnerabilities)
                vulnerabilities = [v for i, v in enumerate(vulnerabilities) if i not in filtered_indices]
                filtered_count = original_count - len(vulnerabilities)
                if filtered_count > 0:
                    cprint(ai_filter_notice(original_count, len(vulnerabilities),
                                           filtered_count))
            print_ai_degraded(ai_analysis)

        # Actively verify what survived triage (scope-gated, safe mode by default)
        exploitation_summary: Optional[Dict[str, Any]] = None
        if vulnerabilities and not getattr(args, 'no_auto_exploit', False):
            exploitation_summary = await run_auto_exploitation(target, vulnerabilities, args)

        output_path = generate_report(
            target, discovery_results, vulnerabilities, bruteforce_results,
            enumeration_results, cve_results, args.output, args.export,
            ai_analysis=ai_analysis,
            exploitation=exploitation_summary,
            external_tools=external_tools,
        )

        # Hand the scan's findings to the post-exploitation stage so its
        # roadmap is built from real results when --post follows a scan.
        args.scan_results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": list(vulnerabilities),
            "discovery": discovery_results or {},
            "bruteforce": bruteforce_results or {},
            "exploitation": (exploitation_summary.get("attempts", [])
                             if isinstance(exploitation_summary, dict) else []),
            "partial": scan_partial,
        }

        con.phase("SCAN COMPLETE" + (" (PARTIAL)" if scan_partial else ""))
        if scan_partial:
            cprint("  NOTE: discovery produced no assets - see the "
                  "DISCOVERY DEGRADED warning above.")
        cprint(f"  Target: {target}")
        cprint(f"  Report: {output_path}")
        cprint(f"{'='*60}\n")


async def run_post_exploitation(targets: List[str], args: argparse.Namespace) -> None:
    if not HAS_POST:
        cprint("[!] Post-exploitation modules not available. Check installation.")
        return

    engagement = _resolve_engagement(targets, args)
    orchestrator = PostOrchestrator(engagement=engagement)
    orchestrator.configure({
        "c2_url": args.c2_url or "",
        "exfil_url": args.exfil_url or "",
        "callback_host": args.post_host or "0.0.0.0",
        "callback_port": args.post_port or 4444,
        "auto_decide": not args.post_manual,
        "auto_assess": not args.no_auto_assess and engagement is not None,
        "listener_wait": max(0.0, float(args.post_wait or 10.0)),
        "scan_results": getattr(args, "scan_results", {}) or {},
    })

    if args.post_payload:
        from modules.post_exploitation.payloads import PayloadFactory
        try:
            payload = PayloadFactory.build(
                args.post_payload, args.post_host, args.post_port,
                retries=args.post_payload_retries,
                interval=args.post_payload_interval,
            )
        except ValueError as exc:
            cprint(f"[!] {exc}")
            return
        # Raw print: payloads are copy-pasted, ANSI would corrupt them.
        print(f"# Reconnecting {args.post_payload} reverse payload for "
              f"{args.post_host}:{args.post_port} "
              f"({args.post_payload_retries} retries x "
              f"{args.post_payload_interval}s)")
        print(payload)
        if not args.post_shell:
            return

    if args.post_only:
        orchestrator.config["only_phases"] = [args.post_only]
    if args.post_skip:
        orchestrator.config["skip_phases"] = [args.post_skip]

    if args.post_list_sessions:
        sessions = orchestrator.session_mgr.list()
        if not sessions:
            cprint("No saved sessions.")
            return
        for s in sessions:
            cprint(f"  {s.id}: {s.target} [{s.platform.value}] {s.user.username} ({s.state.value})")
        return

    if args.post_shell == "reverse":
        cprint(f"[*] Starting reverse shell listener on {args.post_host}:{args.post_port}")
        await orchestrator.start_listener(args.post_host, args.post_port)
        cprint("[*] Waiting for an inbound shell "
              f"(up to {args.post_wait:g}s; use --post-payload to print a "
              "reconnecting payload)")
        session = await orchestrator.session_mgr.wait_for_session(
            timeout=max(0.0, float(args.post_wait or 10.0)))
        if not session:
            cprint(f"[!] No session received within {args.post_wait:g}s. "
                  "Use --post-interactive after a session connects.")
            return
        cprint(f"[+] Session {session.id} received from {session.target}")
        if engagement is not None and not _enforce_session_scope(orchestrator, session,
                                                                 engagement):
            return

    elif args.post_shell == "bind":
        if not targets:
            cprint("[!] Need target for bind shell connection")
            return
        target = targets[0].replace("https://", "").replace("http://", "").split("/")[0]
        cprint(f"[*] Connecting to bind shell at {target}:{args.post_port}")
        session = await _register_scoped_bind(orchestrator, target, args, engagement)
        if not session:
            return

    elif args.post_shell == "web":
        url = args.post_web_url or targets[0] if targets else ""
        if not url:
            cprint("[!] Need --post-web-url for web shell")
            return
        session = await _register_scoped_web(orchestrator, url, args, engagement)
        if not session:
            return
        cprint(f"[+] Web shell registered: {url}")
    else:
        if not targets:
            cprint("[!] No target specified for post-exploitation")
            return
        if engagement is None:
            cprint("[!] No engagement could be established for post-exploitation; "
                  "failing closed. Provide --scope-file or --engagement-id, "
                  "or a --target to build an explicit ad-hoc scope.")
            return
        session = await _register_manual_session(orchestrator, targets[0], args,
                                                 engagement)
        if not session:
            return

    if args.post_interactive:
        await orchestrator.interactive_console(session)
        return

    manual = args.post_manual
    cprint(f"\n{'='*60}")
    cprint(f"  POST-EXPLOITATION CHAIN")
    cprint(f"  Session: {session.id} | Target: {session.target}")
    if engagement is not None:
        cprint(f"  Engagement: {engagement.id} ({engagement.name})")
    cprint(f"{'='*60}\n")

    results = await orchestrator.run_full_chain(session, interactive=manual, manual_mode=manual)

    report = orchestrator.generate_report(session.id)
    cprint(f"\n{'='*60}")
    cprint(f"  POST-EXPLOITATION COMPLETE")
    cprint(f"  Sessions succeeded: {report['phases_succeeded']}/{report['phases_completed']}")
    cprint(f"  Critical findings: {len(report['critical_findings'])}")
    cprint(f"  Root obtained: {report['is_root']}")
    cprint(f"  Live sessions: {report.get('sessions_total', 1)}")
    if report.get("edr_policy", {}).get("edr_detected"):
        suppressed = report["edr_policy"].get("suppressed", [])
        cprint(f"  EDR detected - suppressed: {', '.join(suppressed) or 'none'}")
    roadmap = report.get("roadmap") or {}
    summary = roadmap.get("summary") or {}
    if summary:
        cprint(f"  Roadmap: {summary.get('phases_applicable', 0)}/"
              f"{summary.get('phases_total', 0)} applicable phase(s), "
              f"{summary.get('actions_total', 0)} action(s) "
              f"({summary.get('actions_by_execution', {}).get('automated', 0)} "
              f"automatable)")
    cprint(f"{'='*60}\n")

    if report.get("sessions"):
        cprint("  Tracked sessions:")
        for row in report["sessions"]:
            parent = f" <- {row['parent_session']}" if row.get("parent_session") else ""
            cprint(f"    {row['id']}  {row['target']}  [{row['shell_type']}] "
                  f"{row['state']} scope={row['scope_decision']}{parent}")
        cprint()

    await _run_post_ai_suggestions(report)

    report_path = f"post_exploit_{session.id}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    cprint(f"[+] Report saved to {report_path}")

    orchestrator.session_mgr.save()


async def _run_post_ai_suggestions(report: Dict[str, Any]) -> None:
    """Optional AI-suggested next steps after the post-exploitation chain."""
    from modules.ai_integration import AIIntegration

    engine = AIIntegration()
    if not engine.enabled:
        return
    findings_payload = report.get("findings") or [
        {"type": f.get("type", ""), "severity": f.get("severity", "")}
        for f in report.get("critical_findings", [])
    ]
    steps = await engine.suggest_next_steps(
        findings_payload, {"post_exploitation": True}
    )
    if not steps:
        return
    cprint("\n  [*] AI-assisted next steps "
          f"({engine.provider.value}:{engine.model}):")
    for s in steps:
        cprint(f"      [AI] {s.content[:160]}")


def _resolve_engagement(targets: List[str], args: argparse.Namespace,
                        techniques: Optional[List[str]] = None):
    """Establish the engagement used for post-exploitation (fail-closed).

    Priority: ``--scope-file`` → ``--engagement-id`` → explicit ad-hoc from
    ``--target``/targets.  Returns ``None`` when no scope can be established.

    ``techniques`` only applies to the ad-hoc fallback: an explicit scope
    file or stored engagement always decides its own allow-list.
    """
    from modules.engagement import (EngagementStore, ad_hoc_engagement,
                                    load_engagement_file)
    if getattr(args, "scope_file", None):
        try:
            engagement = load_engagement_file(args.scope_file)
        except (OSError, ValueError) as exc:
            cprint(f"[!] Cannot load engagement scope file: {exc}")
            return None
        return engagement
    if getattr(args, "engagement_id", None):
        engagement = EngagementStore().get(args.engagement_id)
        if engagement is None:
            cprint(f"[!] Engagement '{args.engagement_id}' not found in "
                  f"engagements.json; failing closed.")
            return None
        if not engagement.active:
            cprint(f"[!] Engagement '{args.engagement_id}' is inactive; failing closed.")
            return None
        return engagement
    if targets:
        kwargs: Dict[str, Any] = {"operator": os.getenv('USER', 'cli')}
        if techniques:
            kwargs["techniques"] = techniques
        return ad_hoc_engagement(list(targets), **kwargs)
    cprint("[!] No engagement or target list provided; post-exploitation will "
          "fail closed (no scope established).")
    return None


def _resolve_exploitation_engagement(target: str, args: argparse.Namespace):
    """Engagement used for automated exploitation (fail closed).

    The ad-hoc technique list exists for ``--post`` and does not include
    ``exploitation``; the operator's explicit ``-t`` target *is* the
    authorization for an in-scope scan, so exploitation is added here.
    An explicit scope file or engagement id is never overridden.
    """
    from modules.engagement import AD_HOC_TECHNIQUES, Technique
    techniques = list(dict.fromkeys(
        [*AD_HOC_TECHNIQUES, Technique.EXPLOITATION.value]))
    return _resolve_engagement([target], args, techniques=techniques)


def _enforce_session_scope(orchestrator, session, engagement) -> bool:
    """Kill a session whose target is not proven in scope; returns False on deny."""
    check = engagement.check_target(session.target)
    if check.allowed:
        session.engagement_id = engagement.id
        session.scope_decision = check.decision.value
        return True
    cprint(f"[!] Session target {session.target!r} is out of scope: "
          f"{check.reason}. Terminating session.")
    import asyncio as _asyncio
    _asyncio.get_event_loop().run_until_complete(
        orchestrator.session_mgr.kill(session.id))
    return False


async def _register_scoped_bind(orchestrator, target: str, args, engagement) -> Optional[object]:
    try:
        session = await orchestrator.register_bind_shell(target, args.post_port)
    except Exception as exc:
        cprint(f"[!] Failed to connect to bind shell: {exc}")
        return None
    if not session:
        cprint("[!] Failed to connect to bind shell")
        return None
    if engagement is None:
        cprint("[!] No engagement established; bind session denied (fail closed).")
        return None
    if not _enforce_session_scope(orchestrator, session, engagement):
        return None
    return session


async def _register_scoped_web(orchestrator, url: str, args, engagement) -> Optional[object]:
    if engagement is None:
        cprint("[!] No engagement established; web session denied (fail closed).")
        return None
    params = {"cmd": args.post_web_param}
    session = await orchestrator.register_web_shell(url, params, method=args.post_web_method)
    if not session:
        cprint("[!] Failed to register web shell")
        return None
    if not _enforce_session_scope(orchestrator, session, engagement):
        return None
    return session


async def _register_manual_session(orchestrator, target: str, args, engagement) -> Optional[object]:
    from modules.post_exploitation import ShellType
    try:
        session = orchestrator.session_mgr.create_for_engagement(
            target, engagement,
            shell_type=ShellType.CUSTOM,
            execution_context="manual",
        )
    except ValueError as exc:
        cprint(f"[!] Session denied: {exc}")
        return None
    return session


# ============================================================================
# REST API SERVER (Flask)
# ============================================================================

MODE_ALIASES = {
    '1': 'full',
    '2': 'discovery',
    '3': 'vuln',
    '4': 'api',
}
API_VALID_MODES = {'1', '2', '3', 'full', 'discovery', 'vuln'}

# In-process job registry (cleared on server restart)
JOBS: Dict[str, Dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()


class _TokenBucketLimiter:
    """Small dependency-free sliding-window rate limiter keyed per client."""

    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    @staticmethod
    def parse(limit_str: str) -> Optional[tuple]:
        """Parse 'N per second/minute/hour/day' -> (limit, window_seconds)."""
        parts = limit_str.strip().lower().split()
        try:
            limit = int(parts[0])
        except (ValueError, IndexError):
            return None
        unit = parts[2] if len(parts) > 2 else 'second'
        window = {'second': 1, 'minute': 60, 'hour': 3600, 'day': 86400}.get(unit, 1)
        return limit, window

    def allow(self, key: str, limit_str: str) -> bool:
        parsed = self.parse(limit_str)
        if not parsed:
            return True
        limit, window = parsed
        now = time.time()
        with self._lock:
            dq = self._hits[key]
            while dq and now - dq[0] > window:
                dq.popleft()
            if len(dq) >= limit:
                return False
            dq.append(now)
            return True


_limiter = _TokenBucketLimiter()


def _client_key() -> str:
    api_key = request.headers.get('X-API-KEY', 'anonymous')
    return f"{api_key}|{request.remote_addr}"


def _env_bool(name: str, default: bool = True) -> bool:
    return os.getenv(name, 'true' if default else 'false').lower() == 'true'


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _require_api_key():
    """Return an error (jsonify, status) tuple when auth fails, else None."""
    if not _env_bool('REQUIRE_API_KEY'):
        return None
    api_key = os.getenv('ATHENA_API_KEY', '')
    if not api_key:
        return jsonify({'error': 'Service unavailable',
                        'detail': 'ATHENA_API_KEY is not configured on the server'}), 503
    provided = request.headers.get('X-API-KEY')
    if not provided:
        return jsonify({'error': 'Unauthorized',
                        'detail': 'X-API-KEY header is required'}), 401
    if provided != api_key:
        return jsonify({'error': 'Unauthorized',
                        'detail': 'Invalid API key'}), 401
    return None


def _apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"
    )
    return response


def _parse_targets(data: Dict[str, Any]) -> List[str]:
    target = data.get('target')
    if isinstance(target, str):
        return [t.strip() for t in target.split(',') if t.strip()]
    if isinstance(target, list):
        return [t.strip() for t in target if isinstance(t, str) and t.strip()]
    return []


def _safe_report_name(target: str) -> str:
    return target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')


async def _scan_single_url(url: str) -> list:
    scanner = VulnerabilityScanner(stealth_mode=True)
    try:
        return await scanner.scan_url(url)
    finally:
        await scanner.close()


async def _run_background_scan(job_id: str, targets: List[str], mode: str) -> None:
    """Execute a queued scan job in the background and record its outcome."""
    job = JOBS.get(job_id)
    if job:
        job['status'] = 'RUNNING'
    try:
        mode_text = {'1': 'full', '2': 'discovery', '3': 'vuln'}.get(mode, mode)
        args = argparse.Namespace(
            mode=mode_text, output='json', profile=None,
            scan='tcp_connect', ports=None, concurrent=200, rate=1000,
            jitter=0, pause=False, export=None, verbose=False,
        )
        await run_scan_session(targets, args)
        if job:
            job['status'] = 'COMPLETE'
            job['finished_at'] = datetime.now(timezone.utc).isoformat()
            job['results'] = [
                {'target': t, 'report_file': f"report_{_safe_report_name(t)}.json"}
                for t in targets
            ]
    except Exception as exc:
        if job:
            job['status'] = 'FAILED'
            job['finished_at'] = datetime.now(timezone.utc).isoformat()
            job['error'] = str(exc)


def create_app(safe_mode: bool = True) -> Flask:
    """Build the Athena Flask application (no server started)."""
    app = Flask('athena')
    FrameworkConfig.SAFE_MODE = safe_mode
    os.environ['AETHELRED_SAFE_MODE'] = 'true' if safe_mode else 'false'

    @app.after_request
    def _sec(response):
        return _apply_security_headers(response)

    @app.route('/health', methods=['GET'])
    def health():
        active = sum(1 for j in JOBS.values() if j.get('status') in ('QUEUED', 'RUNNING'))
        return jsonify({
            'status': 'online',
            'version': '2.2.0',
            'safe_mode': FrameworkConfig.SAFE_MODE,
            'active_scans': active,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })

    @app.route('/metrics', methods=['GET'])
    def metrics():
        total = len(JOBS)
        active = sum(1 for j in JOBS.values() if j.get('status') in ('QUEUED', 'RUNNING'))
        vulns = sum(j.get('total_findings', 0) for j in JOBS.values())
        body = (
            "# HELP athena_scan_requests_total Total number of scan requests dispatched\n"
            "# TYPE athena_scan_requests_total counter\n"
            f"athena_scan_requests_total {total}\n"
            "# HELP athena_vulnerabilities_total Total vulnerabilities found\n"
            "# TYPE athena_vulnerabilities_total counter\n"
            f"athena_vulnerabilities_total {vulns}\n"
            "# HELP athena_active_scans Currently queued or running scans\n"
            "# TYPE athena_active_scans gauge\n"
            f"athena_active_scans {active}\n"
        )
        return app.response_class(body, mimetype='text/plain; version=0.0.4')

    @app.route('/scan', methods=['POST'])
    def scan():
        auth_err = _require_api_key()
        if auth_err:
            return auth_err
        if not _limiter.allow('scan|' + _client_key(), os.getenv('RATE_LIMIT_SCAN', '5 per minute')):
            return jsonify({'error': 'Rate limit exceeded',
                            'detail': 'Rate limit exceeded'}), 429
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({'error': 'Bad request',
                            'detail': 'Request body must be JSON'}), 400
        targets = _parse_targets(data)
        if not targets:
            return jsonify({'error': 'Bad request',
                            'detail': 'target must be a non-empty domain/IP or list of them'}), 400
        max_targets = _env_int('MAX_TARGETS_PER_REQUEST', 10)
        if len(targets) > max_targets:
            return jsonify({'error': 'Bad request',
                            'detail': f'Too many targets. Max {max_targets} per request'}), 400
        mode = str(data.get('mode', '1')).strip()
        if mode not in API_VALID_MODES:
            return jsonify({'error': 'Bad request',
                            'detail': f"Invalid mode '{mode}'. Valid: 1 (full), 2 (discovery), 3 (scan)"}), 400
        job_id = str(uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()
        with _JOBS_LOCK:
            JOBS[job_id] = {
                'id': job_id, 'status': 'QUEUED', 'targets': targets,
                'mode': mode, 'started_at': now_iso, 'finished_at': None,
                'error': None, 'results': None,
            }
        threading.Thread(
            target=lambda: asyncio.run(_run_background_scan(job_id, targets, mode)),
            daemon=True,
        ).start()
        return jsonify({
            'status': 'accepted',
            'job_id': job_id,
            'targets_count': len(targets),
            'mode': mode,
            'poll_url': f'/scan/status/{job_id}',
            'message': f'Security assessment queued for {len(targets)} target(s)',
        }), 202

    @app.route('/scan/status/<job_id>', methods=['GET'])
    def scan_status(job_id):
        auth_err = _require_api_key()
        if auth_err:
            return auth_err
        job = JOBS.get(job_id)
        if not job:
            return jsonify({'error': 'Not found', 'detail': f'No job with id {job_id}'}), 404
        return jsonify(job)

    @app.route('/scan/url', methods=['POST'])
    def scan_url_endpoint():
        auth_err = _require_api_key()
        if auth_err:
            return auth_err
        if not _limiter.allow('scan_url|' + _client_key(), '10 per minute'):
            return jsonify({'error': 'Rate limit exceeded',
                            'detail': 'Limit: 10 per minute'}), 429
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({'error': 'Bad request',
                            'detail': 'Request body must be JSON'}), 400
        url = data.get('url')
        if not isinstance(url, str) or not url.strip():
            return jsonify({'error': 'Bad request', 'detail': 'url field is required'}), 400
        url = url.strip()
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            return jsonify({'error': 'Bad request',
                            'detail': 'url must include http:// or https:// and a valid hostname'}), 400
        try:
            findings = asyncio.run(_scan_single_url(url))
        except Exception as exc:
            app.logger.exception('scan_url failed for %s', url)
            return jsonify({'error': 'Internal scan error', 'detail': str(exc)}), 500
        return jsonify({'url': url, 'findings': findings, 'count': len(findings)})

    @app.route('/jobs', methods=['GET'])
    def jobs():
        auth_err = _require_api_key()
        if auth_err:
            return auth_err
        summary = [{
            'id': j['id'], 'status': j['status'], 'targets': j['targets'],
            'mode': j['mode'], 'started_at': j['started_at'],
            'finished_at': j['finished_at'],
        } for j in JOBS.values()]
        return jsonify({'jobs': summary, 'total': len(summary)})

    # ------------------------------------------------------------------
    # Assessment API – engagements / sessions / findings / attack paths
    # ------------------------------------------------------------------

    @app.route('/engagements', methods=['GET'])
    def engagements_list():
        auth_err = _require_api_key()
        if auth_err:
            return auth_err
        from modules.engagement import EngagementStore
        store = EngagementStore()
        active_only = request.args.get('active', 'true').lower() == 'true'
        items = [e.to_dict() for e in store.list(active_only=active_only)]
        return jsonify({'engagements': items, 'total': len(items)})

    @app.route('/engagements/<engagement_id>', methods=['GET'])
    def engagement_detail(engagement_id):
        auth_err = _require_api_key()
        if auth_err:
            return auth_err
        from modules.engagement import EngagementStore
        engagement = EngagementStore().get(engagement_id)
        if not engagement:
            return jsonify({'error': 'Not found',
                            'detail': f'No engagement {engagement_id}'}), 404
        return jsonify(engagement.to_dict())

    @app.route('/engagements/<engagement_id>/scope', methods=['GET'])
    def engagement_scope_check(engagement_id):
        """Check whether a proposed target is in scope (fail-closed)."""
        auth_err = _require_api_key()
        if auth_err:
            return auth_err
        from modules.engagement import EngagementStore
        engagement = EngagementStore().get(engagement_id)
        if not engagement:
            return jsonify({'error': 'Not found',
                            'detail': f'No engagement {engagement_id}'}), 404
        target = request.args.get('target', '')
        if not target:
            return jsonify({'error': 'Bad request',
                            'detail': 'target query parameter is required'}), 400
        check = engagement.check_target(target)
        return jsonify(check.to_dict())

    @app.route('/sessions', methods=['GET'])
    def sessions_list():
        auth_err = _require_api_key()
        if auth_err:
            return auth_err
        try:
            from modules.post_exploitation import SessionState
            from modules.post_exploitation.session import SessionManager
        except ImportError:
            return jsonify({'error': 'Post-exploitation modules unavailable'}), 501
        mgr = SessionManager()
        mgr.load()
        state = request.args.get('state')
        sessions = mgr.list(SessionState(state) if state else None)
        return jsonify({'sessions': [
            {
                'id': s.id, 'target': s.target,
                'platform': s.platform.value,
                'shell_type': s.shell_type.value,
                'state': s.state.value,
                'engagement_id': s.engagement_id,
                'user': s.user.username,
                'is_root': s.user.is_root,
                'hostname': s.system.hostname,
            } for s in sessions
        ], 'total': len(sessions)})

    @app.route('/sessions/<session_id>', methods=['GET'])
    def session_detail(session_id):
        auth_err = _require_api_key()
        if auth_err:
            return auth_err
        try:
            from modules.post_exploitation.session import SessionManager
        except ImportError:
            return jsonify({'error': 'Post-exploitation modules unavailable'}), 501
        mgr = SessionManager()
        mgr.load()
        session = mgr.get(session_id)
        if not session:
            return jsonify({'error': 'Not found',
                            'detail': f'No session {session_id}'}), 404
        return jsonify({
            'id': session.id, 'target': session.target,
            'platform': session.platform.value,
            'shell_type': session.shell_type.value,
            'state': session.state.value,
            'engagement_id': session.engagement_id,
            'initial_access_finding_id': session.initial_access_finding_id,
            'execution_context': session.execution_context,
            'scope_decision': session.scope_decision,
            'user': {
                'username': session.user.username,
                'uid': session.user.uid,
                'is_root': session.user.is_root,
            },
            'system': {
                'hostname': session.system.hostname,
                'os': session.system.os,
                'kernel': session.system.kernel,
                'architecture': session.system.architecture,
            },
            'assessment': session.assessment_results,
        })

    @app.route('/findings', methods=['GET'])
    def findings_list():
        auth_err = _require_api_key()
        if auth_err:
            return auth_err
        from modules.findings import FindingRegistry
        registry = FindingRegistry()
        engagement_id = request.args.get('engagement_id', '')
        state = request.args.get('state')
        state_enum = None
        if state:
            from modules.findings import VALID_STATES
            state_enum = VALID_STATES.get(state)
        findings = registry.list(engagement_id=engagement_id,
                                 state=state_enum)
        return jsonify({'findings': [f.to_dict() for f in findings],
                        'total': len(findings)})

    @app.route('/attack-path', methods=['GET'])
    def attack_path():
        auth_err = _require_api_key()
        if auth_err:
            return auth_err
        from modules.attack_path import build_graph
        from modules.findings import FindingRegistry
        from modules.post_exploitation.session import SessionManager

        engagement_id = request.args.get('engagement_id', '')
        findings = [f.to_dict() for f in
                    FindingRegistry().list(engagement_id=engagement_id)]
        sessions = []
        try:
            mgr = SessionManager()
            mgr.load()
            if engagement_id:
                sessions = [
                    {
                        'id': s.id, 'target': s.target,
                        'state': s.state.value,
                        'platform': s.platform.value,
                        'shell_type': s.shell_type.value,
                        'user': {
                            'username': s.user.username,
                            'is_root': s.user.is_root,
                        },
                    } for s in mgr.list()
                    if s.engagement_id == engagement_id
                ]
            else:
                sessions = [
                    {
                        'id': s.id, 'target': s.target,
                        'state': s.state.value,
                        'platform': s.platform.value,
                        'shell_type': s.shell_type.value,
                        'user': {
                            'username': s.user.username,
                            'is_root': s.user.is_root,
                        },
                    } for s in mgr.list()
                ]
        except Exception:
            pass
        graph = build_graph(engagement_id, findings, sessions=sessions)
        return jsonify(graph.to_dict())

    @app.route('/apidocs/')
    def apidocs():
        return (
            "<!DOCTYPE html><html><head><title>Athena REST API</title></head><body>"
            "<h1>Athena REST API</h1><ul>"
            "<li><code>GET /health</code> - health check (no auth)</li>"
            "<li><code>GET /metrics</code> - Prometheus metrics (no auth)</li>"
            "<li><code>POST /scan</code> - queue a scan job (auth)</li>"
            "<li><code>GET /scan/status/&lt;job_id&gt;</code> - job status (auth)</li>"
            "<li><code>POST /scan/url</code> - synchronous single-URL scan (auth)</li>"
            "<li><code>GET /jobs</code> - list jobs (auth)</li>"
            "<li><code>GET /engagements</code> - list engagements (auth)</li>"
            "<li><code>GET /engagements/&lt;id&gt;/scope</code> - scope check (auth)</li>"
            "<li><code>GET /sessions</code> - list assessment sessions (auth)</li>"
            "<li><code>GET /findings</code> - findings registry (auth)</li>"
            "<li><code>GET /attack-path</code> - attack-path graph (auth)</li>"
            "</ul><p>Auth: <code>X-API-KEY</code> header.</p></body></html>",
            200,
            {'Content-Type': 'text/html'},
        )

    return app


def run_web_server(safe_mode: bool = True, host: str = None, port: int = None,
                   debug: bool = False) -> Flask:
    """Create and run the Athena REST API server. Returns the Flask app."""
    if not HAS_FLASK:
        cprint("[!] Flask is required for the API server. Run: pip install flask")
        sys.exit(1)
    app = create_app(safe_mode=safe_mode)
    if host is None:
        host = os.getenv('SERVER_HOST', '0.0.0.0')
    if port is None:
        try:
            port = int(os.getenv('SERVER_PORT', '5000'))
        except ValueError:
            port = 5000
    ssl_context = None
    if os.getenv('HTTPS_ENABLED', 'true').lower() == 'true':
        cert = os.getenv('SSL_CERT', 'cert.pem')
        key = os.getenv('SSL_KEY', 'key.pem')
        if os.path.exists(cert) and os.path.exists(key):
            ssl_context = (cert, key)
        else:
            cprint(f"[!] HTTPS_ENABLED=true but {cert}/{key} not found - serving HTTP")
    scheme = 'https' if ssl_context else 'http'
    cprint(f"[*] Athena REST API listening on {scheme}://{host}:{port}")
    app.run(host=host, port=port, debug=debug, ssl_context=ssl_context)
    return app


#: Pipeline stage → engagement technique mapping (for gating + preflight).
STAGE_TECHNIQUES = {
    "engagement": "recon",
    "recon": "recon",
    "enumeration": "recon",
    "discovery": "scanning",
    "scanning": "scanning",
    "validation": "controlled_validation",
    "initial_access": "exploitation",
    "post_exploitation_assessment": "post_exploitation",
    "attack_path_analysis": "attack_path_correlation",
    "impact_assessment": "risk_impact_assessment",
    "reporting": "evidence",
}


async def run_pipeline_stages(targets: List[str], args: argparse.Namespace) -> None:
    """Execute selected pipeline stages under the orchestrator.

    Each stage runs independently and fails without aborting the pipeline.
    With ``--preflight`` every stage is first explained (WHAT / WHY /
    TARGET / IN SCOPE / EXPECTED EVIDENCE) and executed only when an
    engagement authorizes it; confirmation-required stages are gated.
    """
    from modules.engagement import ad_hoc_engagement, EngagementStore
    from modules.logging_config import audit_logger

    if not targets:
        cprint("[!] Pipeline stages require a target "
              "(-t TARGET or -f TARGET_FILE)")
        sys.exit(1)

    stage_keys = args.stage or [s.key for s in STAGE_BY_KEY.values()]

    engagement = None
    if args.engagement_id:
        store = EngagementStore()
        engagement = store.get(args.engagement_id)
        if engagement is None:
            cprint(f"[!] Unknown engagement id: {args.engagement_id}")
            sys.exit(1)
    else:
        engagement = ad_hoc_engagement(targets)

    cleanup = CleanupManager(audit=audit_logger, engagement_id=engagement.id)
    orchestrator = PipelineOrchestrator(engagement_id=engagement.id,
                                        audit=audit_logger)
    gate = OperationGate(engagement=engagement, operator="cli",
                         audit=audit_logger, cleanup=cleanup)

    audit_logger.log_operation(
        operator="cli", action="PIPELINE_START", target=",".join(targets),
        result="INITIATED", engagement_id=engagement.id, module="cli",
        authorization_decision="PENDING",
        scope_decision=("in_scope"
                        if engagement.check_target(targets[0]).allowed
                        else "blocked_by_scope"),
        details=f"stages={','.join(stage_keys)} preflight={args.preflight}")

    async def runner_for(stage_key: str):
        spec = STAGE_BY_KEY.get(stage_key)
        technique = STAGE_TECHNIQUES.get(stage_key, "")

        async def _module_runner():
            if stage_key == "discovery":
                return await run_discovery(
                    targets[0], args.output,
                    ["tcp_connect"],
                    parse_ports(args.ports) if args.ports else None,
                    args.concurrent, args.rate, args.jitter)
            if stage_key == "enumeration":
                return await run_enumeration(targets[0], [])
            if stage_key == "scanning":
                return await run_vuln_scan(targets[0], None, False)
            if stage_key == "reporting":
                return await generate_report(
                    targets[0], {}, [], {}, {}, [], args.output, args.export)
            raise StructuredError(
                "STAGE_NOT_IMPLEMENTED",
                f"stage {stage_key!r} has no autonomous module yet; "
                "it is an orchestration seam awaiting a module",
                details={"produced_by_spec":
                         list(spec.produces) if spec else []})
        return technique, _module_runner

    for index, stage_key in enumerate(stage_keys, start=1):
        if stage_key not in STAGE_BY_KEY:
            cprint(f"[!] Unknown stage: {stage_key!r}")
            cprint("    Valid stages: " + ", ".join(STAGE_BY_KEY))
            sys.exit(1)
        spec = STAGE_BY_KEY[stage_key]
        technique, runner = await runner_for(stage_key)
        plan = gate.plan(
            action=f"{spec.name} (pipeline stage)",
            rationale=spec.description or spec.name,
            target=targets[0], technique=technique,
            expected_evidence=list(spec.produces),
            requires_confirmation=engagement.requires_confirmation(technique),
        )

        if args.preflight:
            cprint(f"\n[{index}/{len(stage_keys)}] " + plan.explain())
            confirmation = not plan.requires_confirmation

        in_scope = engagement.check_target(targets[0]).allowed
        if args.preflight:
            outcome = await gate.execute(
                plan, runner, timeout_seconds=0,
                confirmation=confirmation)
            state = outcome["state"]
            error = outcome.get("error")
        else:
            result = await orchestrator.run_stage(
                stage_key, runner, in_scope=in_scope)
            state = result.state.value
            error = result.error

        cprint(f"    -> stage {stage_key!r} ended with state {state}"
              + (f" ({error['code']})" if error else ""))

    cprint("\n" + json.dumps(orchestrator.report(), indent=2, default=str))
    if args.preflight:
        cleanup.cleanup()

    audit_logger.log_operation(
        operator="cli", action="PIPELINE_END", target=",".join(targets),
        result="COMPLETED", engagement_id=engagement.id, module="cli",
        authorization_decision="AUTHORIZED",
        scope_decision="in_scope",
        details=f"stages_run={','.join(orchestrator.results)}")


async def main():
    args = parse_args()
    if getattr(args, 'no_color', False):
        con.disable()

    if args.mode:
        args.mode = MODE_ALIASES.get(args.mode, args.mode)

    if args.unsafe:
        FrameworkConfig.SAFE_MODE = False
        os.environ['AETHELRED_SAFE_MODE'] = 'false'

    if args.api or args.mode == 'api':
        run_web_server(safe_mode=FrameworkConfig.SAFE_MODE,
                       host=args.api_host, port=args.api_port, debug=args.verbose)
        return

    if args.guide is not None:
        if args.export:
            path = generate_guide_json(args.export)
            cprint(f'Guide exported to {path}')
        else:
            show_guide(args.guide if args.guide else None)
        return

    if getattr(args, 'list_tools', False):
        await show_tool_status()
        return

    if args.list_plugins:
        loader = PluginLoader()
        plugins = loader.list_plugins()
        cprint("Available Plugins:")
        for p in plugins:
            cprint(f"  - {p.get('name', 'Unknown')}: {p.get('description', '')}")
        return

    if args.list_stages:
        for s in stage_list():
            cprint(f"  {s['key']:<28} {s['name']} "
                  f"(produces: {', '.join(s['produces']) or 'none'})")
        return

    if args.stage or args.preflight:
        targets = (resolve_targets(args)
                   if args.target or args.target_file else [])
        await run_pipeline_stages(targets, args)
        return

    if args.post or args.post_shell or args.post_list_sessions or args.post_interactive:
        targets = resolve_targets(args) if args.target or args.target_file else []
        await run_post_exploitation(targets, args)
        return

    if args.verbose:
        os.environ['ATHENA_LOG_LEVEL'] = 'DEBUG'

    if args.profile:
        load_config(args.profile)

    if args.tor:
        args.proxy = 'socks5://127.0.0.1:9050'

    targets = resolve_targets(args)

    try:
        await run_scan_session(targets, args)
    except KeyboardInterrupt:
        cprint("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        cprint(f"\n[!] Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    if args.post:
        await run_post_exploitation(targets, args)


if __name__ == '__main__':
    load_config()
    setup_logging()
    asyncio.run(main())
