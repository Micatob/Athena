import asyncio
import sys
import os
import json
import argparse
import html
import threading
import time
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
        print("[!] No target specified. Use -t TARGET or -f TARGET_FILE")
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
    if not port_str or port_str == 'top100':
        return []
    if port_str == 'top1000':
        return []
    if port_str == 'all':
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
            print(f"  [*] {self.desc}: {n}/{self.total}", end='\r')

    def close(self):
        if self.pbar:
            self.pbar.close()


async def run_discovery(target: str, output_format: str = 'html',
                         scan_types: List[str] = None, ports: List[int] = None,
                         concurrent: int = 200, rate: int = 1000, jitter: int = 0) -> Dict[str, Any]:
    print(f"\n{'='*60}")
    print(f"  PHASE 1: DISCOVERY & RECONNAISSANCE")
    print(f"{'='*60}\n")
    discovery = DiscoveryModule()
    try:
        results = await discovery.run(target)
        print(f"  [+] Harvesting emails...")
        urls = results.get('urls', [])
        emails = await discovery.harvest_emails(target, urls)
        if emails:
            results['emails'] = emails
        if scan_types:
            print(f"  [+] Advanced port scanning ({', '.join(scan_types)})...")
            adv_ports = ports or None
            adv_results = await discovery.scan_ports_advanced(
                target, scan_types=scan_types, ports=adv_ports,
                concurrent=concurrent, rate_limit=rate, jitter=jitter/1000.0
            )
            results['advanced_ports'] = adv_results
        return results
    finally:
        await discovery.close()


async def run_vuln_scan(target: str, urls: List[str] = None,
                         stealth: bool = False) -> List[Dict[str, Any]]:
    print(f"\n{'='*60}")
    print(f"  PHASE 2: VULNERABILITY SCANNING")
    print(f"{'='*60}\n")
    if not urls:
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        urls = [target.rstrip('/') + '/']
    scanner = VulnerabilityScanner(stealth_mode=stealth)
    try:
        results = await scanner.scan_all(urls)
        return results
    finally:
        await scanner.close()


async def run_bruteforce(target: str, discovery_results: Dict[str, Any] = None) -> Dict[str, Any]:
    print(f"\n{'='*60}")
    print(f"  PHASE 3: BRUTEFORCING & AUTH TESTING")
    print(f"{'='*60}\n")
    results: Dict[str, Any] = {'web_logins': [], 'service_creds': [], 'default_creds': [], 'admin_panels': []}
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
        print(f"  [*] HIGH-VALUE TARGETS: {len(admin_login_forms)} admin panel login forms (cPanel/Webmail/WHM)")
        for i, form in enumerate(admin_login_forms, 1):
            source = form.get('source', 'UNKNOWN')
            print(f"      {i}. [{source}] {form['url']}")
    
    if admin_panels:
        print(f"  [*] Discovered {len(admin_panels)} admin panels:")
        results['admin_panels'] = admin_panels
        for panel in admin_panels[:10]:  # Show top 10
            panel_type = panel.get('panel_type', 'UNKNOWN')
            print(f"      - [{panel_type}] {panel['url']} (HTTP {panel['status']})")
    
    # Combine: admin panels first, then filtered regular forms
    all_forms = admin_login_forms + filtered_forms
    
    if all_forms:
        print(f"\n  [*] Bruteforcing {len(all_forms)} login forms ({len(admin_login_forms)} admin, {len(filtered_forms)} regular)...")
        
        # Use AI to analyze and prioritize forms
        from modules.ai_integration import AIIntegration
        ai_engine = AIIntegration()
        
        if ai_engine.enabled:
            print(f"  [*] AI analyzing target priority ({ai_engine.provider.value})...")
            try:
                prioritized = await ai_engine.prioritize_bruteforce_targets(all_forms)
                if prioritized:
                    all_forms = prioritized
                    print(f"  [+] AI prioritized targets for optimal efficiency")
            except Exception as e:
                print(f"  [-] AI prioritization failed, using default order: {e}")
        
        bf = BruteforceModule()
        try:
            # Use intelligent bruteforce for admin panels, regular for others
            if admin_login_forms:
                print(f"\n  [*] Phase 3a: Intelligent bruteforce on admin panels...")
                creds = await bf.intelligent_bruteforce(admin_login_forms)
                results['web_logins'].extend(creds)
            
            if filtered_forms:
                print(f"\n  [*] Phase 3b: Standard bruteforce on regular login forms...")
                creds = await bf.bruteforce_login_forms(filtered_forms)
                results['web_logins'].extend(creds)
        finally:
            await bf.close()
    else:
        print(f"  [*] No login forms to bruteforce (filtered out registration/signup forms)")

    host = target.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    service_bf = ServiceBruteforcer()
    port_service_map = {
        21: 'ftp', 22: 'ssh', 3306: 'mysql', 5432: 'postgresql',
        1433: 'mssql', 6379: 'redis', 23: 'telnet',
    }
    for port, service in port_service_map.items():
        if port in ports:
            print(f"  [*] Checking default credentials on {service}://{host}:{port}")
            creds = await service_bf.bruteforce_service(host, port, service, ['root', 'admin'], ['root', 'admin'])
            results['service_creds'].extend(creds)
            for c in creds:
                if c.success:
                    print(f"    [+] Default credentials found: {c.username}:{c.password} on {service}")

    return results


async def run_enumeration(target: str, ports: List[int] = None) -> Dict[str, Any]:
    print(f"\n{'='*60}")
    print(f"  PHASE: ENUMERATION")
    print(f"{'='*60}\n")
    results: Dict[str, Any] = {}
    host = target.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    port_map = {445: 'smb', 161: 'snmp', 25: 'smtp', 587: 'smtp', 465: 'smtp', 139: 'smb',
                110: 'pop3', 995: 'pop3', 143: 'imap', 993: 'imap'}

    if ports:
        for port in ports:
            service = port_map.get(port)
            if service == 'smb':
                print(f"  [*] SMB enumeration on {host}:{port}")
                smb = SMBEnumerator()
                results['smb'] = await smb.enumerate(host, port)
                if results['smb'].get('accessible'):
                    print(f"    [+] SMB accessible: {results['smb'].get('os_version', 'unknown')}")
            elif service == 'snmp':
                print(f"  [*] SNMP enumeration on {host}:{port}")
                snmp = SNMPEnumerator()
                results['snmp'] = await snmp.enumerate(host, port)
                if results['snmp'].get('accessible'):
                    print(f"    [+] SNMP accessible, community: {results['snmp'].get('community', 'N/A')}")
            elif service == 'smtp':
                print(f"  [*] SMTP enumeration on {host}:{port}")
                smtp = SMTPEnumerator()
                results['smtp'] = await smtp.enumerate(host, port)
                if results['smtp'].get('accessible'):
                    print(f"    [+] SMTP accessible ({results['smtp'].get('transport', 'plain')}): {results['smtp'].get('banner', '')[:60]}")
            elif service == 'pop3':
                print(f"  [*] POP3 enumeration on {host}:{port}")
                pop3 = POP3Enumerator()
                results['pop3'] = await pop3.enumerate(host, port)
                if results['pop3'].get('accessible'):
                    print(f"    [+] POP3 accessible: {results['pop3'].get('banner', '')[:60]}")
            elif service == 'imap':
                print(f"  [*] IMAP enumeration on {host}:{port}")
                imap = IMAPEnumerator()
                results['imap'] = await imap.enumerate(host, port)
                if results['imap'].get('accessible'):
                    print(f"    [+] IMAP accessible: {results['imap'].get('banner', '')[:60]}")

    return results


async def run_cve_mapping(technologies: List[Dict[str, Any]]) -> List[VersionCVEResult]:
    print(f"\n{'='*60}")
    print(f"  PHASE: CVE MAPPING")
    print(f"{'='*60}\n")
    mapper = CVEMapper()
    results = await mapper.map_versions(technologies)
    for r in results:
        if r.cves:
            print(f"  [+] {r.technology} {r.version}: {len(r.cves)} CVEs (max CVSS: {r.max_cvss})")
            for cve in r.cves[:3]:
                print(f"      - {cve.cve_id}: {cve.description[:80]}...")
    return results


def generate_report(target: str, discovery: Dict[str, Any], vulnerabilities: List[Dict[str, Any]],
                     bruteforce: Dict[str, Any] = None, enumeration: Dict[str, Any] = None,
                     cve_results: List[VersionCVEResult] = None,
                     output_format: str = 'html', output_path: str = None,
                     ai_analysis: Dict[str, Any] = None) -> str:
    report_gen = ReportGenerator()
    report_data = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'discovery': discovery,
        'vulnerabilities': vulnerabilities,
        'exploitation': [],
    }
    if ai_analysis:
        report_data['ai_analysis'] = ai_analysis
    if bruteforce:
        report_data['bruteforce'] = bruteforce
    if enumeration:
        report_data['enumeration'] = enumeration
    if cve_results:
        cve_dicts = []
        for r in cve_results:
            cve_dicts.append({
                'technology': r.technology, 'version': r.version,
                'confidence': r.confidence,
                'cves': [{'cve_id': c.cve_id, 'description': c.description,
                          'cvss_score': c.cvss_score, 'exploit_available': c.exploit_available}
                         for c in r.cves],
                'max_cvss': r.max_cvss,
            })
        report_data['cve_mapping'] = cve_dicts

    report = report_gen.generate_comprehensive_report(report_data)

    safe_name = target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
    if not output_path:
        output_path = f"report_{safe_name}"

    if output_format in ('html', 'all'):
        html_content = _generate_html_report(report)
        html_path = f"{output_path}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"  [+] HTML report: {html_path}")

    if output_format in ('json', 'all'):
        json_path = f"{output_path}.json"
        report_gen.export_to_json(report, json_path)
        print(f"  [+] JSON report: {json_path}")

    if output_format in ('csv', 'all'):
        csv_path = f"{output_path}.csv"
        report_gen.export_to_csv(report_data, csv_path)
        print(f"  [+] CSV report: {csv_path}")

    if output_format in ('pdf', 'all'):
        pdf_path = f"{output_path}.pdf"
        ok = report_gen.generate_pdf_report(report, pdf_path)
        if ok:
            print(f"  [+] PDF report: {pdf_path}")

    return output_path


def _generate_html_report(report: Dict[str, Any]) -> str:
    audit = report.get('athena_security_audit', report)
    summary = audit.get('audit_summary', {})
    sev = summary.get('severity_breakdown', {})
    vulns = audit.get('detailed_analysis', {})

    critical_count = sev.get('critical', 0)
    high_count = sev.get('high', 0)
    medium_count = sev.get('medium', 0)

    vuln_rows = ''
    for vtype, vinfo in vulns.items():
        s = vinfo.get('severity', 'UNKNOWN')
        color = {'CRITICAL': '#ff4444', 'HIGH': '#ff8800', 'MEDIUM': '#ffbb33', 'LOW': '#ffdd55'}.get(s, '#999')
        assets = ', '.join(vinfo.get('assets_affected', [])[:3])
        techniques = ''.join(f"<li>{t}</li>" for t in vinfo.get('attack_techniques', []))
        tools = ', '.join(vinfo.get('tools', []))
        gains = vinfo.get('attacker_gains', '')
        
        # Build confirmed findings table
        confirmed_findings = vinfo.get('confirmed_findings', [])
        findings_html = ''
        if confirmed_findings:
            findings_html = '<div class="confirmed-findings"><strong>Confirmed Findings:</strong><table class="findings-table">'
            findings_html += '<tr><th>URL</th><th>Payload</th><th>Response</th></tr>'
            for finding in confirmed_findings[:10]:  # Limit to 10
                url = finding.get('url', '')
                payload = finding.get('payload', '')
                desc = finding.get('description', '')
                findings_html += f'<tr><td><code>{url}</code></td><td><code>{payload}</code></td><td>{desc}</td></tr>'
            findings_html += '</table></div>'
        
        vuln_rows += f"""
        <tr>
            <td><span class="sev-badge" style="background:{color}">{s}</span></td>
            <td>{vtype}</td>
            <td>{assets}</td>
            <td>{vinfo.get('description', '')}
                {findings_html}
                <details class="attack-details">
                    <summary>How an attacker compromises this</summary>
                    <ol class="attack-steps">{techniques}</ol>
                    <p><strong>Attacker gains:</strong> {gains}</p>
                    <p><strong>Tools:</strong> {tools}</p>
                </details>
            </td>
        </tr>"""

    tech_items = ''
    for t in audit.get('discovery_findings', {}).get('technologies_with_confidence', []):
        tech_items += f"<li>{t.get('technology')} (confidence: {t.get('confidence')})</li>"
    if not tech_items:
        for t in audit.get('discovery_findings', {}).get('technologies', []):
            tech_items += f"<li>{t}</li>"

    rec_items = ''
    for r in audit.get('remediation_recommendations', []):
        rec_items += f"""
        <div class="rec-item">
            <strong>{r.get('issue')}</strong> ({r.get('severity')})<br>
            {r.get('recommendation')}
            <em>Timeline: {r.get('timeline')}</em>
        </div>"""

    no_findings = audit.get('no_vulnerabilities_found', False)
    asset_summary = summary.get('assets_discovered', {})
    asset_text = (f"{asset_summary.get('open_ports', 0)} open ports, "
                  f"{asset_summary.get('urls', 0)} URLs, "
                  f"{asset_summary.get('subdomains', 0)} subdomains, "
                  f"{asset_summary.get('technologies', 0)} technologies")

    discovery_findings = audit.get('discovery_findings', {})
    port_items = ''.join(f"<li>{p}</li>" for p in discovery_findings.get('open_ports', [])[:50])
    url_items = ''.join(f"<li>{html.escape(str(u))}</li>" for u in discovery_findings.get('urls', [])[:50])
    sub_items = ''.join(f"<li>{html.escape(str(s))}</li>" for s in discovery_findings.get('subdomains', [])[:50])

    admin_items = ''.join(
        f"<li><strong>[{html.escape(str(p.get('panel_type', 'UNKNOWN')))}]</strong> "
        f"<code>{html.escape(str(p.get('url', '')))}</code> "
        f"(HTTP {html.escape(str(p.get('status', '')))})</li>"
        for p in discovery_findings.get('admin_panels', [])[:50]
    )
    admin_section = (f"<h2>Admin Panels &amp; High-Value Targets</h2><ul>{admin_items}</ul>"
                     if admin_items else "")

    # --- Consolidated phase sections (credentials, services, CVEs, AI) ---
    bf = audit.get('bruteforce_findings', {}) or {}
    bf_section = ''
    web_creds = bf.get('successful_web_logins', [])
    svc_creds = bf.get('successful_service_logins', [])
    if web_creds or svc_creds or bf.get('admin_panels'):
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
        bf_section = f"""
    <h2>Authentication &amp; Credential Testing</h2>
    <p>Login forms and services tested during the bruteforce phase. Any row below
    is a confirmed credential.</p>
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

    cve_rows_list = audit.get('cve_mapping', []) or []
    if cve_rows_list:
        rows = ''
        for entry in cve_rows_list:
            cves = entry.get('cves', []) or []
            cve_items = ''.join(
                f"<li><code>{html.escape(str(c.get('cve_id', '')))}</code> "
                f"(CVSS {html.escape(str(c.get('cvss_score', '')))}) - "
                f"{html.escape(str(c.get('description', ''))[:160])}</li>"
                for c in cves[:5]
            )
            rows += (f"<tr><td>{html.escape(str(entry.get('technology', '')))}</td>"
                     f"<td>{html.escape(str(entry.get('version', '')) or 'unknown')}</td>"
                     f"<td><ul>{cve_items or '<li><em>No mapped CVEs</em></li>'}</ul></td></tr>")
        cve_section = f"""
    <h2>CVE Mapping (version-based)</h2>
    <table><thead><tr><th>Technology</th><th>Version</th><th>Candidate CVEs</th></tr></thead>
    <tbody>{rows}</tbody></table>"""
    else:
        cve_section = ''

    ai = audit.get('ai_assistant', {}) or {}
    ai_section = ''
    if ai:
        fp_rows = ''.join(
            f"<tr><td>{html.escape(str(f.get('type', '')))}</td>"
            f"<td><code>{html.escape(str(f.get('url', '')))}</code></td>"
            f"<td>{html.escape(str(f.get('reason', ''))[:200])}</td>"
            f"<td>{f.get('confidence', '')}</td></tr>"
            for f in (ai.get('false_positive_details') or [])[:20]
        )
        ai_section = f"""
    <h2>AI Advisory Notes</h2>
    <p>Provider: <code>{html.escape(str(ai.get('provider', '')))}</code>
       / <code>{html.escape(str(ai.get('model', '')))}</code>.
       <strong>Advisory only</strong> - no finding was reclassified or removed by the
       model; deterministic validation remains authoritative.
       Statements: {ai.get('statement_count', 0)}.
       Consolidated {ai.get('consolidation', {}).get('raw_findings', 0)} raw detections into
       {ai.get('consolidation', {}).get('unique_findings', 0)} unique findings.</p>
    {'<table><thead><tr><th>Type</th><th>URL</th><th>AI reason</th><th>Conf.</th></tr></thead><tbody>' + fp_rows + '</tbody></table>' if fp_rows else '<p><em>No false-positive hypotheses raised.</em></p>'}"""


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
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0a0a0f; color: #e0e0e0; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
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
.confirmed-findings {{ margin: 10px 0; padding: 10px; background: #0d1117; border-radius: 6px; border: 1px solid #30363d; }}
.findings-table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.85em; }}
.findings-table th {{ background: #161b22; padding: 6px 8px; text-align: left; font-weight: 600; color: #58a6ff; border-bottom: 1px solid #30363d; }}
.findings-table td {{ padding: 5px 8px; border-bottom: 1px solid #21262d; word-break: break-all; }}
.findings-table tr:hover {{ background: #1c2128; }}
.findings-table code {{ color: #79c0ff; font-size: 0.9em; background: #161b22; padding: 2px 4px; border-radius: 3px; }}
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
            <tr><td><strong>Open Ports</strong></td><td>{port_items or '<em>None detected</em>'}</td></tr>
            <tr><td><strong>URLs</strong></td><td>{url_items or '<em>None detected</em>'}</td></tr>
            <tr><td><strong>Subdomains</strong></td><td>{sub_items or '<em>None detected</em>'}</td></tr>
        </tbody>
    </table>

    {admin_section}

    {bf_section}

    {enum_section}

    {cve_section}

    <h2>Vulnerability Details</h2>
    <table>
        <thead><tr><th>Severity</th><th>Type</th><th>Affected</th><th>Description</th></tr></thead>
        <tbody>{vuln_rows}</tbody>
    </table>

    <h2>Remediation Recommendations</h2>
    {rec_items}

    {ai_section}

    <h2>Compliance</h2>
    <pre style="background:#1a1a2e;padding:15px;border-radius:6px;overflow-x:auto;">{json.dumps(audit.get('compliance_audit', {}), indent=2, default=str)}</pre>
</div>
</body>
</html>"""


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
                                        ensemble_triage)

    engine = AIIntegration()
    if not engine.enabled:
        return {}

    findings_payload = [
        {"id": str(i),
         "title": str(v.get("title") or v.get("type") or "finding"),
         "type": v.get("type", ""),
         "severity": v.get("severity", ""), "url": v.get("url", ""),
         "payload": v.get("payload", ""),
         "description": str(v.get("description", ""))[:300]}
        for i, v in enumerate(vulnerabilities)
    ]
    print(f"\n  [*] AI-assisted analysis ({engine.provider.value}:{engine.model}) ...")

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
    print(f"  [*] Validating {len(consolidated)} consolidated findings "
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
            sample = (vulnerabilities[raw_indices[0]]
                      if raw_indices else {})
            if fp_printed < 10:
                print(f"      [AI-FP] Potential false positive: "
                      f"{sample.get('type')} at {sample.get('url')}")
                fp_printed += 1
        hidden_fp = len(validated.statements) - fp_printed
        if hidden_fp > 0:
            print(f"      [AI-FP] ... and {hidden_fp} more hypothesis/FP "
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
        print(f"      {label} {stmt.content[:150]}")
    if len(queue) > max_lines:
        print(f"      [AI] ... and {len(queue) - max_lines} more advisory "
              "statement(s) (full list in the report)")
    print("      [*] AI output is advisory; findings are not reclassified.")
    return ai_analysis


async def run_scan_session(targets: List[str], args: argparse.Namespace) -> None:
    scan_types_map = {
        'tcp_connect': 'tcp_connect', 'syn': 'syn_stealth', 'syn_stealth': 'syn_stealth',
        'udp': 'udp', 'ack': 'ack', 'fin': 'fin', 'null': 'null', 'xmas': 'xmas',
    }
    scan_types = [scan_types_map.get(s.strip(), s.strip()) for s in args.scan.split(',')]

    state = ScanState.load() if args.resume else None

    for target in targets:
        print(f"\n{'='*60}")
        print(f"  ATHENA SECURITY SUITE")
        print(f"  Target: {target}")
        print(f"  Profile: {args.profile or os.getenv('AETHELRED_PROFILE', 'balanced')}")
        print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

        discovery_results: Dict[str, Any] = {}
        vulnerabilities: List[Dict[str, Any]] = []
        bruteforce_results: Dict[str, Any] = {}
        enumeration_results: Dict[str, Any] = {}

        if args.mode in ('full', 'all', 'discovery', 'recon'):
            discovery_results = await run_discovery(
                target, args.output, scan_types,
                parse_ports(args.ports) if args.ports else None,
                args.concurrent, args.rate, args.jitter
            )
            if args.pause:
                input("  [*] Paused. Press Enter to continue...")

        if args.mode in ('full', 'all', 'vuln'):
            stealth = args.profile == 'stealth' or (args.profile is None and False)
            vulnerabilities = await run_vuln_scan(target, discovery_results.get('urls'), stealth)
            if args.pause:
                input("  [*] Paused. Press Enter to continue...")

        if args.mode in ('full', 'all', 'bruteforce', 'recon'):
            bruteforce_results = await run_bruteforce(target, discovery_results)

        if args.mode in ('full', 'all', 'recon', 'discovery'):
            ports = discovery_results.get('ports', [])
            enumeration_results = await run_enumeration(target, ports)

        cve_results = []
        if args.mode in ('full', 'all', 'recon'):
            tech_list = discovery_results.get('technologies_with_confidence', [])
            if not tech_list:
                tech_list = [{'technology': t, 'version': '', 'confidence': 1} for t in discovery_results.get('technologies', [])]
            if tech_list:
                cve_results = await run_cve_mapping(tech_list)

        # Run AI analysis and filter false positives
        ai_analysis = {}
        if vulnerabilities or discovery_results:
            ai_analysis = await run_ai_analysis(
                target, discovery_results, vulnerabilities,
                {"mode": args.mode}
            )
            
            # Filter out false positives identified by AI
            filtered_indices = ai_analysis.get("filtered_indices", [])
            if filtered_indices:
                original_count = len(vulnerabilities)
                vulnerabilities = [v for i, v in enumerate(vulnerabilities) if i not in filtered_indices]
                filtered_count = original_count - len(vulnerabilities)
                if filtered_count > 0:
                    print(f"  [*] AI filtered {filtered_count} potential false positives "
                          f"({original_count} -> {len(vulnerabilities)} findings); "
                          "full list recorded in the report")

        output_path = generate_report(
            target, discovery_results, vulnerabilities, bruteforce_results,
            enumeration_results, cve_results, args.output, args.export,
            ai_analysis=ai_analysis
        )

        # Hand the scan's findings to the post-exploitation stage so its
        # roadmap is built from real results when --post follows a scan.
        args.scan_results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": list(vulnerabilities),
            "discovery": discovery_results or {},
            "bruteforce": bruteforce_results or {},
            "exploitation": [],
        }

        print(f"\n{'='*60}")
        print(f"  SCAN COMPLETE")
        print(f"  Target: {target}")
        print(f"  Report: {output_path}")
        print(f"{'='*60}\n")


async def run_post_exploitation(targets: List[str], args: argparse.Namespace) -> None:
    if not HAS_POST:
        print("[!] Post-exploitation modules not available. Check installation.")
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
            print(f"[!] {exc}")
            return
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
            print("No saved sessions.")
            return
        for s in sessions:
            print(f"  {s.id}: {s.target} [{s.platform.value}] {s.user.username} ({s.state.value})")
        return

    if args.post_shell == "reverse":
        print(f"[*] Starting reverse shell listener on {args.post_host}:{args.post_port}")
        await orchestrator.start_listener(args.post_host, args.post_port)
        print("[*] Waiting for an inbound shell "
              f"(up to {args.post_wait:g}s; use --post-payload to print a "
              "reconnecting payload)")
        session = await orchestrator.session_mgr.wait_for_session(
            timeout=max(0.0, float(args.post_wait or 10.0)))
        if not session:
            print(f"[!] No session received within {args.post_wait:g}s. "
                  "Use --post-interactive after a session connects.")
            return
        print(f"[+] Session {session.id} received from {session.target}")
        if engagement is not None and not _enforce_session_scope(orchestrator, session,
                                                                 engagement):
            return

    elif args.post_shell == "bind":
        if not targets:
            print("[!] Need target for bind shell connection")
            return
        target = targets[0].replace("https://", "").replace("http://", "").split("/")[0]
        print(f"[*] Connecting to bind shell at {target}:{args.post_port}")
        session = await _register_scoped_bind(orchestrator, target, args, engagement)
        if not session:
            return

    elif args.post_shell == "web":
        url = args.post_web_url or targets[0] if targets else ""
        if not url:
            print("[!] Need --post-web-url for web shell")
            return
        session = await _register_scoped_web(orchestrator, url, args, engagement)
        if not session:
            return
        print(f"[+] Web shell registered: {url}")
    else:
        if not targets:
            print("[!] No target specified for post-exploitation")
            return
        if engagement is None:
            print("[!] No engagement could be established for post-exploitation; "
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
    print(f"\n{'='*60}")
    print(f"  POST-EXPLOITATION CHAIN")
    print(f"  Session: {session.id} | Target: {session.target}")
    if engagement is not None:
        print(f"  Engagement: {engagement.id} ({engagement.name})")
    print(f"{'='*60}\n")

    results = await orchestrator.run_full_chain(session, interactive=manual, manual_mode=manual)

    report = orchestrator.generate_report(session.id)
    print(f"\n{'='*60}")
    print(f"  POST-EXPLOITATION COMPLETE")
    print(f"  Sessions succeeded: {report['phases_succeeded']}/{report['phases_completed']}")
    print(f"  Critical findings: {len(report['critical_findings'])}")
    print(f"  Root obtained: {report['is_root']}")
    print(f"  Live sessions: {report.get('sessions_total', 1)}")
    if report.get("edr_policy", {}).get("edr_detected"):
        suppressed = report["edr_policy"].get("suppressed", [])
        print(f"  EDR detected - suppressed: {', '.join(suppressed) or 'none'}")
    roadmap = report.get("roadmap") or {}
    summary = roadmap.get("summary") or {}
    if summary:
        print(f"  Roadmap: {summary.get('phases_applicable', 0)}/"
              f"{summary.get('phases_total', 0)} applicable phase(s), "
              f"{summary.get('actions_total', 0)} action(s) "
              f"({summary.get('actions_by_execution', {}).get('automated', 0)} "
              f"automatable)")
    print(f"{'='*60}\n")

    if report.get("sessions"):
        print("  Tracked sessions:")
        for row in report["sessions"]:
            parent = f" <- {row['parent_session']}" if row.get("parent_session") else ""
            print(f"    {row['id']}  {row['target']}  [{row['shell_type']}] "
                  f"{row['state']} scope={row['scope_decision']}{parent}")
        print()

    await _run_post_ai_suggestions(report)

    report_path = f"post_exploit_{session.id}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {report_path}")

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
    print("\n  [*] AI-assisted next steps "
          f"({engine.provider.value}:{engine.model}):")
    for s in steps:
        print(f"      [AI] {s.content[:160]}")


def _resolve_engagement(targets: List[str], args: argparse.Namespace):
    """Establish the engagement used for post-exploitation (fail-closed).

    Priority: ``--scope-file`` → ``--engagement-id`` → explicit ad-hoc from
    ``--target``/targets.  Returns ``None`` when no scope can be established.
    """
    from modules.engagement import (EngagementStore, ad_hoc_engagement,
                                    load_engagement_file)
    if getattr(args, "scope_file", None):
        try:
            engagement = load_engagement_file(args.scope_file)
        except (OSError, ValueError) as exc:
            print(f"[!] Cannot load engagement scope file: {exc}")
            return None
        return engagement
    if getattr(args, "engagement_id", None):
        engagement = EngagementStore().get(args.engagement_id)
        if engagement is None:
            print(f"[!] Engagement '{args.engagement_id}' not found in "
                  f"engagements.json; failing closed.")
            return None
        if not engagement.active:
            print(f"[!] Engagement '{args.engagement_id}' is inactive; failing closed.")
            return None
        return engagement
    if targets:
        return ad_hoc_engagement(list(targets), operator=os.getenv('USER', 'cli'))
    print("[!] No engagement or target list provided; post-exploitation will "
          "fail closed (no scope established).")
    return None


def _enforce_session_scope(orchestrator, session, engagement) -> bool:
    """Kill a session whose target is not proven in scope; returns False on deny."""
    check = engagement.check_target(session.target)
    if check.allowed:
        session.engagement_id = engagement.id
        session.scope_decision = check.decision.value
        return True
    print(f"[!] Session target {session.target!r} is out of scope: "
          f"{check.reason}. Terminating session.")
    import asyncio as _asyncio
    _asyncio.get_event_loop().run_until_complete(
        orchestrator.session_mgr.kill(session.id))
    return False


async def _register_scoped_bind(orchestrator, target: str, args, engagement) -> Optional[object]:
    try:
        session = await orchestrator.register_bind_shell(target, args.post_port)
    except Exception as exc:
        print(f"[!] Failed to connect to bind shell: {exc}")
        return None
    if not session:
        print("[!] Failed to connect to bind shell")
        return None
    if engagement is None:
        print("[!] No engagement established; bind session denied (fail closed).")
        return None
    if not _enforce_session_scope(orchestrator, session, engagement):
        return None
    return session


async def _register_scoped_web(orchestrator, url: str, args, engagement) -> Optional[object]:
    if engagement is None:
        print("[!] No engagement established; web session denied (fail closed).")
        return None
    params = {"cmd": args.post_web_param}
    session = await orchestrator.register_web_shell(url, params, method=args.post_web_method)
    if not session:
        print("[!] Failed to register web shell")
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
        print(f"[!] Session denied: {exc}")
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
        print("[!] Flask is required for the API server. Run: pip install flask")
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
            print(f"[!] HTTPS_ENABLED=true but {cert}/{key} not found - serving HTTP")
    scheme = 'https' if ssl_context else 'http'
    print(f"[*] Athena REST API listening on {scheme}://{host}:{port}")
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
        print("[!] Pipeline stages require a target "
              "(-t TARGET or -f TARGET_FILE)")
        sys.exit(1)

    stage_keys = args.stage or [s.key for s in STAGE_BY_KEY.values()]

    engagement = None
    if args.engagement_id:
        store = EngagementStore()
        engagement = store.get(args.engagement_id)
        if engagement is None:
            print(f"[!] Unknown engagement id: {args.engagement_id}")
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
            print(f"[!] Unknown stage: {stage_key!r}")
            print("    Valid stages: " + ", ".join(STAGE_BY_KEY))
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
            print(f"\n[{index}/{len(stage_keys)}] " + plan.explain())
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

        print(f"    -> stage {stage_key!r} ended with state {state}"
              + (f" ({error['code']})" if error else ""))

    print("\n" + json.dumps(orchestrator.report(), indent=2, default=str))
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
            print(f'Guide exported to {path}')
        else:
            show_guide(args.guide if args.guide else None)
        return

    if args.list_plugins:
        loader = PluginLoader()
        plugins = loader.list_plugins()
        print("Available Plugins:")
        for p in plugins:
            print(f"  - {p.get('name', 'Unknown')}: {p.get('description', '')}")
        return

    if args.list_stages:
        for s in stage_list():
            print(f"  {s['key']:<28} {s['name']} "
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
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
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
