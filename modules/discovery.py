import asyncio
from concurrent.futures import ThreadPoolExecutor
import time
import aiohttp
import socket
import ssl as ssl_module
import logging
from typing import Dict, List, Set, Optional, Any, Sequence
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import random
import re
import json
import struct
from functools import partial
from datetime import datetime
from modules.hidden_asset_scanner import HiddenAssetScanner


#: Worker threads for the TCP connect scan.  The asyncio default
#: executor (~12 workers) is the wrong tool for blocking connects.
PORT_SCAN_WORKERS = 64


class DiscoveryModule:
    #: Every selectable discovery stage, in execution order.  ``stages=``
    #: accepts any subset of these names.
    ALL_STAGES: Sequence[str] = (
        'crawl', 'subdomains', 'ports', 'technologies', 'hidden_dirs',
        'dns', 'tls', 'security_endpoints', 'admin_panels', 'hidden_assets',
    )
    #: Fast recon used by ``-m vuln``: real inventory (URLs, subdomains,
    #: ports, tech, DNS/TLS) without the heavy wordlist-driven phases.
    LIGHT_STAGES: Sequence[str] = (
        'crawl', 'subdomains', 'ports', 'technologies', 'dns', 'tls',
        'security_endpoints', 'admin_panels',
    )

    def __init__(self) -> None:
        self._session: Optional[aiohttp.ClientSession] = None
        self.discovered_urls: Set[str] = set()
        self.discovered_subdomains: Set[str] = set()
        self.technologies: Set[str] = set()
        self.visited_urls: Set[str] = set()
        self.login_forms: List[Dict[str, Any]] = []
        self.discovered_secrets: List[Dict[str, Any]] = []
        self.discovered_comments: List[Dict[str, Any]] = []
        self.discovered_endpoints: Set[str] = set()
        self.scanned_scripts: Set[str] = set()
        self.scanned_stylesheets: Set[str] = set()
        self.logger = logging.getLogger(__name__)
        self._baseline_body: Optional[str] = None
        self._baseline_length: int = 0
        self._tech_confidence: Dict[str, int] = {}

        # Known technology keywords — anything outside these is suspicious
        self._KNOWN_TECH_KEYWORDS = {
            'apache', 'nginx', 'iis', 'php', 'asp.net', 'python', 'java',
            'ruby', 'node.js', 'express', 'flask', 'django', 'laravel',
            'wordpress', 'drupal', 'joomla', 'magento', 'shopify', 'wix',
            'cloudflare', 'varnish', 'akamai', 'fastly', 'openresty',
            'caddy', 'gunicorn', 'lighttpd', 'rails', 'vue.js', 'react',
            'angular', 'next.js', 'alpine.js', 'bootstrap', 'tailwind',
            'jquery', 'spring', 'fastapi', 'server', 'version', 'unknown',
        }

    def _add_tech(self, name: str, confidence: int = 3) -> None:
        self.technologies.add(name)
        current = self._tech_confidence.get(name, 0)
        self._tech_confidence[name] = max(current, confidence)

    def _add_versioned_tech(self, name: str, version: str = '', confidence: int = 3) -> None:
        self._add_tech(name, confidence)
        if version:
            self._add_tech(f"{name} {version}", confidence)

    async def _sanitize_technologies(self) -> None:
        filtered = set()
        for t in self.technologies:
            t_stripped = t.strip()
            if not t_stripped or len(t_stripped) < 2:
                continue
            if t_stripped.startswith('<') or '>' in t_stripped or t_stripped.startswith('<!'):
                self.logger.debug(f"Filtered HTML artifact from technologies: {t_stripped}")
                continue
            if t_stripped.startswith('{') or t_stripped.startswith('['):
                continue
            filtered.add(t_stripped)
        self.technologies = filtered
        
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            conn = aiohttp.TCPConnector(ssl=False)
            self._session = aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=10),
                headers={
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
                }
            )
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def run(self, target: str,
                  stages: Optional[Sequence[str]] = None) -> Dict[str, Any]:
        """Run discovery.

        ``stages`` selects a subset of :attr:`ALL_STAGES`; ``None`` runs
        everything.  Selecting a subset keeps the report's asset inventory
        honest without paying for the heavy wordlist-driven phases.
        """
        # Normalize target URL - add protocol if missing
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
            print(f"[*] Auto-corrected target to: {target}")

        print(f"[*] Starting discovery on {target}")
        self.logger.info(f"Starting discovery on {target}")

        # Fetch baseline response for SPA detection (used by directory enumeration)
        self._baseline_body = None
        self._baseline_length = 0
        try:
            async with (await self._get_session()).get(target, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    self._baseline_body = body
                    self._baseline_length = len(body)
        except Exception:
            self.logger.debug("Could not fetch baseline response for SPA detection")

        wanted = tuple(s for s in self.ALL_STAGES
                       if stages is None or s in stages)
        unknown = set(stages or ()) - set(self.ALL_STAGES)
        if unknown:
            self.logger.warning('Ignoring unknown discovery stages: %s',
                                ', '.join(sorted(unknown)))
        print(f"  [*] Discovery stages: {', '.join(wanted)}")

        stage_tasks: Dict[str, Any] = {}
        if 'crawl' in wanted:
            stage_tasks['crawl'] = self.crawl_urls(target)
        if 'subdomains' in wanted:
            stage_tasks['subdomains'] = self.enumerate_subdomains(target)
        if 'ports' in wanted:
            stage_tasks['ports'] = self.scan_ports(target)
        if 'technologies' in wanted:
            stage_tasks['technologies'] = self.detect_technologies(target)
        if 'hidden_dirs' in wanted:
            stage_tasks['hidden_dirs'] = self.find_hidden_directories(target)
        if 'dns' in wanted:
            stage_tasks['dns'] = self.analyze_dns_records(target)
        if 'tls' in wanted:
            stage_tasks['tls'] = self.check_tls_certificate(target)
        if 'security_endpoints' in wanted:
            stage_tasks['security_endpoints'] = \
                self.discover_security_endpoints(target)
        if 'admin_panels' in wanted:
            stage_tasks['admin_panels'] = self.discover_admin_panels(target)

        # Keyed by stage name so a skipped stage can never shift the index
        # mapping of another one's result.
        hidden_asset_scanner = None
        if 'hidden_assets' in wanted:
            hidden_asset_scanner = HiddenAssetScanner()
            stage_tasks['hidden_assets'] = hidden_asset_scanner.run(
                target, self._baseline_body or "", self._baseline_length)

        stage_names = list(stage_tasks)

        async def _timed_stage(name, coro):
            t0 = time.monotonic()
            try:
                return await coro
            finally:
                print(f"    [time] {name}: {time.monotonic() - t0:.1f}s")

        stage_t0 = time.monotonic()
        gathered = await asyncio.gather(
            *(_timed_stage(n, stage_tasks[n]) for n in stage_names),
            return_exceptions=True)
        print(f"    [time] all discovery stages: "
              f"{time.monotonic() - stage_t0:.1f}s")
        results = dict(zip(stage_names, gathered))
        if hidden_asset_scanner is not None:
            await hidden_asset_scanner.close()

        hidden_asset_results = {}
        for r in results.values():
            if isinstance(r, dict) and ("hidden_directories" in r or "backup_files" in r):
                hidden_asset_results = r
                break

        # Second pass: detect technologies on discovered subdomains
        subdomains = list(self.discovered_subdomains)
        if subdomains:
            print(f"  [*] Second-pass analysis on {len(subdomains)} subdomains...")
            sub_tasks = [self.detect_technologies(sub) for sub in subdomains[:5]]
            await asyncio.gather(*sub_tasks, return_exceptions=True)

        await self._sanitize_technologies()

        # Deduplicate: remove base names when versioned counterparts exist
        versioned_bases = set()
        for t in list(self.technologies):
            parts = t.rsplit(' ', 1)
            if len(parts) == 2 and re.match(r'^\d+\.\d+', parts[1]):
                versioned_bases.add(parts[0])
        for base in versioned_bases:
            if base in self.technologies:
                self.technologies.discard(base)
                self._tech_confidence.pop(base, None)

        # Build structured tech list with confidence
        tech_with_confidence = sorted(
            [{'technology': t, 'confidence': self._tech_confidence.get(t, 3)} for t in self.technologies],
            key=lambda x: (-x['confidence'], x['technology'])
        )

        self.logger.info(f"Discovery completed: {len(self.discovered_urls)} URLs, {len(self.discovered_subdomains)} subdomains, {len(self.technologies)} technologies")

        def _stage(name: str, default):
            value = results.get(name, default)
            return default if isinstance(value, Exception) else value

        return {
            'urls': list(self.discovered_urls),
            'subdomains': list(self.discovered_subdomains),
            'technologies': list(self.technologies),
            'technologies_with_confidence': tech_with_confidence,
            'ports': _stage('ports', []),
            'login_forms': self.login_forms,
            'admin_panels': _stage('admin_panels', []),
            'source_analysis': {
                'secrets': self.discovered_secrets,
                'comments': self.discovered_comments,
                'endpoints': list(self.discovered_endpoints)
            },
            'dns_records': _stage('dns', {}),
            'tls_certificate': _stage('tls', {}),
            'security_endpoints': _stage('security_endpoints', []),
            'hidden_assets': hidden_asset_results if hidden_asset_results else {},
            'stages_run': list(wanted),
        }
    
    async def crawl_urls(self, base_url: str) -> None:
        """Advanced crawling with recursive discovery, form detection, HTML comment extraction, and script bundle parsing"""
        try:
            if base_url in self.visited_urls:
                return
            self.visited_urls.add(base_url)
            
            print(f"  [*] Crawling: {base_url}")
            
            async with (await self._get_session()).get(base_url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as response:
                if response.status not in [200, 301, 302]:
                    print(f"    [-] HTTP {response.status}, skipping")
                    return
                    
                content = await response.text()
                print(f"    [+] Got response ({len(content)} bytes)")
                soup = BeautifulSoup(content, 'html.parser')
                
                # HTML developer comments extraction
                html_comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
                for hc in html_comments:
                    comment_text = hc.strip()
                    if not comment_text:
                        continue
                    if self._is_comment_library_noise(comment_text):
                        continue
                    lowered = comment_text.lower()
                    keyword_matches = [k for k in ['todo', 'fixme', 'password', 'key', 'admin', 'secret', 'credentials', 'bypass', 'temp'] if k in lowered]
                    if not keyword_matches:
                        continue
                    if len(keyword_matches) == 1 and len(comment_text.split()) <= 4:
                        continue
                    if not any(c['text'] == comment_text and c['file'] == base_url for c in self.discovered_comments):
                        self.discovered_comments.append({
                            'type': 'HTML Comment',
                            'file': base_url,
                            'text': comment_text
                        })

                # Extract and parse all scripts (both inline and external)
                scripts_found = 0
                for script in soup.find_all('script'):
                    src = script.attrs.get('src')
                    if src:
                        full_src_url = urljoin(base_url, src)
                        parsed_src = urlparse(full_src_url)
                        base_parsed = urlparse(base_url)
                        # Fetch and parse scripts hosted on the target domain netloc
                        if parsed_src.netloc == base_parsed.netloc and full_src_url not in self.scanned_scripts:
                            self.scanned_scripts.add(full_src_url)
                            scripts_found += 1
                            try:
                                async with (await self._get_session()).get(full_src_url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as script_resp:
                                    if script_resp.status == 200:
                                        script_text = await script_resp.text()
                                        self._analyze_script_content(full_src_url, script_text)
                            except Exception as e:
                                self.logger.debug(f"Failed to fetch external script {full_src_url}: {e}")
                    elif script.string:
                        # Inline script analysis
                        self._analyze_script_content(base_url, script.string)

                # Extract and parse all stylesheets
                stylesheets_found = 0
                for link in soup.find_all('link', rel='stylesheet'):
                    href = link.attrs.get('href')
                    if href:
                        full_css_url = urljoin(base_url, href)
                        parsed_css = urlparse(full_css_url)
                        base_parsed = urlparse(base_url)
                        if parsed_css.netloc == base_parsed.netloc and full_css_url not in self.scanned_stylesheets:
                            self.scanned_stylesheets.add(full_css_url)
                            stylesheets_found += 1
                            try:
                                async with (await self._get_session()).get(full_css_url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as css_resp:
                                    if css_resp.status == 200:
                                        css_text = await css_resp.text()
                                        self._analyze_stylesheet_content(full_css_url, css_text)
                            except Exception as e:
                                self.logger.debug(f"Failed to fetch stylesheet {full_css_url}: {e}")

                # Extract all links
                links_found = 0
                for link in soup.find_all('a', href=True):
                    href = link['href'].strip()
                    if href.startswith('#') or href.startswith('javascript:'):
                        continue
                    full_url = urljoin(base_url, href)
                    parsed = urlparse(full_url)
                    base_parsed = urlparse(base_url)
                    
                    if parsed.netloc == base_parsed.netloc:
                        self.discovered_urls.add(full_url)
                        links_found += 1
                        # Recursively crawl if we haven't visited
                        if full_url not in self.visited_urls and len(self.visited_urls) < 50:
                            await self.crawl_urls(full_url)
                
                # Extract forms and parameters
                forms_found = 0
                for form in soup.find_all('form'):
                    action = form.attrs.get('action', '')
                    form_url = urljoin(base_url, action) if action else base_url
                    self.discovered_urls.add(form_url)
                    forms_found += 1

                    # Detect login forms - classify form type
                    has_password = any(inp.get('type') == 'password' for inp in form.find_all('input'))
                    action_lower = action.lower()
                    form_text = form.get_text().lower()
                    form_html = str(form).lower()
                    
                    # Skip registration/signup/password-reset forms
                    is_registration = any(kw in action_lower for kw in ['register', 'signup', 'sign-up', 'create', 'new', 'forgot', 'reset', 'recover'])
                    is_registration = is_registration or any(kw in form_text for kw in ['register', 'signup', 'sign up', 'create account', 'forgot', 'reset password', 'recover'])
                    is_registration = is_registration or any(kw in form_html for kw in ['register', 'signup', 'sign-up', 'create-account', 'forgot-password', 'reset-password'])
                    
                    if is_registration:
                        continue
                    
                    # Classify as login form
                    is_login = has_password or any(kw in action_lower for kw in ['login', 'auth', 'signin', 'log-in', 'sign-in', 'session'])
                    is_login = is_login or any(kw in form_text for kw in ['login', 'log in', 'sign in', 'username', 'email'])
                    
                    if is_login:
                        self.login_forms.append({
                            'url': form_url,
                            'method': form.attrs.get('method', 'post').upper(),
                            'inputs': [{'name': inp.get('name', ''), 'type': inp.get('type', 'text')} for inp in form.find_all('input')],
                            'form_type': 'login',
                            'confidence': 'high' if has_password else 'medium'
                        })
                
                if links_found > 0 or forms_found > 0 or scripts_found > 0 or stylesheets_found > 0:
                    print(f"    [+] Found {links_found} links, {forms_found} forms, {scripts_found} script files parsed, {stylesheets_found} stylesheet files parsed")
        except asyncio.TimeoutError:
            print(f"  [-] Timeout on {base_url}")
            self.logger.warning(f"Timeout crawling {base_url}")
        except Exception as e:
            print(f"  [-] Error crawling {base_url}: {str(e)[:100]}")
            self.logger.exception(f"Error crawling {base_url}: {e}")

    SECRET_PATTERNS = {
        'AWS API Key': r'\b(AIDA[A-Z0-9]{16})\b|\b(AKIA[A-Z0-9]{16})\b',
        'AWS Secret Key': r'(?i)aws(.{0,20})?[\'"]([0-9a-zA-Z\/+]{40})[\'"]',
        'AWS Session Token': r'(?i)aws(.{0,20})?[\'"]([a-z0-9/+]{8,}={0,2})[\'"]\s*[\'"]\w{16,}[\'"]',
        'Google API Key': r'\b(AIzaSy[A-Za-z0-9_-]{33})\b',
        'Google OAuth Key': r'\b([0-9]+-[a-z0-9_]+\.apps\.googleusercontent\.com)\b',
        'Stripe API Key': r'\b(sk_live_[0-9a-zA-Z]{4,})\b|\b(pk_live_[0-9a-zA-Z]{4,})\b',
        'Stripe Restricted Key': r'\b(rk_live_[0-9a-zA-Z]{4,})\b',
        'GitHub Token': r'\b(ghp_[a-zA-Z0-9]{36})\b|\b(gho_[a-zA-Z0-9]{36})\b|\b(ghu_[a-zA-Z0-9]{36})\b|\b(ghs_[a-zA-Z0-9]{36})\b|\b(ghr_[a-zA-Z0-9]{36})\b|\b(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b',
        'GitLab Token': r'\b(glpat-[a-zA-Z0-9\-_]{20,})\b',
        'Slack Token': r'\b(xox[baprs]-[0-9a-zA-Z\-]{10,48})\b',
        'Slack Webhook': r'(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)',
        'Discord Webhook': r'(https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+)',
        'Database Connection String': r'((mongodb|mysql|postgresql|sqlite|oracle|mssql|redshift|snowflake):\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_~@#%^&*()_+={}\[\]|\\:;"\'<>,.?/-]+@[a-zA-Z0-9.-]+:[0-9]+)',
        'Private Key': r'(-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----)',
        'Generic Credential / Token': r'(?i)\b(token|secret|password|passwd|auth_key|jwt_secret|api_key|apikey)\b\s*[:=]\s*[\'"]([a-zA-Z0-9_\-!@#$%^&*()=+]{16,})[\'"]',
        'Firebase Project ID': r'(?i)firebase\.?\s*:\s*\{[^}]*?projectId["\']?\s*[:=]\s*["\']([a-z0-9-]+)["\']',
        'Firebase API Key in JS': r'(?i)apiKey["\']?\s*[:=]\s*["\'](AIzaSy[a-zA-Z0-9_-]{33})["\']',
        'Firebase Config Object': r'(?i)firebase\.?(initializeApp|config)\s*\(\s*\{[^}]{50,}?\}',
        'GCP Service Account': r'(?i)["\']?type["\']?\s*:\s*["\']service_account["\']',
        'Firebase Database URL': r'https?://[a-z0-9-]+\.(firebaseio|firebasedatabase)\.app',
        'Firebase Auth Domain': r'(?i)authDomain["\']?\s*[:=]\s*["\']([a-z0-9-]+\.firebaseapp\.com)["\']',
        'GCP Private Key File': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----(?:.|\n)+?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----',
        'Azure Subscription Key': r'\b(SubscriptionKey=[a-zA-Z0-9]{32})\b',
        'Azure Connection String': r'(DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+=/]+)',
        'Heroku API Key': r'\b(heroku[a-zA-Z0-9_-]{20,})\b',
        'Mailchimp API Key': r'\b([a-f0-9]{32}-us[0-9]{1,2})\b',
        'Twilio API Key': r'\b(SK[a-f0-9]{32})\b',
        'Twilio Auth Token': r'\b([a-f0-9]{32})\b',
        'NPM Token': r'\b(npm_[a-zA-Z0-9]{36})\b',
        'JWT Token': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        'SSH Private Key': r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----',
        'PGP Private Key': r'-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----',
        'Bearer Token in Code': r"""(?i)(['"`])Bearer\s+([a-zA-Z0-9_\-\.]+)\1""",
        'Google Cloud Platform Key': r'\b(ya29\.[a-zA-Z0-9_-]{100,})\b',
        'PEM Certificate': r'-----BEGIN\s+CERTIFICATE-----',
        'PKCS12 Key Store': r'\b[a-fA-F0-9]{64}\b.{0,10}(cert|key|p12|pfx)',
    }

    def _extract_secrets(self, source: str, content: str) -> None:
        """Extract secrets from content using SECRET_PATTERNS and deduplicate."""
        for stype, pattern in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for m in matches:
                val = m.group(0)
                obfuscated = val[:len(val)//2] + "..." if len(val) > 8 else "..."
                snippet_start = max(0, m.start() - 40)
                snippet_end = min(len(content), m.end() + 40)
                snippet = content[snippet_start:snippet_end].replace('\n', ' ').strip()
                if not any(s['value'] == obfuscated and s['file'] == source for s in self.discovered_secrets):
                    self.discovered_secrets.append({
                        'type': stype,
                        'file': source,
                        'value': obfuscated,
                        'snippet': snippet,
                    })

    def _is_comment_library_noise(self, text: str) -> bool:
        """Return True if comment is from a known library/minifier/boilerplate."""
        lowered = text.lower()
        noise_patterns = [
            'license', 'licensed', 'licence', 'copyright', '(c)', '(c)',
            '@license', '@preserve', '@source', '@author', '@file',
            'contributors', 'permission is hereby granted', 'subject to',
            'github.com', 'repository', 'bug report', 'issue tracker',
            'minified', 'compiled by', 'uglify', 'terser', 'webpack',
            'bundle', 'chunk', 'module', 'require(', 'import {',
            'this program is free', 'you should have received',
            'along with this program', 'general public license',
            'mit license', 'apache license', 'bsd license',
            'all rights reserved', 'use of this source',
            'redistribution and use', 'the name of',
            'this file is part of', '* @', 'source map',
            'sourceMappingURL', '# source', 'version 3',
            'is distributed', 'warranty', 'merchantability',
            'fitness for a particular', 'damages', 'liability',
            'strict', 'implied', 'even if', 'shall not',
            'documentation', 'see the', 'note:', 'warning:',
        ]
        if any(p in lowered for p in noise_patterns):
            return True
        if len(text) < 2 or len(text.split()) > 60:
            return True
        if text.startswith(('/', '*', ' *', '**', '#', '@', '<!--')):
            return True
        single_word = text.strip().split()
        if len(single_word) <= 2 and lowered.strip() in (
            'eslint-disable', 'eslint-enable', 'jshint', 'global',
            'globals', 'export', 'ignore', 'istanbul', 'istanbul ignore',
            'prettier', 'tslint', 'flow', 'no-unused', 'no-console',
            'default', 'type:', 'param', 'returns', 'example',
        ):
            return True
        return False

    def _analyze_script_content(self, source: str, content: str) -> None:
        """Analyze script contents for secrets, keys, API endpoints and developer comments."""
        if not content:
            return

        self._extract_secrets(source, content)

        # 2. Developer Comment / TODO Scanner
        # Extract single-line and multi-line comments
        js_comments = re.findall(r'\/\/(.*?)$|\/\*(.*?)\*\/', content, re.MULTILINE | re.DOTALL)
        for jc in js_comments:
            comment_text = (jc[0] or jc[1]).strip()
            if not comment_text:
                continue
            # Filter library/minifier noise before keyword check
            if self._is_comment_library_noise(comment_text):
                continue
            # Check for interesting keywords — require at least 2 keyword matches for short comments
            lowered = comment_text.lower()
            keyword_matches = [k for k in ['todo', 'fixme', 'password', 'key', 'admin', 'secret', 'credentials', 'bypass', 'temp'] if k in lowered]
            if len(keyword_matches) == 0:
                continue
            if len(keyword_matches) == 1 and len(comment_text.split()) <= 4:
                continue
            if not any(c['text'] == comment_text and c['file'] == source for c in self.discovered_comments):
                self.discovered_comments.append({
                    'type': 'Javascript Comment',
                    'file': source,
                    'text': comment_text
                })

        # 3. Dynamic API endpoint scraper
        # Find paths starting with /api/ or v1/ or v2/ inside string literals
        endpoint_matches = re.findall(r'[\'"](\/(?:api|v[0-9]+)[a-zA-Z0-9_./-]*?)[\'"]', content)
        for ep in endpoint_matches:
            if len(ep) > 4 and ep not in self.discovered_endpoints:
                self.discovered_endpoints.add(ep)

    def _analyze_stylesheet_content(self, source: str, content: str) -> None:
        """Analyze stylesheet contents for secrets, keys, API endpoints and developer comments."""
        if not content:
            return

        self._extract_secrets(source, content)

        # 2. Developer Comment / TODO Scanner (CSS comments)
        # CSS comments are /* ... */
        css_comments = re.findall(r'\/\*(.*?)\*\/', content, re.DOTALL)
        for cc in css_comments:
            comment_text = cc.strip()
            if not comment_text:
                continue
            if self._is_comment_library_noise(comment_text):
                continue
            # Check for interesting keywords
            lowered = comment_text.lower()
            keyword_matches = [k for k in ['todo', 'fixme', 'password', 'key', 'admin', 'secret', 'credentials', 'bypass', 'temp'] if k in lowered]
            if not keyword_matches:
                continue
            if len(keyword_matches) == 1 and len(comment_text.split()) <= 4:
                continue
            if not any(c['text'] == comment_text and c['file'] == source for c in self.discovered_comments):
                self.discovered_comments.append({
                    'type': 'CSS Comment',
                    'file': source,
                    'text': comment_text
                })

        # 3. Dynamic endpoint scraper in CSS (e.g., url('/api/endpoint'))
        # Look for url() functions that might contain API endpoints
        url_matches = re.findall(r'url\([\'"]?([^\'")]+)[\'"]?\)', content)
        for url in url_matches:
            # Check if the url looks like an API endpoint
            if re.search(r'/(api|v[0-9]+)/', url):
                if len(url) > 4 and url not in self.discovered_endpoints:
                    self.discovered_endpoints.add(url)
    
    async def enumerate_subdomains(self, target: str) -> None:
        """Comprehensive subdomain enumeration with DNS and HTTP verification"""
        domain = urlparse(target).netloc.split(':')[0]  # Remove port if present
        print(f"  [*] Enumerating subdomains for: {domain}")
        
        # Expanded subdomain list with better coverage
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'v1', 'v2', 'v3', 'api-dev', 'api-staging', 'api-prod',
            'secure', 'mobile', 'shop', 'blog', 'forum', 'news', 'm', 'legacy',
            'old', 'new', 'beta', 'alpha', 'support', 'help', 'vpn', 'webmail',
            'portal', 'backup', 'database', 'git', 'svn', 'wiki', 'stats',
            'monitor', 'proxy', 'cache', 'cdn', 'app', 'dashboard', 'cms',
            'auth', 'oauth', 'sso', 'idp', 'saml', 'ldap', 'owa', 'exchange',
            'autodiscover', 'cpanel', 'whm', 'sftp', 'ssh', 'smtp', 'pop',
            'imap', 'dns', 'ns1', 'ns2', 'ns3', 'ns4', 'mx', 'web',
            'admin1', 'admin2', 'admin3', 'test1', 'test2', 'dev1', 'dev2',
            'staging1', 'staging2', 'api1', 'api2', 'app1', 'app2', 'mobile1',
            'prod', 'production', 'uat', 'preprod', 'qa', 'sandbox', 'demo',
            'jenkins', 'gitlab', 'github', 'docker', 'k8s', 'prometheus',
            'grafana', 'kibana', 'elastic', 'redis', 'rabbit', 'postgres',
            'mysql', 'mongodb', 'ldaps', 'kerberos', 'ntp', 'snmp',
            'images', 'static', 'assets', 'downloads', 'uploads', 'files',
            'media', 'content', 'public', 'private', 'secure', 'internal',
            'extranet', 'intranet', 'partner', 'supplier', 'vendor', 'client',
            # Cloud / DevOps / Modern stack
            'argocd', 'jenkins', 'teamcity', 'bamboo', 'circleci', 'travis',
            'jira', 'confluence', 'bitbucket', 'harbor', 'nexus', 'artifactory',
            'sonar', 'sonarqube', 'codeclimate', 'coveralls',
            'kibana', 'logstash', 'fluentd', 'splunk', 'datadog',
            'newrelic', 'pagerduty', 'opsgenie', 'sensu',
            'iam', 'identity', 'accounts', 'profiles', 'people',
            'remote', 'access', 'gateway', 'jump', 'bastion',
            'services', 'micro', 'mssql', 'oracle', 'cassandra', 'couchdb',
            'influxdb', 'memcached', 'solr', 'kafka', 'zookeeper',
            'jupyter', 'notebook', 'airflow', 'mlflow', 'kubeflow',
            'swagger', 'redoc', 'stoplight', 'postman', 'insomnia',
            'docs', 'developer', 'developers', 'devportal',
            'status', 'statuspage', 'uptime', 'health',
            'metrics', 'statsd', 'graphite', 'jaeger', 'zipkin',
            'registry', 'packages', 'pypi', 'npm', 'maven', 'nuget',
            'edge', 'cdn', 'origin', 'lb', 'loadbalancer',
            'waf', 'firewall', 'ips', 'ids', 'fortinet', 'paloalto',
        ]
        
        # Certificate Transparency first: crt.sh reports names the wordlist
        # would never guess (vpn-02, portal-2024, legacy-clone, ...).
        ct_hosts = await self._crtsh_hosts(domain)
        if ct_hosts:
            print(f"  [+] crt.sh certificate transparency: {len(ct_hosts)} name(s)")

        candidates = {f"{sub}.{domain}" for sub in common_subdomains}
        candidates |= ct_hosts
        candidates.discard(domain)

        async def check_subdomain(full_domain: str):
            try:
                # Try DNS resolution
                try:
                    loop = asyncio.get_event_loop()
                    ip = await loop.run_in_executor(None, socket.gethostbyname, full_domain)
                    self.discovered_subdomains.add(f"http://{full_domain}")
                    self.discovered_subdomains.add(f"https://{full_domain}")
                    print(f"    [+] Found subdomain: {full_domain} ({ip})")
                except Exception:
                    # Try HTTP resolution even if DNS fails
                    try:
                        async with (await self._get_session()).head(f"http://{full_domain}", ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as response:
                            if response.status < 400:
                                self.discovered_subdomains.add(f"http://{full_domain}")
                                print(f"    [+] Found subdomain: {full_domain} (HTTP)")
                    except Exception:
                        self.logger.debug(f"HTTP head check failed for {full_domain}")
            except Exception as e:
                self.logger.debug('check_subdomain outer exception for %s: %s', full_domain, e)

        # Concurrent subdomain checking
        tasks = [check_subdomain(host) for host in sorted(candidates)]
        await asyncio.gather(*tasks, return_exceptions=True)
        print(f"  [+] Subdomain enumeration complete, found {len(self.discovered_subdomains)}")

    async def _crtsh_hosts(self, domain: str) -> Set[str]:
        """Certificate-Transparency names for ``domain`` from crt.sh.

        Free public endpoint, no API key, no binary - one HTTPS call.
        Only in-domain hosts are returned; failures are non-fatal so the
        wordlist pass still runs when crt.sh is unreachable.
        """
        found: Set[str] = set()
        query = f'https://crt.sh/?q=%25.{domain}&output=json'
        try:
            async with (await self._get_session()).get(
                    query, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=25)) as response:
                if response.status != 200:
                    self.logger.debug('crt.sh HTTP %s for %s',
                                      response.status, domain)
                    return found
                entries = await response.json(content_type=None)
        except Exception as exc:
            self.logger.debug('crt.sh lookup failed for %s: %s', domain, exc)
            return found

        if not isinstance(entries, list):
            return found
        suffix = f'.{domain}'
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for raw in str(entry.get('name_value', '')).splitlines():
                host = raw.strip().lower().lstrip('*.').rstrip('.')
                if not host or '/' in host:
                    continue
                if host == domain or host.endswith(suffix):
                    found.add(host)
        return found
    
    async def scan_ports(self, target: str) -> List[int]:
        """Port scanning using thread-pool TCP connects (reliable on all platforms)."""
        from modules.framework_config import FrameworkConfig
        domain = urlparse(target).netloc.split(':')[0]
        open_ports: List[int] = []
        print(f"  [*] Scanning ports on: {domain}")

        timeout = FrameworkConfig.PORT_SCAN_TIMEOUT
        retries = FrameworkConfig.PORT_SCAN_RETRIES
        loop = asyncio.get_event_loop()

        # The process-wide default executor only has ~12 workers, which
        # bottlenecked the connect scan to roughly 10s of wall clock per
        # batch of ports.  A dedicated pool keeps this phase bounded.
        pool = ThreadPoolExecutor(max_workers=PORT_SCAN_WORKERS,
                                  thread_name_prefix='athena-portscan')

        # Resolve DNS
        try:
            await loop.run_in_executor(None, socket.gethostbyname, domain)
        except Exception as e:
            print(f"    [-] DNS resolution failed for {domain}: {e}")
            return []

        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
            993, 995, 1433, 1521, 2049, 3306, 3389, 5060, 5432, 5900, 5985,
            5986, 6379, 8080, 8443, 9000, 9090, 27017,
            20, 26, 37, 79, 81, 88, 106, 113, 119, 123, 161, 162, 179, 199,
            264, 311, 444, 464, 465, 500, 512, 513, 514, 515, 520, 521, 540,
            546, 547, 554, 563, 585, 587, 591, 593, 623, 631, 636, 639, 646,
            657, 691, 749, 750, 751, 752, 753, 754, 760, 764, 765, 767, 783,
            800, 808, 843, 860, 861, 873, 902, 903, 953, 981, 987, 989, 990,
            991, 992, 994, 996, 997, 998, 999, 1000, 1080, 1099, 1100, 1102,
            1104, 1105, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119,
            1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1138, 1141, 1145,
            1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169,
            1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1200, 1201,
            1213, 1216, 1217, 1218, 1233, 1234, 1235, 1236, 1244, 1247, 1248,
            1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258, 1259, 1260,
            1261, 1262, 1263, 1264, 1265, 1266, 1267, 1268, 1269, 1270, 1271,
            1272, 1277, 1287, 1290, 1291, 1293, 1296, 1297, 1299, 1300, 1301,
            1309, 1310, 1311, 1313, 1314, 1315, 1316, 1317, 1318, 1319, 1320,
            1321, 1322, 1323, 1328, 1334, 1335, 1337, 1338, 1341, 1344, 1347,
            1352, 1357, 1360, 1362, 1364, 1366, 1368, 1370, 1371, 1372, 1374,
            1375, 1376, 1377, 1378, 1379, 1380, 1381, 1382, 1383, 1384, 1385,
            1386, 1387, 1388, 1389, 1390, 1391, 1392, 1393, 1394, 1395, 1396,
            1397, 1398, 1399, 1400, 3307, 3310, 4000, 4040, 4848, 5000, 5433,
            5555, 5601, 5672, 5800, 5984, 6082, 6161, 7000, 7001, 7002, 7070,
            7071, 7199, 7474, 7547, 7680, 8000, 8001, 8008, 8009, 8010, 8020,
            8030, 8040, 8050, 8060, 8069, 8070, 8081, 8082, 8083, 8084, 8085,
            8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096,
            8097, 8098, 8099, 8100, 8111, 8112, 8123, 8125, 8139, 8140, 8172,
            8181, 8200, 8222, 8243, 8280, 8300, 8333, 8334, 8403, 8444, 8500,
            8530, 8531, 8600, 8649, 8686, 8787, 8800, 8834, 8873, 8880, 8888,
            8889, 8900, 8910, 8983, 8990, 8999, 9001, 9002, 9003, 9004, 9005,
            9006, 9007, 9008, 9009, 9010, 9042, 9043, 9050, 9060, 9080, 9091,
            9092, 9100, 9290, 9300, 9418, 9600, 9800, 9898, 9900, 9999, 10000,
            10001, 10009, 10010, 10050, 10051, 10080, 10082, 11211, 11214,
            11433, 12000, 12174, 12222, 12345, 12350, 12443, 12489, 12975,
            13000, 13008, 13224, 13579, 14441, 14442, 15000, 15001, 15002,
            15003, 15004, 15672, 16010, 16012, 16016, 16018, 16080, 16113,
             16379, 16380, 16600, 16992, 16993,
        ]

        sem = asyncio.Semaphore(100)
        scanned = 0

        async def scan_port(port):
            nonlocal scanned
            try:
                for attempt in range(retries):
                    try:
                        async with sem:
                            conn = await loop.run_in_executor(
                                pool,
                                partial(socket.create_connection, (domain, port), timeout=timeout),
                            )
                        conn.close()
                        if port not in open_ports:
                            open_ports.append(port)
                            service = self._guess_port_service(port)
                            print(f"    [+] Port {port} open ({service})")
                            if port in (80, 443, 8080, 8443, 8000, 8888, 9090):
                                await self._verify_web_port(domain, port)
                        return
                    except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError):
                        pass
                    except Exception as e:
                        self.logger.debug(f"Port {port} scan error (attempt {attempt+1}): {e}")
            finally:
                scanned += 1
                if scanned % 50 == 0:
                    print(f"    [*] Port scan progress: {scanned}/{len(common_ports)}")

        tasks = [scan_port(p) for p in common_ports]
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            pool.shutdown(wait=False)

        open_ports.sort()
        print(f"  [+] Port scan complete: {len(open_ports)} port(s) open on {domain}")
        return open_ports
    
    @staticmethod
    def _guess_port_service(port: int) -> str:
        services = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            26: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPCbind',
            119: 'NNTP', 123: 'NTP', 135: 'MSRPC', 139: 'NetBIOS-SSN',
            143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap', 179: 'BGP', 389: 'LDAP',
            443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 500: 'ISAKMP',
            512: 'Exec', 513: 'Login', 514: 'Shell', 515: 'Printer',
            520: 'RIP', 521: 'RIPng', 540: 'UUCP', 546: 'DHCPv6-Client',
            547: 'DHCPv6-Server', 554: 'RTSP', 563: 'NNTP-SSL', 585: 'IMAPS',
            587: 'SMTP-Submission', 591: 'FileMaker', 593: 'MSRPC-HTTPS',
            623: 'IPMI', 631: 'IPP', 636: 'LDAPS', 646: 'LDP', 657: 'RMC',
            691: 'MS-Exchange', 749: 'Kerberos-Admin', 750: 'Kerberos-IV',
            751: 'Kerberos-Master', 752: 'Kerberos-Prop', 753: 'Kerberos-Passwd',
            754: 'Kerberos-Change', 760: 'Kerberos-Update', 764: 'Kerberos',
            765: 'Webster', 767: 'Phone', 783: 'SpamAssassin', 800: 'HTTP',
            808: 'HTTP-Alt', 843: 'Flash-Policy', 860: 'iSCSI', 861: 'OWAMP',
            873: 'Rsync', 902: 'VMware', 903: 'VMware-Auth', 953: 'RNDC',
            981: 'Sofa', 987: 'MSTeams', 989: 'FTPS-Data', 990: 'FTPS',
            991: 'NAS', 992: 'Telnet-SSL', 993: 'IMAPS', 994: 'IRC-SSL',
            995: 'POP3S', 996: 'VSFTP', 997: 'Mailbox', 998: 'Puppet',
            999: 'Puppetdb', 1000: 'SOCKS', 1080: 'SOCKS-Proxy', 1099: 'RMI',
            1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8000: 'HTTP-Alt', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            8888: 'HTTP-Alt', 9000: 'HTTP-Alt2', 9090: 'HTTP-Alt3',
            9200: 'Elasticsearch', 9300: 'Elasticsearch', 11211: 'Memcached',
            15672: 'RabbitMQ', 27017: 'MongoDB',
        }
        return services.get(port, 'Unknown')
    
    async def _verify_web_port(self, domain: str, port: int) -> None:
        """Send an HTTP request to verify the service on a web port."""
        try:
            scheme = 'https' if port in (443, 8443) else 'http'
            url = f"{scheme}://{domain}:{port}/"
            async with (await self._get_session()).get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status < 500:
                    server = resp.headers.get('Server', '').strip()
                    powered = resp.headers.get('X-Powered-By', '').strip()
                    via = resp.headers.get('Via', '').strip()
                    if server:
                        self._add_tech(f"Server:{server}", confidence=2)
                    if powered:
                        self._add_tech(powered, confidence=2)
                    if via and 'cloudflare' in via.lower():
                        self._add_tech('Cloudflare', confidence=2)
                    print(f"      -> HTTP {resp.status} on port {port} [{server or 'unknown'}]")
        except Exception:
            pass
    
    @staticmethod
    def _extract_version_pattern(val: str) -> tuple:
        """Parse version strings: 'Apache/2.4.49 (Ubuntu)' -> ('Apache', '2.4.49') or 'nginx 1.18.0' -> ('Nginx', '1.18.0')."""
        val = val.strip()
        if not val:
            return val, ''
        m = re.match(r'^([^\s/]+)\s*[/\s]\s*([\d]+\.[\d]+(?:\.[\d]+)*(?:-[\w.]+)?)', val)
        if m:
            name = m.group(1).strip()
            version = m.group(2).strip()
            name_map = {
                'apache': 'Apache', 'nginx': 'Nginx', 'microsoft-iis': 'IIS',
                'openresty': 'OpenResty', 'cloudflare': 'Cloudflare',
                'caddy': 'Caddy', 'gunicorn': 'Gunicorn', 'lighttpd': 'Lighttpd',
                'php': 'PHP', 'python': 'Python', 'java': 'Java', 'ruby': 'Ruby',
                'node': 'Node.js', 'express': 'Express', 'flask': 'Flask',
                'django': 'Django', 'laravel': 'Laravel', 'rails': 'Ruby on Rails',
                'wordpress': 'WordPress', 'drupal': 'Drupal', 'joomla': 'Joomla',
                'magento': 'Magento', 'shopify': 'Shopify',
            }
            return name_map.get(name.lower(), name), version
        return val, ''

    @staticmethod
    def _extract_version_from_url(url: str) -> list:
        """Extract tech + version from script/CSS URLs: jquery-3.6.0.min.js -> ('jQuery', '3.6.0')."""
        results = []
        patterns = [
            (r'jquery[-.](\d+\.\d+\.\d+)', 'jQuery'),
            (r'bootstrap[-.](\d+\.\d+\.\d+)', 'Bootstrap'),
            (r'vue[-.](\d+\.\d+\.\d+)', 'Vue.js'),
            (r'react[-.](\d+\.\d+\.\d+)', 'React'),
            (r'angular[-.](\d+\.\d+\.\d+)', 'Angular'),
            (r'laravel[-.](\d+\.\d+\.\d+)', 'Laravel'),
            (r'font-awesome[-.](\d+\.\d+\.\d+)', 'Font Awesome'),
            (r'moment[-.](\d+\.\d+\.\d+)', 'Moment.js'),
            (r'chart[-.](\d+\.\d+\.\d+)', 'Chart.js'),
            (r'd3[-.](\d+\.\d+\.\d+)', 'D3.js'),
            (r'three[-.](\d+\.\d+\.\d+)', 'Three.js'),
            (r'axios[-.](\d+\.\d+\.\d+)', 'Axios'),
            (r'swiper[-.](\d+\.\d+\.\d+)', 'Swiper'),
            (r'select2[-.](\d+\.\d+\.\d+)', 'Select2'),
            (r'datatables[-.](\d+\.\d+\.\d+)', 'DataTables'),
        ]
        url_lower = url.lower()
        for pat, name in patterns:
            m = re.search(pat, url_lower)
            if m:
                results.append((name, m.group(1)))
        return results

    async def _probe_urls_for_tech(self, base: str) -> None:
        """Probe well-known paths for technology version fingerprints."""
        probes = {
            '/': None,
            '/robots.txt': None,
            '/readme.html': 'WordPress',
            '/wp-links-opml.php': 'WordPress',
            '/wp-json/': 'WordPress',
            '/CHANGELOG.txt': None,
            '/version.txt': None,
            '/sitemap.xml': None,
            '/favicon.ico': None,
            '/info.php': 'PHP',
            '/phpinfo.php': 'PHP',
            '/server-status': 'Apache',
            '/.env': None,
            '/composer.json': 'PHP',
            '/package.json': 'Node.js',
        }
        for path, expected_tech in probes.items():
            url = f"{base}{path}"
            try:
                async with (await self._get_session()).get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    if resp.status >= 400:
                        continue
                    await self._fingerprint_response(url, resp)
                    if expected_tech and expected_tech not in str(self.technologies):
                        content = await resp.text()
                        if content and len(content) > 50:
                            self._add_tech(expected_tech)
            except Exception:
                pass

    async def detect_technologies(self, target: str) -> None:
        """Advanced technology detection using headers, cookies, content, and well-known paths."""
        print(f"  [*] Detecting technologies on: {target}")
        
        parsed_target = urlparse(target)
        base = f"{parsed_target.scheme}://{parsed_target.netloc}"
        
        # Probe main target first
        try:
            async with (await self._get_session()).get(target, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as response:
                await self._fingerprint_response(target, response)
        except Exception as e:
            self.logger.debug(f"Main tech probe failed for {target}: {e}")
        
        # Probe well-known paths for version info
        await self._probe_urls_for_tech(base)
        
        print(f"  [+] Detected {len(self.technologies)} technologies")
    
    async def _fingerprint_response(self, url: str, response: aiohttp.ClientResponse) -> None:
        """Analyze a single HTTP response for technology fingerprints with version extraction."""
        headers = response.headers
        try:
            content = await response.text()
        except Exception:
            content = ''
        content_lower = content.lower()
        
        # === Header-based version detection (confidence=2) ===
        server = headers.get('Server', '').strip()
        if server:
            name, version = self._extract_version_pattern(server)
            self._add_versioned_tech(name, version, confidence=2)
        
        powered = headers.get('X-Powered-By', '').strip()
        if powered:
            name, version = self._extract_version_pattern(powered)
            self._add_versioned_tech(name, version, confidence=2)
        
        aspnet = headers.get('X-AspNet-Version', '').strip()
        if aspnet:
            self._add_versioned_tech('ASP.NET', aspnet, confidence=2)
        
        runtime = headers.get('X-Runtime', '').strip()
        if runtime:
            if not re.match(r'^\d+\.?\d*$', runtime):
                self._add_tech(runtime, confidence=2)
        
        generator = headers.get('X-Generator', '').strip()
        if generator:
            name, version = self._extract_version_pattern(generator)
            self._add_versioned_tech(name, version, confidence=2)
        
        # X-Version, X-API-Version
        for ver_hdr in ['X-Version', 'X-API-Version', 'X-Platform-version', 'X-Source']:
            val = headers.get(ver_hdr, '').strip()
            if val and re.search(r'\d+\.\d+', val):
                self._add_tech(f"{ver_hdr}:{val}", confidence=2)
        
        # X-Drupal headers
        if headers.get('X-Drupal-Cache') or headers.get('X-Drupal-Dynamic-Cache'):
            self._add_tech('Drupal', confidence=2)
        drupal_v = headers.get('X-Drupal-Version', '').strip()
        if drupal_v:
            self._add_versioned_tech('Drupal', drupal_v, confidence=2)
        
        # Cloudflare detection (headers)
        for hdr in ['CF-Ray', 'CF-Cache-Status']:
            if headers.get(hdr):
                self._add_tech('Cloudflare', confidence=2)
        cf_railgun = headers.get('CF-Railgun', '').strip()
        if cf_railgun:
            self._add_tech('Cloudflare', confidence=2)
        
        # CDN headers
        via = headers.get('Via', '').lower()
        cdn_map = {
            'cloudflare': 'Cloudflare', 'varnish': 'Varnish', 'akamai': 'Akamai',
            'fastly': 'Fastly', 'incapsula': 'Incapsula', 'sucuri': 'Sucuri',
            'cloudfront': 'AWS CloudFront', 'stackpath': 'StackPath',
            'keycdn': 'KeyCDN', 'bunnycdn': 'BunnyCDN', 'cachefly': 'CacheFly',
        }
        for sig, name in cdn_map.items():
            if sig in via:
                self._add_tech(name, confidence=2)
        
        x_cache = headers.get('X-Cache', '').lower()
        for sig, name in [('cloudfront', 'AWS CloudFront'), ('varnish', 'Varnish')]:
            if sig in x_cache:
                self._add_tech(name, confidence=2)
        
        # Set-Cookie based detection
        set_cookie = headers.get('Set-Cookie', '')
        cookie_techs = {
            'laravel_session': 'Laravel', 'django': 'Django',
            'rails': 'Ruby on Rails', '_rack_session': 'Ruby on Rails',
            'asp.net': 'ASP.NET', 'aspnet_session': 'ASP.NET',
            'PHPSESSID': 'PHP', 'wordpress': 'WordPress', 'wp-': 'WordPress',
            'craft_session': 'Craft CMS', 'expiry': 'ExpressionEngine',
            'kirby': 'Kirby CMS', 'statamic': 'Statamic',
            'october_session': 'October CMS',
        }
        for sig, name in cookie_techs.items():
            if sig in set_cookie.lower():
                self._add_tech(name)
                break
        # Session cookie with no-known framework
        if re.search(r'(^|;\s*)(session|sess|sid)=', set_cookie, re.IGNORECASE):
            if not any(c in set_cookie.lower() for c in cookie_techs):
                self._add_tech('Session Cookie Detected', confidence=1)
        
        # === Content-based version extraction ===
        # Meta generator
        gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', content_lower)
        if gen_match:
            gen_val = gen_match.group(1).strip()
            name, version = self._extract_version_pattern(gen_val)
            self._add_versioned_tech( name, version)
        
        # Meta framework tags
        for meta_pat, tech_name in [
            (r'<meta[^>]*name=["\']?application-name["\']?[^>]*content=["\']?([^"\'>]+)', None),
            (r'<meta[^>]*http-equiv=["\']?X-UA-Compatible["\']?', 'IE Compatibility Mode'),
        ]:
            m = re.search(meta_pat, content_lower)
            if m and tech_name:
                self._add_tech(tech_name)
        
        # WordPress readme / changelog
        if 'readme.html' in url.lower() or 'changelog.txt' in url.lower():
            ver_match = re.search(r'(?:wordpress|version|wp)\s*(\d+\.\d+(?:\.\d+)?)', content_lower)
            if ver_match:
                self._add_versioned_tech( 'WordPress', ver_match.group(1))
        
        # Version.txt patterns
        if 'version.txt' in url.lower():
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    name, version = self._extract_version_pattern(line)
                    if version:
                        self._add_versioned_tech( name, version)
                        break
        
        # Package.json / composer.json detection
        if 'package.json' in url.lower():
            try:
                pkg = json.loads(content)
                for dep, ver in pkg.get('dependencies', {}).items():
                    clean_ver = ver.lstrip('^~>=<')
                    if re.match(r'^\d+\.\d+', clean_ver):
                        name = dep.replace('-', ' ').title()
                        self._add_versioned_tech( name.split('/')[-1] if '/' in name else name, clean_ver)
            except Exception:
                pass
        if 'composer.json' in url.lower():
            try:
                pkg = json.loads(content)
                for dep, ver in pkg.get('require', {}).items():
                    clean_ver = ver.lstrip('^~>=<')
                    if re.match(r'^\d+\.\d+', clean_ver):
                        name = dep.split('/')[-1].replace('-', ' ').title()
                        self._add_versioned_tech( name, clean_ver)
            except Exception:
                pass
        
        # Extract version from script/CSS URLs in content
        if content_lower:
            for src_match in re.finditer(r'(?:src|href)=["\']([^"\']+)["\']', content_lower):
                src_url = src_match.group(1)
                for tname, tver in self._extract_version_from_url(src_url):
                    self._add_versioned_tech( tname, tver)
        
        # === Content-based detection with confidence (require >=2 indicators) ===
        def _count_matches(patterns: list) -> int:
            return sum(1 for p in patterns if re.search(p, content_lower))
        
        # CMS detection
        cms_signatures = {
            'WordPress': [
                r'wp-content', r'wp-includes', r'wp-json', r'wordpress',
                r'themes/[^/]+/style\.css', r'wp-embed', r'/wp-admin/',
                r'<link[^>]*/wp-content/', r'<script[^>]*/wp-includes/',
            ],
            'Drupal': [
                r'/sites/default/', r'Drupal\.settings', r'ajaxPageState',
                r'drupal\.js', r'/core/modules/', r'drupalSettings',
                r'/sites/all/', r'Drupal\..*\.min\.js',
            ],
            'Joomla': [
                r'com_', r'/components/', r'/modules/', r'Joomla!',
                r'media/jui/js', r'/templates/[^/]+/js/',
                r'index\.php\?option=com_', r'joomla\.',
            ],
            'Magento': [
                r'Mage\.', r'/skin/frontend/', r'requirejs\.org',
                r'Varien\.', r'magento/', r'mage/',
            ],
            'Shopify': [
                r'cdn\.shopify\.com', r'myshopify\.com', r'shopify\.api',
                r'shopify\.com/s/', r'Shopify\.',
            ],
            'Wix': [
                r'wix\.com', r'editorx\.com', r'Wix\.',
                r'static\.parastorage\.com', r'_wix',
            ],
        }
        for cms, patterns in cms_signatures.items():
            if _count_matches(patterns) >= 2:
                self._add_tech(cms)
        
        # Framework detection
        framework_signatures = {
            'Laravel': [
                r'laravel_session', r'csrf-token[^>]*content=["\']',
                r'livewire', r'alpinejs', r'x-data', r'__livewire',
            ],
            'Django': [
                r'csrfmiddlewaretoken', r'__admin__', r'django\.',
                r'__debug__', r'django\.js',
            ],
            'Express.js': [
                r'express', r'node_modules', r'require\(\'',
                r'__express', r'x-powered-by[^:]*express',
            ],
            'Spring': [
                r'x-application-context', r'/spring-', r'actuator',
                r'whitelabel error page', r'Spring Framework',
            ],
            'Ruby on Rails': [
                r'csrf-param', r'csrf-token[^>]*content=',
                r'rails\.', r'_rack_session', r'data-remote',
            ],
            'ASP.NET': [
                r'__VIEWSTATE', r'__EVENTVALIDATION', r'__REQUESTDIGEST',
                r'WebForm_PostBack', r'aspnet_sessionid',
                r'asp\.net', r'ScriptResource\.axd',
            ],
            'Flask': [
                r'flask', r'werkzeug', r'__debug__',
                r'flashed-messages', r'Flask\.',
            ],
            'Next.js': [
                r'_next/', r'__NEXT_DATA__', r'next/static',
                r'__next', r'next\.js',
            ],
            'React': [
                r'__react', r'react-dom', r'React\.createElement',
                r'root[^>]*id="root"', r'[data-reactroot]',
                r'__NEXT_DATA__', r'react\.',
            ],
            'Vue.js': [
                r'__vue__', r'v-bind', r'v-model', r'v-if',
                r'v-for', r'v-show', r'Vue\.component',
            ],
            'Angular': [
                r'ng-\w+="', r'[ng-controller]', r'_angular',
                r'angular\.min\.js', r'ng-app',
            ],
            'FastAPI': [
                r'fastapi', r'uvicorn', r'openapi\.json',
            ],
        }
        for framework, patterns in framework_signatures.items():
            if _count_matches(patterns) >= 2:
                self._add_tech(framework)
        
        # JS libraries — require at least one specific pattern
        js_signatures = {
            'jQuery': [
                r'jquery[-.\d]', r'jQuery\(function', r'\$\(function',
                r'jquery\.min\.js', r'jquery-',
            ],
            'Bootstrap': [
                r'bootstrap[.\d]', r'<link[^>]*bootstrap\.min\.css',
                r'bootstrap\.bundle', r'data-bs-',
            ],
            'Tailwind CSS': [
                r'tailwindcss', r'@tailwind', r'tailwind\.min\.css',
                r'class="[^"]*\b(m[trblxy]?-\d+|p[trblxy]?-\d+|flex|grid)\b',
            ],
            'Alpine.js': [
                r'alpinejs', r'x-data', r'x-init', r'x-on',
                r'x-text', r'x-bind', r'x-model',
            ],
        }
        for lib, patterns in js_signatures.items():
            if _count_matches(patterns) >= 1:
                self._add_tech(lib, confidence=2)
        
        # Cloudflare / WAF detection (header/status-based, confidence=2)
        if 'cf-ray' in headers or 'cf-cache-status' in headers:
            self._add_tech('Cloudflare', confidence=2)
        if '__cfduid' in set_cookie or 'cf_clearance' in set_cookie:
            self._add_tech('Cloudflare', confidence=2)
        if response.status == 503 and ('cloudflare' in content_lower or 'cf-error' in content_lower):
            self._add_tech('Cloudflare', confidence=2)
        
        # WAF detection (header-based, confidence=2)
        if 'mod_security' in content_lower or 'modsecurity' in str(headers).lower():
            self._add_tech('ModSecurity', confidence=2)
        if 'sucuri' in str(headers).lower() or 'sucuri' in content_lower:
            self._add_tech('Sucuri', confidence=2)
        if 'incapsula' in str(headers).lower() or 'incapsula' in content_lower:
            self._add_tech('Incapsula', confidence=2)
        
        # Programming languages — URL extension inference (confidence=1)
        if response.status in (200, 301, 302):
            if re.search(r'\.php(?:[3-8])?(?:\?|$)', url, re.I) or 'php' in server.lower():
                self._add_tech('PHP', confidence=1)
            if '.aspx' in url.lower() or '.asp' in url.lower():
                self._add_tech('ASP.NET', confidence=1)
            if '.jsp' in url.lower() or '.do' in url.lower():
                self._add_tech('Java', confidence=1)
            if '.py' in url.lower() and 'flask' not in content_lower and 'django' not in content_lower:
                pass
            if server and ('java' in server.lower() or 'oracle' in server.lower() or 'tomcat' in server.lower()):
                self._add_tech('Java', confidence=2)
        # Detect Python via headers (confidence=2)
        if 'python' in str(headers).lower():
            self._add_tech('Python', confidence=2)
        # Node.js detection (confidence=2)
        if 'node' in server.lower() or 'x-node' in str(headers).lower():
            self._add_tech('Node.js', confidence=2)

        # Firebase Hosting detection (confidence=2)
        for fhdr in ['X-Firebase-*', 'X-Firebase-Cloud-Location', 'X-Firebase-Project']:
            if any(firebase_hdr in str(headers).lower() for firebase_hdr in ['x-firebase', 'firebase']):
                self._add_tech('Firebase Hosting', confidence=2)
                break
        if '__session' in set_cookie.lower() or 'firebase' in set_cookie.lower():
            self._add_tech('Firebase Hosting', confidence=2)
        if '/__/auth/' in content_lower or 'firebaseapp.com' in content_lower:
            self._add_tech('Firebase Hosting', confidence=2)
        if 'firebase' in content_lower and ('auth' in content_lower or 'config' in content_lower or 'api' in content_lower):
            if re.search(r'firebase\.?\s*(initializeApp|auth|firestore|database|storage)', content_lower):
                self._add_tech('Firebase', confidence=2)
        if re.search(r'AIzaSy[a-zA-Z0-9_-]{33}', content):
            self._add_tech('Google Cloud / Firebase', confidence=2)
        # Firebase Storage detection
        if 'firebasestorage.googleapis.com' in content_lower:
            self._add_tech('Firebase Storage', confidence=2)
        # Firebase Firestore detection
        if 'firestore.googleapis.com' in content_lower:
            self._add_tech('Cloud Firestore', confidence=2)
        # Firebase Hosting URL pattern
        if re.search(r'https?://[a-z0-9-]+\.web\.app', content_lower):
            self._add_tech('Firebase Hosting', confidence=2)
    
    async def find_hidden_directories(self, target: str) -> None:
        """Aggressive directory and file enumeration with AI-enhanced validation.
        
        Uses massive wordlists, smart dedup, SPA-aware validation, and AI
        to analyze responses and discover hidden attack surface.
        """
        print(f"  [*] Aggressive directory/file enumeration on: {target}")
        
        # Phase 1: Common admin panels and login portals
        admin_paths = [
            '/admin', '/admin/', '/login', '/wp-admin', '/wp-login.php', '/dashboard',
            '/manager', '/console', '/admin.php', '/login.php', '/wp-admin/install.php',
            '/webadmin', '/adminarea', '/bb-admin', '/adminLogin', '/admin_area',
            '/panel', '/panel/', '/cpanel', '/whm', '/cPanel', '/webmail',
            '/phpmyadmin/', '/phpMyAdmin/', '/pma/', '/mysql/', '/dbadmin/',
            '/phpMyAdmin', '/myadmin', '/sqlmanager', '/sql-admin',
            '/administrator', '/administrator/', '/joomla/', '/wp-admin/setup-config.php',
            '/user/login', '/user/register', '/account/login', '/auth/login',
            '/signin', '/signup', '/register',
        ]
        
        # Phase 2: Hidden files and sensitive endpoints
        hidden_files = [
            # Version control
            '/.git', '/.git/', '/.git/config', '/.git/HEAD', '/.gitignore',
            '/.git/config', '/.git/refs/heads/main', '/.git/refs/heads/master',
            '/.svn', '/.svn/', '/.svn/entries', '/.svn/wc.db',
            '/.hg', '/.hg/', '/.hgignore',
            # Environment and config files
            '/.env', '/.env/', '/.env.local', '/.env.production', '/.env.backup',
            '/.env.example', '/.env.dev', '/.env.staging', '/.env.bak',
            '/config.php', '/config.php.bak', '/config.php.old', '/config.php~',
            '/wp-config.php', '/wp-config.php.bak', '/wp-config.php.old',
            '/config.yml', '/config.yaml', '/config.json', '/config.xml',
            '/application.yml', '/application.properties', '/application.cfg',
            '/settings.py', '/local_settings.py', '/config.py',
            '/database.yml', '/database.php', '/db.php', '/conn.php',
            '/connection.php', '/connect.php', '/dbconnect.php',
            # Backup files
            '/backup', '/backups', '/backup/', '/backups/', '/bak/',
            '/old', '/old/', '/temp', '/tmp/', '/archive/', '/archives/',
            '/site.tar.gz', '/backup.tar.gz', '/www.tar.gz', '/html.tar.gz',
            '/site.zip', '/backup.zip', '/www.zip', '/html.zip',
            '/database.sql', '/db.sql', '/dump.sql', '/backup.sql',
            '/data.sql', '/export.sql', '/mysql.sql',
            # Server config files
            '/.htaccess', '/.htpasswd', '/web.config', '/web.config.bak',
            '/server-status', '/server-info', '/mod_status',
            '/nginx.conf', '/apache.conf', '/httpd.conf',
            '/.user.ini', '/php.ini', '/php5.ini', '/php.cfg',
            # Debug and info pages
            '/info.php', '/phpinfo.php', '/i.php', '/p.php', '/infophp.php',
            '/php_info.php', '/phpinfo/', '/php-info.php', '/debug.php',
            '/test.php', '/testing.php', '/temp.php', '/tmp.php',
            '/wp-info.php', '/core/info.php', '/info/phpinfo.php',
            '/debug/', '/debug/info.php', '/server-status',
            # Logs
            '/logs', '/logs/', '/log', '/log/', '/access.log', '/error.log',
            '/debug.log', '/app.log', '/application.log', '/php_errors.log',
            '/apache2/error.log', '/nginx/error.log',
            '/var/log/', '/proc/self/environ',
            # API documentation
            '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
            '/api/docs', '/api/swagger', '/swagger', '/swagger/',
            '/api-docs', '/api-docs/', '/swagger.json', '/swagger-ui/',
            '/openapi.json', '/openapi.yaml', '/redoc/',
            '/graphql', '/graphiql', '/playground',
            # Common CMS paths
            '/wp-content', '/wp-includes', '/wp-json', '/wp-json/wp/v2/users',
            '/xmlrpc.php', '/xmlrpc.php?rsd', '/wlwmanifest.xml',
            '/feed', '/rss', '/comments/feed', '/?feed=rss2',
            '/wp-cron.php', '/wp-login.php?action=register',
            '/joomla/', '/administrator/manifests/',
            '/modules/', '/components/', '/templates/',
            # Laravel / PHP frameworks
            '/telescope', '/telescope/', '/horizon', '/horizon/',
            '/storage/logs/', '/storage/framework/',
            '/ artisan', '/.env.backup', '/.env.production',
            '/public/index.php', '/vendor/phpunit/',
            # Django
            '/admin/', '/admin/login/', '/django-admin/',
            '/static/', '/media/', '/static/admin/',
            '/__debug__/', '/__debug__/?format=json',
            # Node.js / Express
            '/node_modules/', '/package.json', '/package-lock.json',
            '/.env.local', '/.env.development',
            '/server.js', '/app.js', '/index.js',
            # Ruby on Rails
            '/rails/info', '/rails/mailers',
            '/sidekiq', '/sidekiq/', '/sidekiq/queues',
            # Java / Spring
            '/actuator', '/actuator/', '/actuator/health', '/actuator/info',
            '/actuator/env', '/actuator/beans', '/actuator/configprops',
            '/jolokia', '/jolokia/', '/jolokia/list',
            '/swagger-ui.html', '/swagger-resources/',
            # .NET
            '/elmah.axd', '/trace.axd', '/web.config',
            '/aspnet_client/', '/_layouts/',
            # Common sensitive paths
            '/.well-known/', '/.well-known/security.txt',
            '/.well-known/openid-configuration', '/.well-known/change-password',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
            '/humans.txt', '/security.txt', '/.DS_Store',
            '/Thumbs.db', '/web.config', '/crossdomain.xml',
            # Database admin
            '/adminer.php', '/adminer/', '/adminer/index.php',
            '/pgadmin', '/pgadmin/', '/phpPgAdmin/',
            '/rockmongo', '/rockmongo/',
            # Mail
            '/mailman/', '/mailman/admin', '/mailman/listinfo',
            '/roundcube/', '/roundcube/login', '/squirrelmail/',
            '/horde/', '/horde/imp/',
            # Monitoring
            '/grafana/', '/grafana/login', '/kibana/', '/kibana/app/',
            '/prometheus/', '/prometheus/graph',
            '/nagios/', '/nagios/cgi-bin/',
            '/cacti/', '/zabbix/',
            # CI/CD
            '/jenkins/', '/jenkins/login', '/jenkins/script',
            '/gitlab/', '/gitlab/users/sign_in',
            '/github/', '/bitbucket/',
            '/.circleci/', '/.github/', '/.gitlab-ci.yml',
            '/Jenkinsfile', '/Dockerfile', '/docker-compose.yml',
            # Cloud storage
            '/wp-content/uploads/', '/uploads/', '/files/',
            '/images/', '/img/', '/media/', '/assets/',
            '/static/', '/public/', '/dist/',
            '/storage/', '/data/', '/tmp/',
        ]
        
        # Phase 3: Common file extensions to test
        sensitive_extensions = [
            '.bak', '.old', '.orig', '.save', '.swp', '.swo', '~',
            '.php.bak', '.php.old', '.php~', '.php.swp',
            '.txt', '.log', '.sql', '.xml', '.json', '.yml', '.yaml',
            '.tar.gz', '.zip', '.rar', '.7z', '.gz', '.bz2',
            '.conf', '.cfg', '.ini', '.env', '.config',
        ]
        
        # Phase 4: Common parameter fuzzing endpoints
        api_endpoints = [
            '/api/users', '/api/user', '/api/admin', '/api/config',
            '/api/settings', '/api/status', '/api/health', '/api/info',
            '/api/v1/users', '/api/v1/admin', '/api/v1/config',
            '/api/v2/users', '/api/v2/admin', '/api/v2/config',
            '/graphql', '/graphiql', '/api/graphql',
            '/wp-json/wp/v2/users', '/wp-json/wp/v2/posts',
            '/rest/v1/', '/rest/v2/', '/oauth/token', '/oauth/authorize',
        ]
        
        all_paths = admin_paths + hidden_files + api_endpoints
        
        # Add extension variants for discovered paths
        extension_paths = []
        for path in admin_paths[:30]:  # Test top 30 admin paths with extensions
            for ext in ['.bak', '.old', '.php.bak', '~', '.save']:
                extension_paths.append(f"{path}{ext}")
        
        all_paths.extend(extension_paths)
        
        # Deduplicate
        all_paths = list(dict.fromkeys(all_paths))
        
        confirmed_dirs = []
        spa_routes = []
        interesting_findings = []
        baseline_body = None
        baseline_length = 0
        
        # Get baseline
        try:
            async with (await self._get_session()).get(target, ssl=False, 
                                        timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    baseline_body = await resp.text()
                    baseline_length = len(baseline_body)
        except Exception:
            pass
        
        print(f"  [*] Testing {len(all_paths)} paths...")
        
        async def check_path(path):
            try:
                full_url = urljoin(target, path)
                async with (await self._get_session()).get(full_url, ssl=False, 
                                            allow_redirects=True,
                                            timeout=aiohttp.ClientTimeout(total=6)) as response:
                    status = response.status
                    
                    # Always report 401/403 (protected = real endpoint)
                    if status in [401, 403]:
                        self.discovered_urls.add(full_url)
                        confirmed_dirs.append(path)
                        interesting_findings.append({
                            'url': full_url, 'status': status, 'path': path,
                            'type': 'protected', 'description': f'Protected endpoint (HTTP {status})'
                        })
                        print(f"    [+] Protected: {path} (HTTP {status})")
                        return
                    
                    if status == 200:
                        body = await response.text()
                        body_len = len(body)
                        
                        # SPA catch-all detection
                        if baseline_body and baseline_length > 0:
                            length_ratio = abs(body_len - baseline_length) / max(baseline_length, 1)
                            if length_ratio < 0.05 and body_len > 100:
                                # Check content similarity
                                if body[:500] == baseline_body[:500]:
                                    spa_routes.append(path)
                                    return
                        
                        self.discovered_urls.add(full_url)
                        
                        # Check for interesting content
                        body_lower = body.lower()
                        
                        # Directory listing
                        dl_indicators = ['Index of /', '<title>Index of', '<title>Directory Listing',
                                        'Parent Directory</a>', '../"', 'Directory Listing for /',
                                        '[To Parent Directory]', 'autoindex']
                        dl_score = sum(1 for ind in dl_indicators if ind.lower() in body_lower)
                        if dl_score >= 2:
                            interesting_findings.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'directory_listing', 'description': 'Directory listing enabled'
                            })
                            confirmed_dirs.append(path)
                            print(f"    [+] Directory listing: {path}")
                            return
                        
                        # phpinfo
                        phpinfo_indicators = ['PHP Version', 'phpinfo()', '<title>phpinfo',
                                            'PHP License', 'System =>', 'Build Date =>']
                        if sum(1 for ind in phpinfo_indicators if ind in body) >= 3:
                            interesting_findings.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'phpinfo', 'description': 'Exposed phpinfo()'
                            })
                            confirmed_dirs.append(path)
                            print(f"    [+] phpinfo: {path}")
                            return
                        
                        # Git exposed
                        if any(ind in body for ind in ['[core]', 'ref:', 'repositoryformatversion', 'gitdir:']):
                            interesting_findings.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'git_exposed', 'description': 'Git repository exposed'
                            })
                            confirmed_dirs.append(path)
                            print(f"    [+] Git exposed: {path}")
                            return
                        
                        # .env exposed
                        if any(ind in body_lower for ind in ['db_password', 'db_user', 'app_key', 'secret', 'api_key', 'token']):
                            if '=' in body or ':' in body:
                                interesting_findings.append({
                                    'url': full_url, 'status': status, 'path': path,
                                    'type': 'env_exposed', 'description': 'Environment file exposed with secrets'
                                })
                                confirmed_dirs.append(path)
                                print(f"    [+] Environment file: {path}")
                                return
                        
                        # Config file
                        if any(ind in body_lower for ind in ['database', 'password', 'username', 'mysql', 'postgres']):
                            if any(ind in body_lower for ind in ['<?php', 'define(', '$db', 'db_', 'connection']):
                                interesting_findings.append({
                                    'url': full_url, 'status': status, 'path': path,
                                    'type': 'config_exposed', 'description': 'Configuration file exposed'
                                })
                                confirmed_dirs.append(path)
                                print(f"    [+] Config file: {path}")
                                return
                        
                        # Backup file
                        if any(body_lower.endswith(ext) for ext in ['.sql', '.gz', '.zip', '.tar', '.bak']):
                            interesting_findings.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'backup_file', 'description': 'Backup file accessible'
                            })
                            confirmed_dirs.append(path)
                            print(f"    [+] Backup file: {path}")
                            return
                        
                        # API documentation
                        if any(ind in body_lower for ind in ['swagger', 'openapi', 'api documentation', 'api reference']):
                            interesting_findings.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'api_docs', 'description': 'API documentation exposed'
                            })
                            confirmed_dirs.append(path)
                            print(f"    [+] API docs: {path}")
                            return
                        
                        # Default content detection
                        default_indicators = ['default page', 'default welcome', 'it works',
                                            'apache default', 'nginx default', 'iis default']
                        if any(ind in body_lower for ind in default_indicators):
                            interesting_findings.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'default_page', 'description': 'Default server page'
                            })
                            return
                        
                        # Generic 200 - add to discovered
                        confirmed_dirs.append(path)
                        
            except Exception:
                pass
        
        # Run in batches for better performance
        batch_size = 30
        for i in range(0, len(all_paths), batch_size):
            batch = all_paths[i:i + batch_size]
            tasks = [check_path(p) for p in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            # Progress update
            progress = min(i + batch_size, len(all_paths))
            print(f"    [*] Progress: {progress}/{len(all_paths)} paths tested")
        
        # Store results
        self.discovered_urls.update(f"{target.rstrip('/')}{d}" for d in confirmed_dirs)
        
        # Summary
        print(f"\n  [+] Directory enumeration complete:")
        print(f"      - {len(confirmed_dirs)} paths confirmed")
        print(f"      - {len(interesting_findings)} interesting findings")
        print(f"      - {len(spa_routes)} SPA catch-all routes filtered")
        
        if interesting_findings:
            print(f"\n  [*] Interesting findings:")
            for finding in interesting_findings[:20]:
                print(f"      [{finding['type'].upper()}] {finding['url']} - {finding['description']}")
            # Infer SPA hosting platform
            self._add_tech('Single Page App (SPA) Hosting', confidence=3)
            # Probe for Firebase-specific endpoints
            try:
                fb_probe = urljoin(target, '/__/firebase/init.json')
                async with (await self._get_session()).get(fb_probe, ssl=False, timeout=aiohttp.ClientTimeout(total=4)) as fb_resp:
                    if fb_resp.status == 200:
                        fb_body = await fb_resp.text()
                        if 'firebase' in fb_body.lower() or 'projectId' in fb_body:
                            self._add_tech('Firebase Hosting', confidence=5)
                            self._add_tech('Google Cloud Platform', confidence=3)
                            print(f"      => Confirmed Firebase Hosting via /__/firebase/init.json")
            except Exception:
                pass
            if 'Firebase Hosting' not in self.technologies:
                # Check for other SPA hosting fingerprints
                try:
                    nf_probe = urljoin(target, '/.netlify/functions/')
                    async with (await self._get_session()).get(nf_probe, ssl=False, timeout=aiohttp.ClientTimeout(total=4)) as nf_resp:
                        if nf_resp.status in (200, 401, 403, 404):
                            pass
                except Exception:
                    pass
        # Dedicated phpinfo probing pass - check endpoints not covered by directory enum
        phpinfo_paths = ['/info.php', '/phpinfo.php', '/i.php', '/p.php', '/infophp.php',
                         '/wp-info.php', '/core/info.php', '/info/phpinfo.php',
                         '/debug.php', '/phpinfo/', '/php_info.php', '/php-info.php']
        phpinfo_found = False
        for path in phpinfo_paths:
            if path in common_directories or any(d == path for d in confirmed_dirs):
                continue
            try:
                full_url = urljoin(target, path)
                async with (await self._get_session()).get(full_url, ssl=False, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if len(body) > 500:
                            phpinfo_indicators = [
                                'PHP Version', 'phpinfo()', '<title>phpinfo',
                                'PHP License', 'PHP Credits', 'System =>',
                                'Build Date =>', 'Configure Command =>',
                                'Server API =>', 'Virtual Directory Support =>',
                            ]
                            if sum(1 for ind in phpinfo_indicators if ind in body) >= 3:
                                self.discovered_urls.add(full_url)
                                if not phpinfo_found:
                                    print(f"  [+] phpinfo endpoints detected:")
                                    phpinfo_found = True
                                print(f"      - {path}")
            except Exception:
                pass

        if confirmed_dirs:
            print(f"  [+] Real directories found: {len(confirmed_dirs)}")
        else:
            print(f"  [+] No distinct directories found — all routes return SPA catch-all")
        print(f"  [-] Failed to probe: {len(error_routes)} routes")

    async def analyze_dns_records(self, target: str) -> Dict[str, Any]:
        """Analyze DNS records: MX, TXT (SPF/DKIM/DMARC), NS, A, AAAA for security assessment."""
        domain = urlparse(target).netloc.split(':')[0]
        dns_info: Dict[str, Any] = {
            'domain': domain,
            'a_records': [],
            'mx_records': [],
            'txt_records': [],
            'ns_records': [],
            'spf_record': None,
            'dkim_record': None,
            'dmarc_record': None,
        }

        try:
            loop = asyncio.get_event_loop()

            # A records
            try:
                a_info = await loop.run_in_executor(None, socket.gethostbyname_ex, domain)
                dns_info['a_records'] = a_info[2]
                dns_info['ip'] = a_info[2][0] if a_info[2] else None
            except Exception:
                pass

            # Try DNS library if available
            try:
                import dns.resolver
                # MX records
                try:
                    mx_answers = await loop.run_in_executor(
                        None, lambda: dns.resolver.resolve(domain, 'MX')
                    )
                    dns_info['mx_records'] = [
                        {'exchange': str(r.exchange), 'preference': r.preference}
                        for r in mx_answers
                    ]
                except Exception:
                    pass

                # TXT records (SPF, DKIM, DMARC)
                try:
                    txt_answers = await loop.run_in_executor(
                        None, lambda: dns.resolver.resolve(domain, 'TXT')
                    )
                    for r in txt_answers:
                        txt_str = str(r)
                        dns_info['txt_records'].append(txt_str)
                        if 'v=spf1' in txt_str:
                            dns_info['spf_record'] = txt_str
                        if 'dkim' in txt_str.lower():
                            dns_info['dkim_record'] = txt_str
                except Exception:
                    pass

                # NS records
                try:
                    ns_answers = await loop.run_in_executor(
                        None, lambda: dns.resolver.resolve(domain, 'NS')
                    )
                    dns_info['ns_records'] = [str(r) for r in ns_answers]
                except Exception:
                    pass

                # DMARC
                try:
                    dmarc_answers = await loop.run_in_executor(
                        None, lambda: dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                    )
                    for r in dmarc_answers:
                        txt_str = str(r)
                        if 'v=DMARC1' in txt_str:
                            dns_info['dmarc_record'] = txt_str
                except Exception:
                    pass
            except ImportError:
                self.logger.debug('dnspython not available, skipping advanced DNS lookups')

            # WAF / CDN detection via IP
            if dns_info.get('ip'):
                ip = dns_info['ip']
                # Check for known CDN/WAF IP ranges (simplified)
                cloudflare_ranges = ['104.16.', '104.17.', '104.18.', '104.19.',
                                     '172.64.', '172.65.', '172.66.', '172.67.',
                                     '162.158.', '188.114.', '197.234.']
                aws_ranges = ['54.', '52.', '35.', '13.', '3.', '18.']
                for prefix in cloudflare_ranges:
                    if ip.startswith(prefix):
                        self._add_tech('Cloudflare CDN', confidence=3)
                        break
                for prefix in aws_ranges:
                    if ip.startswith(prefix):
                        self._add_tech('AWS Hosting', confidence=2)
                        break

            # Security assessments
            if dns_info.get('spf_record'):
                spf = dns_info['spf_record'].lower()
                if '~all' in spf:
                    dns_info['spf_analysis'] = 'SOFTFAIL - emails may be spoofed'
                elif '-all' in spf:
                    dns_info['spf_analysis'] = 'HARDFAIL - strict SPF policy'
                elif '?all' in spf or '+all' in spf or 'all' not in spf:
                    dns_info['spf_analysis'] = 'WEAK - SPF allows unauthorized senders'
                else:
                    dns_info['spf_analysis'] = 'No SPF record - domain is vulnerable to email spoofing'

            if not dns_info.get('dmarc_record'):
                dns_info['dmarc_analysis'] = 'No DMARC record - domain vulnerable to email spoofing'
            else:
                dmarc = dns_info['dmarc_record'].lower()
                if 'p=reject' in dmarc:
                    dns_info['dmarc_analysis'] = 'REJECT - strong DMARC policy'
                elif 'p=quarantine' in dmarc:
                    dns_info['dmarc_analysis'] = 'QUARANTINE - moderate DMARC policy'
                elif 'p=none' in dmarc:
                    dns_info['dmarc_analysis'] = 'NONE - monitoring only, no protection'

        except Exception as exc:
            self.logger.debug(f'DNS analysis error: {exc}')

        return dns_info

    async def check_tls_certificate(self, target: str) -> Dict[str, Any]:
        """Check TLS certificate details: issuer, subject, expiry, SANs, and weak ciphers."""
        domain = urlparse(target).netloc.split(':')[0]
        tls_info: Dict[str, Any] = {
            'domain': domain,
            'issues': [],
        }

        try:
            loop = asyncio.get_event_loop()
            ctx = ssl_module.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_module.CERT_NONE

            def _get_cert():
                try:
                    with socket.create_connection((domain, 443), timeout=8) as sock:
                        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            version = ssock.version()
                            cipher = ssock.cipher()
                            return cert, version, cipher
                except Exception:
                    return None, None, None

            cert, tls_version, cipher = await loop.run_in_executor(None, _get_cert)
            if cert:
                tls_info['subject'] = dict(cert.get('subject', []))
                tls_info['issuer'] = dict(cert.get('issuer', []))
                tls_info['version'] = tls_version
                tls_info['cipher'] = cipher[0] if cipher else None
                tls_info['cipher_bits'] = cipher[1] if cipher else None

                # Expiry check
                not_after = cert.get('notAfter', '')
                not_before = cert.get('notBefore', '')
                tls_info['valid_from'] = not_before
                tls_info['valid_until'] = not_after

                try:
                    expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry - datetime.now()).days
                    tls_info['days_until_expiry'] = days_left
                    if days_left < 0:
                        tls_info['issues'].append(f'Certificate EXPIRED {abs(days_left)} days ago')
                    elif days_left < 30:
                        tls_info['issues'].append(f'Certificate expires in {days_left} days (URGENT)')
                    elif days_left < 90:
                        tls_info['issues'].append(f'Certificate expires in {days_left} days (renew soon)')
                except Exception:
                    pass

                # SANs (Subject Alternative Names)
                sans = []
                for ext in cert.get('subjectAltName', []):
                    if ext[0] == 'DNS':
                        sans.append(ext[1])
                        if ext[1].startswith('*.') and ext[1] != f'*.{domain}':
                            self._add_tech(f'Wildcard Cert: {ext[1]}', confidence=2)
                tls_info['subject_alt_names'] = sans

                # Weak TLS version detection
                if tls_version and any(v in tls_version for v in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']):
                    tls_info['issues'].append(f'Weak TLS version: {tls_version}')

                # Weak cipher detection
                if cipher and cipher[0]:
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'EXPORT', 'NULL', 'anon', 'LOW']
                    for weak in weak_ciphers:
                        if weak.lower() in cipher[0].lower():
                            tls_info['issues'].append(f'Weak cipher: {cipher[0]}')
                            break

                self._add_tech(f'TLS {tls_version}', confidence=2)
        except Exception as exc:
            self.logger.debug(f'TLS check error: {exc}')

        return tls_info

    async def discover_security_endpoints(self, target: str) -> List[Dict[str, Any]]:
        """Discover security-related endpoints and well-known resources."""
        discovered = []
        security_endpoints = [
            '/.well-known/security.txt',
            '/.well-known/assetlinks.json',
            '/.well-known/apple-app-site-association',
            '/security.txt',
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',
            '/humans.txt',
            '/keybase.txt',
            '/.well-known/change-password',
            '/.well-known/dnt-policy.txt',
            '/.well-known/openid-configuration',
            '/.well-known/webfinger',
            '/.well-known/nodeinfo',
            '/.well-known/host-meta',
            '/.well-known/host-meta.json',
        ]

        for endpoint in security_endpoints:
            try:
                full_url = urljoin(target, endpoint)
                async with (await self._get_session()).get(full_url, ssl=False,
                                           timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    if resp.status == 200:
                        content_len = len(await resp.text())
                        discovered.append({
                            'url': full_url,
                            'status': resp.status,
                            'content_length': content_len,
                        })
                        print(f'    [+] Security endpoint: {endpoint} ({content_len} bytes)')
            except Exception:
                pass

        return discovered

    async def discover_admin_panels(self, target: str) -> List[Dict[str, Any]]:
        """Discover admin panels, cPanel, webmail, and other high-value login targets."""
        discovered = []
        admin_paths = [
            # cPanel
            '/cpanel', '/cPanel', '/whm', '/whm-login', '/cgi-bin/login',
            '/cgi-bin/cpanel', '/cgi-sys/defaultwebpage.cgi',
            # Webmail
            '/webmail', '/webmail/', '/webmail/login', '/roundcube/',
            '/squirrelmail/', '/horde/', '/imp/', '/atmail/',
            '/webmail2/', '/mail/', '/email/', '/mailman/',
            # DirectAdmin
            '/:2222', '/CMD_LOGIN', '/CMD_SHIFT_LOGIN',
            # Plesk
            '/login', '/panel/', '/plesk/', '/modules/launcher/',
            # phpMyAdmin
            '/phpmyadmin/', '/pma/', '/phpMyAdmin/', '/myadmin/',
            '/mysql/', '/dbadmin/', '/sqlmanager/',
            # Admin panels
            '/admin', '/admin/', '/admin/login', '/admin.php',
            '/administrator/', '/admin_area/', '/admin/login.php',
            '/wp-admin/', '/wp-login.php', '/user/login',
            '/manager/', '/management/', '/panel/',
            # WordPress specific
            '/wp-admin', '/wp-login.php', '/xmlrpc.php',
            # Joomla
            '/administrator', '/administrator/',
            # Laravel
            '/telescope', '/horizon', '/forge',
            # Django
            '/admin/', '/django-admin/',
            # Gitlab
            '/users/sign_in', '/users/sign_up',
            # Grafana
            '/login', '/grafana/login',
            # Kibana
            '/app/kibana', '/app/discover',
            # Jenkins
            '/login', '/j_security_check',
            # Tomcat
            '/manager/html', '/host-manager/html',
            # SonarQube
            '/sessions/new',
            # Portainer
            '/#!/auth',
            # Cockpit
            '/cockpit/login',
            # Mailman
            '/mailman/admin', '/mailman/options',
            # ISPConfig
            '/login', '/ispconfig',
            # cPanel alternate
            '/cgi-sys/changepasswd.cgi', '/cgi-bin/passwd',
        ]

        # Extract base URL components
        from urllib.parse import urlparse
        parsed = urlparse(target)
        base_domain = parsed.netloc.split(':')[0]
        
        # Also try common subdomains for admin panels
        admin_subdomains = ['cpanel', 'webmail', 'mail', 'admin', 'panel', 'whm']
        
        print(f"  [*] Probing for admin panels on {base_domain}...")
        
        # Probe main paths
        for path in admin_paths:
            try:
                full_url = urljoin(target, path)
                async with (await self._get_session()).get(full_url, ssl=False,
                                           timeout=aiohttp.ClientTimeout(total=5),
                                           allow_redirects=False) as resp:
                    if resp.status in (200, 301, 302, 303, 307, 308):
                        content_len = len(await resp.text()) if resp.status == 200 else 0
                        location = resp.headers.get('Location', '')
                        discovered.append({
                            'url': full_url,
                            'status': resp.status,
                            'redirect': location if resp.status in (301, 302, 303, 307, 308) else '',
                            'content_length': content_len,
                            'type': 'admin_panel',
                            'panel_type': self._classify_panel_type(path),
                        })
                        panel_type = self._classify_panel_type(path)
                        print(f'    [+] Admin panel: {path} [{panel_type}] (HTTP {resp.status})')
            except Exception:
                pass

        # Probe admin subdomains
        for sub in admin_subdomains:
            try:
                sub_url = f"{parsed.scheme}://{sub}.{base_domain}"
                async with (await self._get_session()).get(sub_url, ssl=False,
                                           timeout=aiohttp.ClientTimeout(total=5),
                                           allow_redirects=False) as resp:
                    if resp.status in (200, 301, 302, 303, 307, 308):
                        location = resp.headers.get('Location', '')
                        discovered.append({
                            'url': sub_url,
                            'status': resp.status,
                            'redirect': location if resp.status in (301, 302, 303, 307, 308) else '',
                            'content_length': 0,
                            'type': 'admin_panel',
                            'panel_type': sub.upper(),
                        })
                        print(f'    [+] Admin subdomain: {sub}.{base_domain} (HTTP {resp.status})')
            except Exception:
                pass

        # Filter and prioritize - high-value targets first
        high_value = [d for d in discovered if d['panel_type'] in ('CPANEL', 'WHM', 'WEBMAIL', 'CPANEL_WEBMAIL')]
        medium_value = [d for d in discovered if d not in high_value]
        
        # Add login forms from admin panels to the main login_forms list
        for panel in high_value:
            panel_url = panel.get('redirect') or panel['url']
            # Check if there's a login form on the panel
            try:
                async with (await self._get_session()).get(panel_url, ssl=False,
                                           timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        from bs4 import BeautifulSoup
                        content = await resp.text()
                        soup = BeautifulSoup(content, 'html.parser')
                        for form in soup.find_all('form'):
                            has_password = any(inp.get('type') == 'password' for inp in form.find_all('input'))
                            if has_password:
                                action = form.attrs.get('action', '')
                                form_url = urljoin(panel_url, action) if action else panel_url
                                self.login_forms.append({
                                    'url': form_url,
                                    'method': form.attrs.get('method', 'post').upper(),
                                    'inputs': [{'name': inp.get('name', ''), 'type': inp.get('type', 'text')} for inp in form.find_all('input')],
                                    'form_type': 'admin_login',
                                    'source': panel['panel_type'],
                                    'priority': 'high'
                                })
                                print(f'    [+] Login form found on {panel["panel_type"]}: {form_url}')
            except Exception:
                pass

        if discovered:
            print(f"  [+] Discovered {len(discovered)} admin panels ({len(high_value)} high-value targets)")
        
        return high_value + medium_value

    def _classify_panel_type(self, path: str) -> str:
        """Classify the type of admin panel based on path."""
        path_lower = path.lower()
        if 'cpanel' in path_lower or 'whm' in path_lower:
            return 'CPANEL'
        elif 'webmail' in path_lower or 'roundcube' in path_lower or 'squirrelmail' in path_lower or 'horde' in path_lower:
            return 'WEBMAIL'
        elif 'phpmyadmin' in path_lower or 'pma' in path_lower:
            return 'PHPMYADMIN'
        elif 'admin' in path_lower or 'administrator' in path_lower:
            return 'CMS_ADMIN'
        elif 'wp-' in path_lower:
            return 'WORDPRESS'
        elif 'login' in path_lower or 'signin' in path_lower:
            return 'GENERIC_LOGIN'
        elif 'manager' in path_lower:
            return 'TOMCAT_MANAGER'
        else:
            return 'OTHER'

    async def harvest_emails(self, target: str, urls: List[str]) -> List[Dict[str, Any]]:
        """Extract email addresses from web pages."""
        emails_found: List[Dict[str, Any]] = []
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        exclude_domains = {'example.com', 'domain.com', 'yourdomain.com', 'test.com', 'email.com', 'mail.com'}
        seen = set()
        for url in urls[:30]:
            try:
                async with (await self._get_session()).get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status != 200:
                        continue
                    content = await resp.text()
                    for match in email_pattern.finditer(content):
                        email = match.group(0).lower()
                        domain = email.split('@')[1] if '@' in email else ''
                        if domain not in exclude_domains and email not in seen:
                            seen.add(email)
                            emails_found.append({'email': email, 'source': url, 'confidence': 'medium'})
            except Exception:
                continue
        if emails_found:
            print(f"  [+] Harvested {len(emails_found)} email addresses")
        return emails_found

    async def scan_ports_advanced(self, target: str,
                                   scan_types: List[str] = None,
                                   ports: List[int] = None,
                                   top_ports: str = '1000',
                                   concurrent: int = 200,
                                   rate_limit: float = 1000,
                                   jitter: float = 0) -> Dict[str, Any]:
        """Advanced port scanning with multiple scan types."""
        from modules.framework_config import FrameworkConfig
        domain = urlparse(target).netloc.split(':')[0]
        if not ports:
            if top_ports == '100':
                ports = self._TOP_PORTS_100
            elif top_ports == '1000':
                ports = self._TOP_PORTS_1000
            elif top_ports == 'all':
                ports = list(range(1, 65536))
            else:
                ports = self._TOP_PORTS_1000
        if scan_types is None:
            scan_types = ['tcp_connect']
        print(f"  [*] Advanced scanning {domain} with {len(scan_types)} scan types on {len(ports)} ports")
        print(f"      Scan types: {', '.join(scan_types)}, concurrency: {concurrent}")
        results: Dict[str, Any] = {'host': domain, 'scan_types': scan_types, 'ports': {}}
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, socket.gethostbyname, domain)
        except Exception as e:
            print(f"    [-] DNS resolution failed for {domain}: {e}")
            return results
        for scan_type in scan_types:
            if scan_type == 'tcp_connect':
                port_results = await self._scan_tcp_connect(domain, ports, concurrent, rate_limit, jitter)
            elif scan_type == 'syn_stealth':
                port_results = await self._scan_syn_stealth(domain, ports, concurrent, rate_limit, jitter)
            elif scan_type == 'udp':
                port_results = await self._scan_udp(domain, ports, concurrent, rate_limit, jitter)
            elif scan_type == 'ack':
                port_results = await self._scan_ack(domain, ports, concurrent, rate_limit, jitter)
            elif scan_type == 'fin':
                port_results = await self._scan_fin(domain, ports, concurrent, rate_limit, jitter)
            elif scan_type == 'null':
                port_results = await self._scan_null(domain, ports, concurrent, rate_limit, jitter)
            elif scan_type == 'xmas':
                port_results = await self._scan_xmas(domain, ports, concurrent, rate_limit, jitter)
            else:
                continue
            for p, info in port_results.items():
                if p not in results['ports']:
                    results['ports'][p] = {}
                results['ports'][p][scan_type] = info
        open_count = sum(1 for p in results['ports'].values() if any(v.get('open') for v in p.values()))
        print(f"  [+] Advanced scan complete: {open_count} open ports out of {len(ports)} scanned")
        return results

    _TOP_PORTS_100 = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5060, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9000, 9090, 27017, 20, 26, 37, 79, 81, 88, 106, 113, 119, 123, 161, 162, 179, 199, 264, 311, 444, 464, 465, 500, 512, 513, 514, 515, 520, 521, 540, 546, 547, 554, 563, 585, 587, 591, 593, 623, 631, 636, 639, 646, 657, 691, 749, 750, 751, 752, 753, 754, 760, 764, 765, 767, 783, 800, 808, 843, 860, 861, 873, 902, 903, 953, 981, 987, 989, 990]

    _TOP_PORTS_1000 = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
        993, 995, 1433, 1521, 2049, 3306, 3389, 5060, 5432, 5900, 5985,
        5986, 6379, 8080, 8443, 9000, 9090, 27017,
    ]

    async def _scan_tcp_connect(self, domain: str, ports: List[int], concurrent: int, rate_limit: float, jitter: float) -> Dict[int, Dict]:
        results = {}
        sem = asyncio.Semaphore(concurrent)
        from modules.framework_config import FrameworkConfig
        timeout = FrameworkConfig.PORT_SCAN_TIMEOUT
        retries = FrameworkConfig.PORT_SCAN_RETRIES
        loop = asyncio.get_event_loop()

        async def scan_port(port):
            nonlocal results
            for attempt in range(retries):
                try:
                    async with sem:
                        if jitter > 0:
                            await asyncio.sleep(random.uniform(0, jitter))
                        conn = await loop.run_in_executor(None, partial(socket.create_connection, (domain, port), timeout=timeout))
                    conn.close()
                    results[port] = {'open': True, 'service': self._guess_port_service(port)}
                    if port in (80, 443, 8080, 8443, 8000, 8888, 9090):
                        await self._verify_web_port(domain, port)
                    return
                except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError):
                    pass
                except Exception as e:
                    self.logger.debug(f"Port {port} error (attempt {attempt+1}): {e}")

        tasks = [scan_port(p) for p in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        return results

    async def _scan_syn_stealth(self, domain: str, ports: List[int], concurrent: int, rate_limit: float, jitter: float) -> Dict[int, Dict]:
        results = {}
        try:
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(3)
        except (OSError, PermissionError, AttributeError):
            print("    [-] SYN scan requires root/admin privileges, falling back to TCP connect")
            return await self._scan_tcp_connect(domain, ports, concurrent, rate_limit, jitter)

        sem = asyncio.Semaphore(concurrent)

        async def scan_syn(port):
            nonlocal results
            if jitter > 0:
                await asyncio.sleep(random.uniform(0, jitter))
            seq = random.randint(1000, 9999)
            src_port = random.randint(1024, 65535)
            pkt = self._build_syn_packet(src_port, port, seq)
            try:
                await loop.run_in_executor(None, lambda: sock.sendto(pkt, (domain, 0)))
                resp = await loop.run_in_executor(None, lambda: sock.recv(1024))
                if resp:
                    tcp_data = resp[20:]
                    if len(tcp_data) >= 14:
                        flags = tcp_data[13]
                        if flags & 0x12 and not (flags & 0x04):
                            results[port] = {'open': True, 'service': self._guess_port_service(port)}
            except socket.timeout:
                pass
            except Exception as e:
                self.logger.debug(f"SYN scan port {port}: {e}")

        tasks = [scan_syn(p) for p in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        sock.close()
        return results

    def _build_syn_packet(self, src_port: int, dst_port: int, seq: int) -> bytes:
        data_offset = 5
        flags = 0x02
        window = socket.htons(65535)
        checksum = 0
        offset_res = (data_offset << 4) | 0
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port, dst_port, seq, 0,
            offset_res, flags, window, checksum, 0
        )
        pseudo_hdr = struct.pack('!4s4sBBH',
            socket.inet_aton('0.0.0.0'), socket.inet_aton('0.0.0.0'),
            0, socket.IPPROTO_TCP, len(tcp_header)
        )
        checksum = self._compute_checksum(pseudo_hdr + tcp_header)
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port, dst_port, seq, 0,
            offset_res, flags, window, checksum, 0
        )
        return tcp_header

    @staticmethod
    def _compute_checksum(data: bytes) -> int:
        if len(data) % 2 != 0:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i+1]
            s += w
        s = (s >> 16) + (s & 0xffff)
        s = (s >> 16) + (s & 0xffff)
        return ~s & 0xffff

    async def _scan_udp(self, domain: str, ports: List[int], concurrent: int, rate_limit: float, jitter: float) -> Dict[int, Dict]:
        results = {}
        loop = asyncio.get_event_loop()
        sem = asyncio.Semaphore(concurrent)

        async def scan_udp(port):
            nonlocal results
            if jitter > 0:
                await asyncio.sleep(random.uniform(0, jitter))
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(b'\x00' * 8, (domain, port))
                try:
                    data, addr = await loop.run_in_executor(None, lambda: sock.recvfrom(1024))
                    if data:
                        results[port] = {'open': True, 'service': self._guess_port_service(port)}
                except socket.timeout:
                    results[port] = {'open|filtered': True, 'service': self._guess_port_service(port)}
                finally:
                    sock.close()
            except Exception:
                pass

        tasks = [scan_udp(p) for p in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        return results

    async def _scan_ack(self, domain: str, ports: List[int], concurrent: int, rate_limit: float, jitter: float) -> Dict[int, Dict]:
        results = {}
        loop = asyncio.get_event_loop()
        sem = asyncio.Semaphore(concurrent)

        async def scan_ack(port):
            nonlocal results
            if jitter > 0:
                await asyncio.sleep(random.uniform(0, jitter))
            try:
                conn = await loop.run_in_executor(None, partial(socket.create_connection, (domain, port), timeout=3))
                results[port] = {'unfiltered': True, 'service': self._guess_port_service(port)}
                conn.close()
            except socket.timeout:
                results[port] = {'filtered': True}
            except ConnectionRefusedError:
                results[port] = {'filtered': False, 'open': False}
            except Exception:
                pass

        tasks = [scan_ack(p) for p in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        return results

    async def _scan_fin(self, domain: str, ports: List[int], concurrent: int, rate_limit: float, jitter: float) -> Dict[int, Dict]:
        results = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(3)
        except Exception:
            return results

        loop = asyncio.get_event_loop()

        async def scan_fin(port):
            nonlocal results
            seq = random.randint(1000, 9999)
            src_port = random.randint(1024, 65535)
            pkt = self._build_flag_packet(src_port, port, seq, 0x01)
            try:
                await loop.run_in_executor(None, lambda: sock.sendto(pkt, (domain, 0)))
                resp = await loop.run_in_executor(None, lambda: sock.recv(1024))
                if resp:
                    results[port] = {'closed': True}
            except socket.timeout:
                results[port] = {'open|filtered': True}
            except Exception:
                pass

        tasks = [scan_fin(p) for p in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        sock.close()
        return results

    async def _scan_null(self, domain: str, ports: List[int], concurrent: int, rate_limit: float, jitter: float) -> Dict[int, Dict]:
        results = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(3)
        except Exception:
            return results

        loop = asyncio.get_event_loop()

        async def scan_null(port):
            nonlocal results
            seq = random.randint(1000, 9999)
            src_port = random.randint(1024, 65535)
            pkt = self._build_flag_packet(src_port, port, seq, 0x00)
            try:
                await loop.run_in_executor(None, lambda: sock.sendto(pkt, (domain, 0)))
                resp = await loop.run_in_executor(None, lambda: sock.recv(1024))
                if resp:
                    results[port] = {'closed': True}
            except socket.timeout:
                results[port] = {'open|filtered': True}
            except Exception:
                pass

        tasks = [scan_null(p) for p in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        sock.close()
        return results

    async def _scan_xmas(self, domain: str, ports: List[int], concurrent: int, rate_limit: float, jitter: float) -> Dict[int, Dict]:
        results = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(3)
        except Exception:
            return results

        loop = asyncio.get_event_loop()

        async def scan_xmas(port):
            nonlocal results
            seq = random.randint(1000, 9999)
            src_port = random.randint(1024, 65535)
            pkt = self._build_flag_packet(src_port, port, seq, 0x29)
            try:
                await loop.run_in_executor(None, lambda: sock.sendto(pkt, (domain, 0)))
                resp = await loop.run_in_executor(None, lambda: sock.recv(1024))
                if resp:
                    results[port] = {'closed': True}
            except socket.timeout:
                results[port] = {'open|filtered': True}
            except Exception:
                pass

        tasks = [scan_xmas(p) for p in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        sock.close()
        return results

    def _build_flag_packet(self, src_port: int, dst_port: int, seq: int, flags: int) -> bytes:
        data_offset = 5
        window = socket.htons(65535)
        checksum = 0
        offset_res = (data_offset << 4) | 0
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port, dst_port, seq, 0,
            offset_res, flags, window, checksum, 0
        )
        pseudo_hdr = struct.pack('!4s4sBBH',
            socket.inet_aton('0.0.0.0'), socket.inet_aton('0.0.0.0'),
            0, socket.IPPROTO_TCP, len(tcp_header)
        )
        checksum = self._compute_checksum(pseudo_hdr + tcp_header)
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port, dst_port, seq, 0,
            offset_res, flags, window, checksum, 0
        )
        return tcp_header

