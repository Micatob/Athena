import asyncio
import aiohttp
import socket
import ssl as ssl_module
import logging
import os
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import random
import re
import json
import struct
from functools import partial
from datetime import datetime


class DiscoveryModule:
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
        self.directory_results: List[Dict[str, Any]] = []
        self.scanned_scripts: Set[str] = set()
        self.scanned_stylesheets: Set[str] = set()
        self.logger = logging.getLogger(__name__)
        self._baseline_body: Optional[str] = None
        self._baseline_length: int = 0
        self._tech_confidence: Dict[str, int] = {}
        self._proxy: Optional[str] = None

        # Apache/IIS/nginx soft-404 page fingerprints - responses containing
        # these (e.g. Apache "The requested URL was not found on this server"
        # plus its "ErrorDocument" fallback message) are NOT real endpoints.
        self._SOFT_404_FINGERPRINTS = (
            'the requested url was not found',
            'the requested url /',
            'not found on this server',
            'not found error was encountered',
            'error was encountered while trying',
            'errordocument',
            '404 not found',
            '404 error',
            'http 404',
            'page not found',
            'page does not exist',
            'page you are looking for',
            'we could not find the page',
            'file or directory not found',
            'the resource you requested',
            'object not found',
            'cannot find the page',
            'could not be found',
            'no such file or directory',
            'does not exist on this server',
            'the link you clicked is broken',
            'nothing was found',
        )

        # Known technology keywords — anything outside these is suspicious
        self._KNOWN_TECH_KEYWORDS = {
            'apache', 'nginx', 'iis', 'php', 'asp.net', 'python', 'java',
            'ruby', 'node.js', 'express', 'flask', 'django', 'laravel',
            'wordpress', 'drupal', 'joomla', 'magento', 'shopify', 'wix',
            'cloudflare', 'varnish', 'akamai', 'fastly', 'openresty',
            'caddy', 'gunicorn', 'lighttpd', 'rails', 'vue.js', 'react',
            'angular', 'next.js', 'nuxt.js', 'svelte', 'alpine.js', 'bootstrap', 'tailwind',
            'jquery', 'spring', 'fastapi', 'firebase', 'webpack', 'vite',
            'typescript', 'spa', 'single page application',
            'server', 'version', 'unknown',
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

    async def run(self, target: str, wordlist_path: Optional[str] = None,
                  max_depth: int = 1, proxy: Optional[str] = None) -> Dict[str, Any]:
        """Run comprehensive discovery"""
        # Normalize target URL - add protocol if missing
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
            print(f"[*] Auto-corrected target to: {target}")

        print(f"[*] Starting discovery on {target}")
        self.logger.info(f"Starting discovery on {target}")
        self._proxy = proxy

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

        tasks = [
            self.crawl_urls(target),
            self.enumerate_subdomains(target),
            self.scan_ports(target),
            self.detect_technologies(target),
            self.find_hidden_directories(target, wordlist_path=wordlist_path, max_depth=max_depth),
            self.analyze_dns_records(target),
            self.check_tls_certificate(target),
            self.discover_security_endpoints(target),
            self.discover_admin_panels(target),
            self.detect_waf(target),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

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

        return {
            'urls': list(self.discovered_urls),
            'subdomains': list(self.discovered_subdomains),
            'technologies': list(self.technologies),
            'technologies_with_confidence': tech_with_confidence,
            'ports': results[2] if not isinstance(results[2], Exception) else [],
            'login_forms': self.login_forms,
            'admin_panels': results[8] if not isinstance(results[8], Exception) else [],
            'source_analysis': {
                'secrets': self.discovered_secrets,
                'comments': self.discovered_comments,
                'endpoints': list(self.discovered_endpoints)
            },
            'dns_records': results[5] if not isinstance(results[5], Exception) else {},
            'tls_certificate': results[6] if not isinstance(results[6], Exception) else {},
            'security_endpoints': results[7] if not isinstance(results[7], Exception) else [],
            'hidden_directories': self.directory_results,
            'waf': results[9] if not isinstance(results[9], Exception) else {},
            'baseline_body': self._baseline_body or '',
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
                        # Always analyze script URL for framework hints (even CDN)
                        _url_hints = {
                            r'react[.-]': 'React', r'react-dom[.-]': 'React DOM',
                            r'vue[.-]': 'Vue.js', r'angular[.-]': 'Angular',
                            r'next[.-]': 'Next.js', r'nuxt[.-]': 'Nuxt.js',
                            r'svelte[.-]': 'Svelte', r'typescript[.-]': 'TypeScript',
                            r'webpack[.-]': 'Webpack', r'vite[.-]': 'Vite',
                        }
                        for _pat, _tech in _url_hints.items():
                            if re.search(_pat, full_src_url, re.I):
                                self._add_tech(_tech, confidence=2)
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
        'Stripe API Key': r'\b(sk_(?:live|test)_[0-9a-zA-Z]{24})\b|\b(pk_(?:live|test)_[0-9a-zA-Z]{24})\b',
        'Stripe Restricted Key': r'\b(rk_live_[0-9a-zA-Z]{24,34})\b',
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

    # Technology signatures for JS bundle fingerprinting
    _JS_TECH_SIGNATURES = {
        'Firebase': [
            r'firebase[\.\s]*initializeApp',
            r'firebase[\.\s]*auth\b',
            r'firebase[\.\s]*firestore\b',
            r'firebase[\.\s]*database\b',
            r'firebase[\.\s]*storage\b',
            r'firebase[\.\s]*messaging\b',
            r'firebase[\.\s]*analytics\b',
            r'firebase[\.\s]*functions\b',
            r'@firebase/app',
            r'@firebase/auth',
            r'@firebase/firestore',
            r'firebaseConfig',
            r'firebaseio\.com',
            r'firebaseapp\.com',
            r'firebasestorage\.googleapis\.com',
            r'firestore\.googleapis\.com',
            r'googleapis\.com/v0b.*firebase',
        ],
        'React': [
            r'React\.createElement',
            r'react-dom',
            r'react\.production',
            r'react\.development',
            r'__REACT_DEVTOOLS',
            r'__REACT_FIBER',
            r'ReactDOM\.render',
            r'ReactDOM\.createRoot',
            r'createElement\(.blockquote',
            r'jsx-runtime',
        ],
        'Vue.js': [
            r'Vue\.component',
            r'createApp\(',
            r'vue\.runtime',
            r'vue\.global',
            r'__VUE__',
            r'Vue\.mixin',
            r'Vue\.use\(',
            r'v-model',
            r'v-bind:',
        ],
        'Angular': [
            r'@angular/core',
            r'@angular/common',
            r'@angular/compiler',
            r'ng\.probe',
            r'ng\.getComponent',
            r'zone\.js',
            r'NgZone',
            r'@angular/platform-browser',
            r'angular\.js',
        ],
        'Next.js': [
            r'__NEXT_DATA__',
            r'next/router',
            r'next/link',
            r'next/image',
            r'_next/static',
            r'next\.js',
            r'NextRouter',
        ],
        'Nuxt.js': [
            r'__NUXT__',
            r'nuxt\.',
            r'@nuxt/',
            r'vue-router',
            r'vuex',
            r'pinia',
        ],
        'Svelte': [
            r'svelte/internal',
            r'svelte/store',
            r'@sveltejs',
            r'\.svelte/',
            r'svelte\.register',
        ],
        'TypeScript': [
            r'typescript',
            r'__awaiter',
            r'__generator',
            r'__assign',
            r'__extends',
            r'TS helpers',
        ],
        'Webpack': [
            r'webpackJsonp',
            r'__webpack_require__',
            r'webpackChunk',
            r'webpackBootstrap',
            r'__webpack_modules__',
        ],
        'Vite': [
            r'import\.meta\.hot',
            r'vite/client',
            r'@vitejs',
            r'__vite_ssr',
        ],
        'Tailwind CSS': [
            r'tailwindcss',
            r'@tailwind base',
            r'@tailwind components',
            r'tailwind\.config',
        ],
        'Bootstrap': [
            r'bootstrap\.min\.js',
            r'bootstrap\.bundle',
            r'Bootstrap\.Modal',
            r'data-bs-',
        ],
        'jQuery': [
            r'jquery[\-\.]',
            r'jQuery\(',
            r'\$\(',
            r'\.ajax\(',
        ],
        'Google Analytics / GTM': [
            r'google-analytics\.com',
            r'googletagmanager\.com',
            r'gtag\(',
            r'ga\(',
            r'dataLayer\.push',
            r'GTM-',
            r'UA-',
        ],
    }

    def _analyze_script_content(self, source: str, content: str) -> None:
        """Analyze script contents for secrets, keys, API endpoints, developer comments, and technology fingerprints."""
        if not content:
            return

        # Technology fingerprinting from JS bundle content
        self._fingerprint_js_technologies(source, content)

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

    def _fingerprint_js_technologies(self, source: str, content: str) -> None:
        """Detect technologies from JavaScript bundle content."""
        for tech_name, patterns in self._JS_TECH_SIGNATURES.items():
            matched = False
            for pattern in patterns:
                if re.search(pattern, content, re.I):
                    matched = True
                    break
            if matched:
                self._add_tech(tech_name, confidence=2)

                # Extract Firebase version from bundle if present
                if tech_name == 'Firebase':
                    firebase_ver = re.search(
                        r'(?:firebase|@firebase/[a-z-]+)[\s@/"\']+v?(\d+\.\d+\.\d+)',
                        content, re.I)
                    if firebase_ver:
                        self._add_versioned_tech('Firebase SDK', firebase_ver.group(1), confidence=2)
                    # Detect specific Firebase services
                    for svc, sig in [
                        ('Firebase Auth', r'firebase[\.\s]*auth\(|@firebase/auth'),
                        ('Cloud Firestore', r'firebase[\.\s]*firestore\(|@firebase/firestore'),
                        ('Firebase Storage', r'firebase[\.\s]*storage\(|@firebase/storage'),
                        ('Firebase Realtime Database', r'firebase[\.\s]*database\(|@firebase/database'),
                        ('Firebase Functions', r'firebase[\.\s]*functions\(|@firebase/functions'),
                        ('Firebase Messaging', r'firebase[\.\s]*messaging\(|@firebase/messaging'),
                        ('Firebase Analytics', r'firebase[\.\s]*analytics\(|@firebase/analytics'),
                    ]:
                        if re.search(sig, content, re.I):
                            self._add_tech(svc, confidence=2)

                # Extract React version if present
                if tech_name == 'React':
                    react_ver = re.search(r'react[/-]v?(\d+\.\d+\.\d+)', content, re.I)
                    if react_ver:
                        self._add_versioned_tech('React', react_ver.group(1), confidence=2)

                # Extract Vue version
                if tech_name == 'Vue.js':
                    vue_ver = re.search(r'vue[/-]v?(\d+\.\d+\.\d+)', content, re.I)
                    if vue_ver:
                        self._add_versioned_tech('Vue.js', vue_ver.group(1), confidence=2)

                # Extract Angular version
                if tech_name == 'Angular':
                    ng_ver = re.search(r'angular[/-]v?(\d+\.\d+\.\d+)', content, re.I)
                    if ng_ver:
                        self._add_versioned_tech('Angular', ng_ver.group(1), confidence=2)

                # Extract jQuery version
                if tech_name == 'jQuery':
                    jq_ver = re.search(r'jquery[/-]v?(\d+\.\d+\.\d+)', content, re.I)
                    if jq_ver:
                        self._add_versioned_tech('jQuery', jq_ver.group(1), confidence=2)

                # Extract Tailwind version
                if tech_name == 'Tailwind CSS':
                    tw_ver = re.search(r'tailwindcss[/-]v?(\d+\.\d+\.\d+)', content, re.I)
                    if tw_ver:
                        self._add_versioned_tech('Tailwind CSS', tw_ver.group(1), confidence=2)

                # Extract Bootstrap version
                if tech_name == 'Bootstrap':
                    bs_ver = re.search(r'bootstrap[/-]v?(\d+\.\d+\.\d+)', content, re.I)
                    if bs_ver:
                        self._add_versioned_tech('Bootstrap', bs_ver.group(1), confidence=2)

                # Extract Webpack version
                if tech_name == 'Webpack':
                    wp_ver = re.search(r'webpack[/-]v?(\d+\.\d+\.\d+)', content, re.I)
                    if wp_ver:
                        self._add_versioned_tech('Webpack', wp_ver.group(1), confidence=2)

                # Extract Google Analytics / GTM IDs
                if tech_name == 'Google Analytics / GTM':
                    gtm_id = re.search(r'(GTM-[A-Z0-9]+)', content)
                    if gtm_id:
                        self._add_tech(f'Google Tag Manager ({gtm_id.group(1)})', confidence=2)
                    ua_id = re.search(r'(UA-\d+-\d+)', content)
                    if ua_id:
                        self._add_tech(f'Google Analytics ({ua_id.group(1)})', confidence=2)

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
        
        async def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
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
                self.logger.debug('check_subdomain outer exception for %s: %s', subdomain, e)
        
        # Concurrent subdomain checking
        tasks = [check_subdomain(sub) for sub in common_subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)
        print(f"  [+] Subdomain enumeration complete, found {len(self.discovered_subdomains)}")
    
    async def scan_ports(self, target: str) -> List[int]:
        """Port scanning using thread-pool TCP connects (reliable on all platforms)."""
        from modules.framework_config import FrameworkConfig
        domain = urlparse(target).netloc.split(':')[0]
        open_ports: List[int] = []
        print(f"  [*] Scanning ports on: {domain}")

        timeout = FrameworkConfig.PORT_SCAN_TIMEOUT
        retries = FrameworkConfig.PORT_SCAN_RETRIES
        loop = asyncio.get_event_loop()

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
                                None,
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
        await asyncio.gather(*tasks, return_exceptions=True)

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
            matches = _count_matches(patterns)
            # For SPAs, a single strong indicator is enough (the HTML shell is minimal)
            is_spa = 'SPA (Single Page Application)' in self.technologies
            threshold = 1 if is_spa else 2
            if matches >= threshold:
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

        # === SPA (Single Page Application) detection ===
        # Detect SPA mount points and bundle patterns
        spa_mounts = [
            (r'id=["\']root["\']', 'React'),
            (r'id=["\']app["\']', 'Vue.js/React/Angular'),
            (r'<app-root>', 'Angular'),
            (r'ng-version=["\']', 'Angular'),
            (r'data-reactroot', 'React'),
            (r'__next', 'Next.js'),
            (r'id=["\']__nuxt["\']', 'Nuxt.js'),
            (r'__vue_app__', 'Vue.js'),
            (r'__svelte', 'Svelte'),
        ]
        spa_framework = None
        for pattern, name in spa_mounts:
            if re.search(pattern, content):
                spa_framework = name
                self._add_tech('SPA (Single Page Application)', confidence=3)
                if name not in ('Vue.js/React/Angular',):
                    self._add_tech(name, confidence=3)
                break

        # Detect SPA from minimal HTML shell with script bundles
        if not spa_framework:
            script_count = len(re.findall(r'<script\b', content, re.I))
            has_mount = bool(re.search(r'id=["\'](?:root|app|main)["\']', content))
            body_len = len(content.strip())
            if has_mount and script_count >= 1 and body_len < 15000:
                self._add_tech('SPA (Single Page Application)', confidence=2)

        # Extract framework info from CDN-hosted script URLs (even cross-domain)
        cdn_framework_hints = {
            r'react[.-](?:production|development|umd|cjs|min)\.js': 'React',
            r'react-dom[.-](?:production|development|umd|cjs|min)\.js': 'React DOM',
            r'vue[.-](?:runtime|global|production|min)\.js': 'Vue.js',
            r'angular[.-](?:production|development|min)\.js': 'Angular',
            r'angular[.-](?:cli|material|min)\.js': 'Angular',
            r'next[.-](?:dist|static|bundle)\.js': 'Next.js',
            r'nuxt[.-](?:runtime|dist|bundle)\.js': 'Nuxt.js',
            r'svelte[.-](?:bundle|chunk|min)\.js': 'Svelte',
            r'@angular(?:/core|/common|/compiler)': 'Angular',
            r'@vue(?:/runtime|/compiler)': 'Vue.js',
            r'react(?:/umd|/cjs|/esm)': 'React',
            r'typescript(?:\.min)?\.js': 'TypeScript',
            r'webpack[.-](?:runtime|chunk|bundle)\.js': 'Webpack',
            r'vite[.-](?:client|module)\.js': 'Vite',
        }
        for src_match in re.finditer(r'(?:src|href)=["\']([^"\']+)["\']', content):
            src_url = src_match.group(1)
            for pattern, name in cdn_framework_hints.items():
                if re.search(pattern, src_url, re.I):
                    self._add_tech(name, confidence=2)
    
    async def detect_waf(self, target: str) -> Dict[str, Any]:
        """Detect WAF/CDN presence (fingerprints + active challenge probes)."""
        try:
            from modules.waf import WAFDetector
        except ImportError:
            return {}
        print(f"  [*] Detecting WAF / CDN protections on {target}...")
        detector = WAFDetector(proxy=self._proxy)
        try:
            report = await detector.detect(target)
        finally:
            await detector.close()
        if report.detected:
            advice = WAFDetector.evasion_advice(report.waf_name)
            report.detail = f"{report.detail}; evasion: {advice[0] if advice else 'encode payloads'}"
            print(f"    [+] WAF DETECTED: {report.waf_name} (confidence {report.confidence:.0%})")
            if report.challenge_blocked:
                print(f"        - Actively blocking (HTTP {report.challenge_status})")
            for sig in report.matched_signatures[:5]:
                print(f"        - Signature: {sig}")
            for a in advice[:3]:
                print(f"        - Bypass: {a}")
        else:
            print(f"    [-] No WAF signatures detected")
        return report.to_dict()

    def _builtin_wordlist_path(self) -> str:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, 'config', 'directories.txt')

    def _load_directory_wordlist(self, wordlist_path: Optional[str] = None) -> List[str]:
        """Load directory/file entries from a custom wordlist file plus the
        bundled `config/directories.txt`. One entry per line, '#' comments,
        entries get a leading '/' added if missing."""
        paths: List[str] = []
        seen: Set[str] = set()
        candidates = [wordlist_path] if wordlist_path else []
        candidates.append(self._builtin_wordlist_path())
        for wp in candidates:
            if not wp:
                continue
            if not os.path.exists(wp):
                print(f"    [!] Wordlist not found: {wp}")
                continue
            try:
                with open(wp, 'r', encoding='utf-8', errors='ignore') as fh:
                    for raw in fh:
                        line = raw.strip()
                        if not line or line.startswith('#'):
                            continue
                        if line.startswith('*.'):
                            line = line[2:]
                        if not line.startswith('/'):
                            line = '/' + line
                        if line not in seen:
                            seen.add(line)
                            paths.append(line)
            except OSError as exc:
                self.logger.warning(f"Failed to load wordlist {wp}: {exc}")
        return paths

    async def _harvest_robots_sitemap(self, target: str) -> List[str]:
        """Extract additional paths from robots.txt and any sitemap files."""
        extra: List[str] = []
        sitemap_urls: List[str] = []

        try:
            robots_url = urljoin(target, '/robots.txt')
            async with (await self._get_session()).get(robots_url, ssl=False, proxy=self._proxy,
                                                       timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    for m in re.finditer(r'(?i)^\s*(?:Disallow|Allow)\s*:\s*(\S+)', body, re.MULTILINE):
                        p = m.group(1).strip()
                        if not p or p == '*':
                            continue
                        if p.endswith('*'):
                            p = p[:-1]
                        if p:
                            extra.append(p)
                    sitemap_urls = re.findall(r'(?i)^\s*Sitemap\s*:\s*(\S+)', body, re.MULTILINE)
        except Exception:
            pass

        if not sitemap_urls:
            sitemap_urls = [urljoin(target, '/sitemap.xml')]

        touched: Set[str] = set()
        pending = sitemap_urls[:5]
        while pending and len(extra) < 500:
            sm_url = pending.pop(0)
            if sm_url in touched:
                continue
            touched.add(sm_url)
            try:
                async with (await self._get_session()).get(sm_url, ssl=False, proxy=self._proxy,
                                                           timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status != 200:
                        continue
                    sm_body = await resp.text()
                    if '<sitemapindex' in sm_body.lower():
                        pending.extend(re.findall(r'<loc>\s*([^<]+?)\s*</loc>', sm_body, re.I)[:8])
                        continue
                    for loc in re.findall(r'<loc>\s*([^<]+?)\s*</loc>', sm_body, re.I):
                        try:
                            parsed = urlparse(loc)
                            if parsed.path:
                                extra.append(parsed.path)
                        except Exception:
                            continue
            except Exception:
                continue

        return list(dict.fromkeys(extra))

    def _is_soft_404(self, body: str, body_len: int,
                     baseline_body: Optional[str], baseline_length: int) -> bool:
        """Detect fake 200 responses (SPA catch-all, Apache/nginx 404 pages)."""
        if baseline_body and baseline_length > 0:
            ratio = abs(body_len - baseline_length) / max(baseline_length, 1)
            if ratio < 0.05 and body_len > 100 and body[:500] == baseline_body[:500]:
                return True
        b = body.lower()
        hits = sum(1 for f in self._SOFT_404_FINGERPRINTS if f in b)
        if hits >= 2:
            return True
        if hits >= 1 and body_len < 350:
            return True
        return False

    def _is_redirect_to_404(self, location: str, base: str) -> bool:
        """Redirect to a 404 page or straight back to the homepage = soft-404."""
        if not location:
            return False
        loc_lower = location.lower()
        if any(k in loc_lower for k in ('404', 'notfound', 'not-found', 'error')):
            return True
        try:
            loc_path = urlparse(location).path.rstrip('/')
            base_path = urlparse(base).path.rstrip('/')
            if loc_path == base_path:
                return True
        except Exception:
            pass
        return False

    def _looks_like_dir(self, path: str) -> bool:
        if path.endswith('/'):
            return True
        last_seg = path.rstrip('/').rsplit('/', 1)[-1]
        return '.' not in last_seg

    async def _dir_scan(self, base: str, paths: List[str],
                        baseline_body: Optional[str], baseline_length: int,
                        depth: int, sem: asyncio.Semaphore,
                        request_budget: List[int]) -> List[str]:
        """Probe a batch of paths. Returns confirmed directory paths for recursion."""
        confirmed: List[Dict[str, Any]] = []
        dirs_for_recursion: List[str] = []
        done = 0
        total = len(paths)
        printed = 0
        NOTABLE_TYPES = {'directory_listing', 'phpinfo', 'git_exposed', 'env_exposed',
                         'config_exposed', 'backup_file', 'api_docs', 'login',
                         'protected', 'server_error'}

        async def check_path(path: str) -> None:
            nonlocal done, printed
            if request_budget[0] <= 0:
                return
            full_url = urljoin(base, path)
            request_budget[0] -= 1
            async with sem:
                try:
                    async with (await self._get_session()).get(
                            full_url, ssl=False, allow_redirects=False, proxy=self._proxy,
                            timeout=aiohttp.ClientTimeout(total=6)) as resp:
                        status = resp.status
                        headers = resp.headers

                        # Hard negatives - these paths do not exist
                        if status in (400, 404, 410):
                            return

                        def _print(finding_type: str, line: str) -> None:
                            nonlocal printed
                            if finding_type in NOTABLE_TYPES and printed < 60:
                                printed += 1
                                print(f"    {line}")

                        # Redirects - keep unless the redirect target is a 404/homepage
                        if status in (301, 302, 303, 307, 308):
                            location = headers.get('Location', '')
                            if self._is_redirect_to_404(location, base):
                                return
                            self.discovered_urls.add(full_url)
                            confirmed.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'redirect',
                                'description': f'Redirects to {location or "/"}'
                            })
                            if self._looks_like_dir(path):
                                dirs_for_recursion.append(path)
                            _print('redirect', f"[+] Redirect: {path} -> {location or '/'} (HTTP {status})")
                            return

                        # Protected paths - always interesting
                        if status in (401, 403):
                            self.discovered_urls.add(full_url)
                            confirmed.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'protected',
                                'description': f'Protected endpoint (HTTP {status})'
                            })
                            if self._looks_like_dir(path):
                                dirs_for_recursion.append(path)
                            _print('protected', f"[+] Protected: {path} (HTTP {status})")
                            return

                        # No content but real
                        if status in (204, 205):
                            self.discovered_urls.add(full_url)
                            confirmed.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'exists',
                                'description': f'Endpoint exists, no content (HTTP {status})'
                            })
                            if self._looks_like_dir(path):
                                dirs_for_recursion.append(path)
                            return

                        # Server errors - exists but broken
                        if status >= 500:
                            self.discovered_urls.add(full_url)
                            confirmed.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'server_error',
                                'description': f'Endpoint exists but errors (HTTP {status})'
                            })
                            if self._looks_like_dir(path):
                                dirs_for_recursion.append(path)
                            return

                        if status != 200:
                            return

                        body = await resp.text()
                        body_len = len(body)
                        body_lower = body.lower()

                        if self._is_soft_404(body, body_len, baseline_body, baseline_length):
                            return

                        self.discovered_urls.add(full_url)

                        # --- Interesting content classification ---
                        # Directory listing
                        dl_indicators = ['index of /', '<title>index of', '<title>directory listing',
                                         'parent directory</a>', '../"', 'directory listing for /',
                                         '[to parent directory]', 'autoindex']
                        dl_score = sum(1 for ind in dl_indicators if ind in body_lower)
                        if dl_score >= 2:
                            confirmed.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'directory_listing',
                                'description': 'Directory listing enabled'
                            })
                            dirs_for_recursion.append(path)
                            _print('directory_listing', f"[+] Directory listing: {path}")
                            return

                        # phpinfo
                        phpinfo_indicators = ['php version', 'phpinfo()', '<title>phpinfo',
                                              'php license', 'system =>', 'build date =>',
                                              'configure command =>', 'server api =>']
                        if sum(1 for ind in phpinfo_indicators if ind in body_lower) >= 3:
                            confirmed.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'phpinfo', 'description': 'Exposed phpinfo()'
                            })
                            _print('phpinfo', f"[+] phpinfo: {path}")
                            return

                        # Git exposed
                        if any(ind in body_lower for ind in ['[core]', 'ref:', 'repositoryformatversion', 'gitdir:']):
                            confirmed.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'git_exposed', 'description': 'Git repository exposed'
                            })
                            _print('git_exposed', f"[+] Git exposed: {path}")
                            return

                        # Environment file with secrets
                        if any(ind in body_lower for ind in ['db_password', 'db_user', 'app_key',
                                                             'secret_key', 'api_key', 'access_token',
                                                             'private_key', 'password=']):
                            if '=' in body or ':' in body:
                                confirmed.append({
                                    'url': full_url, 'status': status, 'path': path,
                                    'type': 'env_exposed',
                                    'description': 'Environment file exposed with secrets'
                                })
                                _print('env_exposed', f"[+] Environment file: {path}")
                                return

                        # Config file
                        if any(ind in body_lower for ind in ['database', 'password', 'username',
                                                             'mysql', 'postgres']):
                            if any(ind in body_lower for ind in ['<?php', 'define(', '$db', 'db_',
                                                                 'connection', 'configure']):
                                confirmed.append({
                                    'url': full_url, 'status': status, 'path': path,
                                    'type': 'config_exposed',
                                    'description': 'Configuration file exposed'
                                })
                                _print('config_exposed', f"[+] Config file: {path}")
                                return

                        # Backup / archive file
                        if body_lower.endswith(('.sql', '.gz', '.zip', '.tar', '.bak', '.7z', '.rar')):
                            confirmed.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'backup_file', 'description': 'Backup file accessible'
                            })
                            _print('backup_file', f"[+] Backup file: {path}")
                            return

                        # API documentation
                        if any(ind in body_lower for ind in ['swagger', 'openapi', 'api documentation',
                                                             'api reference', 'graphiql']):
                            confirmed.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'api_docs', 'description': 'API documentation exposed'
                            })
                            _print('api_docs', f"[+] API docs: {path}")
                            return

                        # Login form
                        if '<form' in body_lower and ('type="password"' in body_lower or
                                                      "type='password'" in body_lower):
                            confirmed.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'login', 'description': 'Login form exposed'
                            })
                            if self._looks_like_dir(path):
                                dirs_for_recursion.append(path)
                            _print('login', f"[+] Login form: {path}")
                            return

                        # Default server page
                        default_indicators = ['default page', 'default welcome', 'it works',
                                              'apache default', 'nginx default', 'iis default']
                        if any(ind in body_lower for ind in default_indicators):
                            confirmed.append({
                                'url': full_url, 'status': status, 'path': path,
                                'type': 'default_page', 'description': 'Default server page'
                            })
                            return

                        # Generic 200 - real content
                        confirmed.append({
                            'url': full_url, 'status': status, 'path': path,
                            'type': 'content',
                            'description': f'HTTP {status}, {body_len} bytes'
                        })
                        if self._looks_like_dir(path):
                            dirs_for_recursion.append(path)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass
                finally:
                    done += 1

        for i in range(0, total, 40):
            batch = paths[i:i + 40]
            tasks = [check_path(p) for p in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            if done % 400 < 40:
                print(f"    [*] Depth {depth} progress: {min(done, total)}/{total}")

        self.directory_results.extend(confirmed)
        return list(dict.fromkeys(dirs_for_recursion))

    async def find_hidden_directories(self, target: str, wordlist_path: Optional[str] = None,
                                      max_depth: int = 1) -> None:
        """Aggressive directory/file enumeration.

        Combines a bundled 1200+ entry wordlist (plus an optional custom
        wordlist), extension fuzzing (.txt/.php/.html/.zip/.bak/~ etc. so
        `files.txt`, `admin.txt`, `passwords.txt`, `robots.txt` and friends
        are probed), robots.txt/sitemap path harvesting, soft-404 filtering
        and recursive re-scanning of confirmed directories.
        """
        base = target.rstrip('/')
        print(f"  [*] Aggressive directory/file enumeration on: {target}")

        # 1) Paths from robots.txt + sitemaps (trusted - site references them)
        try:
            extra_paths = await self._harvest_robots_sitemap(target)
            for p in extra_paths:
                full = urljoin(base, p)
                self.discovered_urls.add(full)
                self.directory_results.append({
                    'url': full, 'status': 200, 'path': p,
                    'type': 'reference', 'source': 'robots_sitemap',
                    'description': 'Path referenced by robots.txt/sitemap'
                })
            if extra_paths:
                print(f"    [+] Harvested {len(extra_paths)} paths from robots.txt/sitemaps")
        except Exception:
            pass

        # 2) Build candidate list from wordlists
        wl_entries = self._load_directory_wordlist(wordlist_path)
        print(f"    [*] Wordlist: {len(wl_entries)} base entries")

        fuzz_all = ['.txt']
        fuzz_priority = ['.php', '.html', '.htm', '.zip', '.tar.gz', '.gz', '.7z',
                         '.bak', '.old', '.orig', '.save', '.swp', '.swo', '~',
                         '.sql', '.log', '.json', '.xml', '.yml', '.yaml',
                         '.cfg', '.conf', '.ini', '.inc', '.config', '.env']
        priority_kw = ('admin', 'pass', 'user', 'config', 'database', 'secret',
                       'key', 'token', 'credential', 'backup', 'login', 'account',
                       'customer', 'client', 'employ', 'staff', 'member', 'student',
                       'mail', 'ftp', 'ssh', 'vpn', 'db')

        candidates: List[str] = []
        seen: Set[str] = set()
        for entry in wl_entries:
            if entry in seen:
                continue
            seen.add(entry)
            candidates.append(entry)
            last_seg = entry.rstrip('/').rsplit('/', 1)[-1]
            if '.' in last_seg:
                continue
            candidates.append(entry + '/')
            for ext in fuzz_all:
                candidates.append(f"{entry}{ext}")
            if any(kw in entry.lower() for kw in priority_kw):
                for ext in fuzz_priority:
                    candidates.append(f"{entry}{ext}")

        # Core admin/api panels kept from the curated phase lists
        for path in ['/cpanel', '/cPanel', '/whm', '/webmail', '/:2222', '/CMD_LOGIN',
                     '/phpmyadmin/', '/pma/', '/adminer.php', '/actuator', '/actuator/health',
                     '/actuator/env', '/telescope', '/horizon', '/swagger-ui.html',
                     '/wp-login.php', '/wp-json/wp/v2/users', '/graphql',
                     '/cgi-sys/defaultwebpage.cgi', '/.well-known/security.txt']:
            if path not in seen:
                seen.add(path)
                candidates.append(path)
        candidates.extend(['/api/v1', '/api/v2', '/api/v3',
                           '/api/docs', '/api/swagger', '/openapi.json'])

        all_paths = list(dict.fromkeys(candidates))

        # In stealth mode, reduce scope to avoid excessive requests
        from modules.framework_config import FrameworkConfig
        is_stealth = FrameworkConfig.STEALTH_MODE
        if is_stealth and len(all_paths) > 500:
            # Keep only the most important paths: admin panels, API endpoints, and a subset of wordlist
            priority_paths = [p for p in all_paths if any(kw in p.lower() for kw in
                ('admin', 'login', 'api', 'config', 'backup', 'secret', 'wp-', 'phpmyadmin',
                 'actuator', 'swagger', 'graphql', 'env', 'server-status', '.env', 'debug'))]
            # Add a random sample of remaining paths
            other_paths = [p for p in all_paths if p not in priority_paths]
            import random
            sample_size = min(300, len(other_paths))
            sampled = random.sample(other_paths, sample_size) if other_paths else []
            all_paths = priority_paths + sampled
            print(f"    [*] Stealth mode: reduced to {len(all_paths)} priority paths")

        print(f"    [*] {len(all_paths)} paths to test (with extension variants)")

        # 3) Baseline for soft-404 / SPA detection
        baseline_body = self._baseline_body
        baseline_length = self._baseline_length
        if baseline_body is None:
            try:
                async with (await self._get_session()).get(base, ssl=False, proxy=self._proxy,
                                                           timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        baseline_body = await resp.text()
                        baseline_length = len(baseline_body)
            except Exception:
                pass

        # 4) Scan with optional recursion into confirmed directories
        sem = asyncio.Semaphore(30 if not is_stealth else 10)
        request_budget = [22000 if not is_stealth else 2000]
        print(f"  [*] Testing {len(all_paths)} paths (depth 1)...")

        level_dirs = await self._dir_scan(base, all_paths, baseline_body, baseline_length,
                                          1, sem, request_budget)

        for depth in range(2, max_depth + 1):
            if not level_dirs:
                break
            if request_budget[0] <= 0:
                print(f"    [!] Request budget exhausted, stopping recursion")
                break
            level_dirs = level_dirs[:6]
            child_paths: List[str] = []
            child_seen: Set[str] = set()
            for d in level_dirs:
                for entry in wl_entries[:400]:
                    child = d.rstrip('/') + entry
                    if child in child_seen:
                        continue
                    child_seen.add(child)
                    child_paths.append(child)
                    if '.' in entry.rsplit('/', 1)[-1] or entry.endswith('/'):
                        continue
                    child_paths.append(child + '.txt')
            print(f"  [*] Recursing depth {depth}: {len(child_paths)} paths under "
                  f"{len(level_dirs)} directories...")
            level_dirs = await self._dir_scan(base, child_paths, baseline_body, baseline_length,
                                              depth, sem, request_budget)

        # 5) Results
        total_found = [f for f in self.directory_results]
        interesting = [f for f in total_found if f['type'] in (
            'directory_listing', 'phpinfo', 'git_exposed', 'env_exposed',
            'config_exposed', 'backup_file', 'api_docs', 'login',
            'protected', 'server_error')]
        print(f"\n  [+] Directory enumeration complete:")
        print(f"      - {len(total_found)} paths confirmed")
        print(f"      - {len(interesting)} interesting findings")
        if interesting:
            print(f"\n  [*] Interesting findings:")
            for finding in interesting[:25]:
                print(f"      [{finding['type'].upper()}] {finding['url']} - {finding['description']}")
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

