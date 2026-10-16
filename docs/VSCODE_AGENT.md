# Athena — VS Code Extension / VAPT Agent Contract

How an editor extension (or any agent) drives Athena headlessly.
Athena is non-interactive by default; nothing here ever prompts on stdin.

## 1. Drive via CLI (simplest)

```text
python athena.py -t TARGET -m MODE -o FORMAT [--export PATH] [--resume] [--restart]
```

| Item | Contract |
|---|---|
| Modes (`-m`) | `full` (default), `discovery`, `vuln`, `bruteforce`, `recon`, `all` |
| Formats (`-o`) | `html` (default), `json`, `csv`, `pdf`, `sarif`, `all` |
| Report path | `report_<target>.<ext>` in CWD, or `--export PATH` (extension appended per format) |
| Exit | `0` on completed report (even with findings); non-zero on fatal error only |
| Prompts | None by default. `--confirm-dangerous` is the ONLY flag that reads stdin, and it degrades to allow-with-notice when stdin is not a TTY |
| Resume | `--resume` continues from checkpoint; `--restart` starts fresh |
| Authenticated scan | `--auth-user/--auth-pass` (+ optional `--auth-login-url`); passwords never logged, stored, or reported |

Safety defaults an agent inherits: `AETHELRED_SAFE_MODE=true` blocks
destructive actions; aggressive techniques need an authorization file plus
scope proof (`--scope-file` / `--engagement-id`); every decision is appended
to `athena_audit.log`.

## 2. Drive via REST API (long scans)

```text
python athena.py --api [--api-host HOST] [--api-port PORT]
```

Defaults: `SERVER_HOST=0.0.0.0`, `SERVER_PORT=5000`. Mutating endpoints
require `X-API-KEY: <ATHENA_API_KEY>` (`REQUIRE_API_KEY` defaults true).

| Method | Endpoint | Auth | Returns |
|---|---|---|---|
| `GET` | `/health` | no | health + safe-mode + active scans |
| `GET` | `/metrics` | no | Prometheus text |
| `POST` | `/scan` | yes | `202` + `job_id` (`target` string/list, `mode`) |
| `GET` | `/scan/status/<job_id>` | yes | `QUEUED`/`RUNNING`/`COMPLETE`/`FAILED` |
| `POST` | `/scan/url` | yes | synchronous single-URL probe |
| `GET` | `/jobs` | yes | in-process jobs |
| `GET` | `/scans` | yes | finished-scan history |
| `GET` | `/scans/<id>` | yes | scan + severity counts |
| `GET` | `/scans/<id>/export?format=json\|csv\|sarif` | yes | re-emitted findings |
| `GET` | `/apidocs/` | no | endpoint reference |

Jobs are durable: a server restart requeues `RUNNING` jobs as `QUEUED`.

## 3. Findings schema (stable)

JSON findings always carry at least:

```json
{
  "type": "SQL Injection",
  "severity": "CRITICAL",
  "url": "https://target/page?id=1",
  "description": "…",
  "verified": true,
  "verification": {"status": "confirmed"},
  "confidence": "high",
  "evidence": {"proof": "…"},
  "source": "athena-native"
}
```

`severity` ∈ `CRITICAL|HIGH|MEDIUM|LOW|INFO`. `verification.status` ∈
`confirmed|possible|inconclusive`. Non-dict rows never appear.

## 4. SARIF contract (Problems panel / code scanning)

`-o sarif`, `--export-history ID --output sarif`, or
`/scans/<id>/export?format=sarif` all emit SARIF 2.1.0 from one builder,
so rule ids are identical everywhere:

- `tool.driver.name` = `Athena Security Suite`
- rule ids = `athena/<slug>` (e.g. `athena/sql-injection`), stable across runs
- levels: `CRITICAL|HIGH` → `error`, `MEDIUM` → `warning`, else `note`
- `locations[0].physicalLocation.artifactLocation.uri` = finding URL
- `properties.athenaVerification` / `athenaVerified` carry the proof state

## 5. Local history (no server needed)

Finished scans persist in `~/.athena/athena.db` (`ATHENA_DB_PATH` / `--store`
override):

```text
python athena.py --history                                  # list scans
python athena.py --export-history 12 --output sarif --export out
```

## 6. Deferred / operator-only (documented, not required)

- Headless Chromium crawl: skipped until the operator runs
  `playwright install chromium` (~170 MB, intentionally not fetched by
  default). Detection, auth, and vuln scanning are unaffected.
- `NVD_API_KEY` (optional): raises CVE lookup 5→50 req/30s; anonymous
  rate still works. `DEEPSEEK_API_KEY` (optional): second LLM failover
  after Groq/Gemini.
