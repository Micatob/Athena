# Athena Security Suite – API Reference

> Full request/response documentation for the REST API served by `python athena.py --api`

**Base URL:** `https://<host>:<port>` (default `https://localhost:5000`)  
**Authentication:** `X-API-KEY: <your-key>` header on all protected endpoints.

---

## Authentication

All endpoints marked ✅ require the `X-API-KEY` header.

| Condition | HTTP Status | Body |
|---|---|---|
| Header missing | `401` | `{"error": "Unauthorized", "detail": "X-API-KEY header is required"}` |
| Wrong key | `401` | `{"error": "Unauthorized", "detail": "Invalid API key"}` |
| Key not configured on server | `503` | `{"error": "Service unavailable", "detail": "ATHENA_API_KEY is not configured..."}` |

---

## `GET /health`

System health check. No authentication required.

**Response 200:**
```json
{
  "status": "online",
  "version": "2.2.0",
  "safe_mode": true,
  "active_scans": 0,
  "timestamp": "2026-04-19T00:00:00+00:00"
}
```

---

## `GET /metrics`

Prometheus exposition format metrics. No authentication required.

**Response 200** (`Content-Type: text/plain; version=0.0.4`):
```text
# HELP athena_scan_requests_total Total number of scan requests dispatched
# TYPE athena_scan_requests_total counter
athena_scan_requests_total{mode="1",target="example.com"} 3.0
# HELP athena_vulnerabilities_total Total vulnerabilities found
...
```

**Available metrics:**

| Metric | Type | Labels |
|---|---|---|
| `athena_scan_requests_total` | Counter | `target`, `mode` |
| `athena_scan_duration_seconds` | Histogram | – |
| `athena_vulnerabilities_total` | Counter | `severity` |
| `athena_exploit_attempts_total` | Counter | `vuln_type`, `status` |
| `athena_circuit_breaker_trips_total` | Counter | `host` |
| `athena_api_errors_total` | Counter | `endpoint`, `http_status` |
| `athena_active_scans` | Gauge | – |

---

## `POST /scan` ✅

Queue one or more background security assessment jobs.

**Rate limit:** 5 requests per minute per API key + IP.

**Request body:**
```json
{
  "target": "example.com",
  "mode": "1"
}
```

`target` may also be a list or a comma-separated string:
```json
{
  "target": ["site1.com", "site2.com"],
  "mode": "2"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `target` | string \| array | ✅ | Domain(s), IP(s), or CIDR block(s) |
| `mode` | string | No | `"1"`=Full, `"2"`=Discovery, `"3"`=Scan only. Default: `"1"` |

**Response 202 (Accepted):**
```json
{
  "status": "accepted",
  "job_id": "a3f5c923-...",
  "targets_count": 2,
  "mode": "1",
  "poll_url": "/scan/status/a3f5c923-...",
  "message": "Security assessment queued for 2 target(s)"
}
```

**Error responses:**

| Status | Condition |
|---|---|
| `400` | Missing `target` field, empty targets, invalid `mode`, too many targets |
| `401` | Invalid or missing API key |
| `429` | Rate limit exceeded |

---

## `GET /scan/status/{job_id}` ✅

Poll the status of a background scan job.

**Response 200:**
```json
{
  "id": "a3f5c923-...",
  "status": "COMPLETE",
  "targets": ["example.com"],
  "mode": "1",
  "started_at": "2026-04-19T00:01:00+00:00",
  "finished_at": "2026-04-19T00:05:32+00:00",
  "error": null,
  "results": [
    {"target": "example.com", "report_file": "report_example.com.json"}
  ]
}
```

| `status` value | Meaning |
|---|---|
| `QUEUED` | Job registered, not yet started |
| `RUNNING` | Active scan in progress |
| `COMPLETE` | All targets scanned successfully |
| `FAILED` | Fatal error during scan execution |

**Response 404:** Job ID not found.

---

## `POST /scan/url` ✅

Scan a single URL for vulnerabilities (synchronous probe, short timeout).

**Rate limit:** 10 requests per minute.

**Request body:**
```json
{
  "url": "https://example.com/api?id=1"
}
```

The URL must include `http://` or `https://` and a valid hostname. Bare strings, `ftp://`, `file://`, etc. are rejected.

**Response 200:**
```json
{
  "url": "https://example.com/api?id=1",
  "findings": [
    {
      "type": "Missing Security Headers",
      "severity": "MEDIUM",
      "url": "https://example.com/api?id=1",
      "description": "Missing: X-Frame-Options, Content-Security-Policy"
    }
  ],
  "count": 1
}
```

**Error responses:**

| Status | Condition |
|---|---|
| `400` | Missing `url`, invalid scheme, no hostname |
| `500` | Internal scan error (detailed message in `detail` field) |

---

## `GET /jobs` ✅

List all scan jobs held in the in-process registry (cleared on server restart).

**Response 200:**
```json
{
  "jobs": [
    {
      "id": "a3f5c923-...",
      "status": "COMPLETE",
      "targets": ["example.com"],
      "mode": "1",
      "started_at": "2026-04-19T00:01:00+00:00",
      "finished_at": "2026-04-19T00:05:32+00:00"
    }
  ],
  "total": 1
}
```

---

## `GET /apidocs/`

Interactive Swagger UI. No authentication required.
Renders full request/response schemas and allows live API calls.

---

## Security Response Headers

Every response from the API includes:

| Header | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Cache-Control` | `no-store, no-cache, must-revalidate, max-age=0` |
| `Content-Security-Policy` | `default-src 'self'; ...` |

---

## Scan Mode Reference

| Mode | CLI | API | Description |
|---|---|---|---|
| `1` | `--mode 1` | `"mode": "1"` | Full test: discovery → bruteforce → scan → exploit → report |
| `2` | `--mode 2` | `"mode": "2"` | Discovery only: subdomains, URLs, technologies |
| `3` | `--mode 3` | `"mode": "3"` | Vulnerability scan only (no exploitation) |
| `4` | `--api` | N/A | Start REST API server |

---

## Vulnerability Types Detected

| Category | Severity Range | Detection Method |
|---|---|---|
| SQL Injection (Error/Union/Blind/Time-based) | CRITICAL | Active probing |
| Cross-Site Scripting (Reflected/DOM) | HIGH | Reflection detection |
| Command Injection (Output/Time-based) | CRITICAL | Pattern matching |
| Local File Inclusion / Path Traversal | CRITICAL | Indicator strings |
| Server-Side Request Forgery | HIGH | Metadata URL probing |
| XXE Injection | CRITICAL | XML parser probing |
| Authentication Bypass | CRITICAL | Credential testing |
| Open API Endpoints (IDOR) | HIGH | Unauthenticated access |
| CSRF Vulnerability | MEDIUM | Form token analysis |
| Missing Security Headers | MEDIUM | Header inspection |
| Sensitive Information Disclosure | CRITICAL | Pattern matching |
| Directory Listing Enabled | HIGH | Content inspection |
| Server Version Disclosure | MEDIUM | Header inspection |
| Race Condition (Potential) | MEDIUM | Concurrent request testing |
