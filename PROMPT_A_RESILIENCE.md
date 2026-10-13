# PROMPT A — Resilience & Evidence Hardening (Athena Security Suite)

> Save date: 2026-10-13. Later prompts: B = Coverage (headless crawl, auth sessions,
> nuclei correlation), C = Operations (SQLite store, queue, exports, API mode).
> Do NOT start B or C in this session.

---

## Context you need before writing code

Project: `C:\Users\Hermes\Desktop\athena` — Athena Security Suite (`athena.py` CLI,
`modules/` package). Windows, Python 3.14, asyncio pipeline:
`WAF gate → discovery → vuln scan → bruteforce → enumeration → CVE mapping →
AI triage → automated exploitation → report`.

Hardening history (already done, do not regress):
- Report builder handles `verification.evidence = None`, non-dict findings,
  null discovery lists (`modules/reporting.py`).
- AI integration handles string confidences, null LLM-JSON lists
  (`modules/ai_integration.py`).
- Fatal errors log full traceback to `athena_errors.log`; report-phase failure
  writes `report_<target>.fallback.json` (`athena.py`).
- Test suite: `pytest tests/` — 935 tests, all green. Keep them green.

Known operational facts from the last real scan (target: shared cPanel/Exim host
behind ModSecurity WAF):
- Full scan ≈ 45 min; vuln-scan stage alone ≈ 19 min.
- All 7 automated verification attempts were `inconclusive` because handlers
  matched success signatures only; the WAF returned 403/406 or the body never
  matched. No timing-based or out-of-band proof exists today.
- Both AI providers (groq, gemini) hit 429 mid-run; AI is advisory-only.

## Objective — three deliverables

### 1. Checkpoint / resume

- After each pipeline stage, persist a checkpoint to
  `~/.athena/checkpoints/<target_hash>/state.json` plus per-stage payload files
  (`discovery.json`, `vulns.json`, `exploitation.json`, …).
- New CLI flags: `--resume` (continue latest checkpoint for target),
  `--restart` (ignore checkpoints), `--checkpoint-dir <path>`.
- On `SIGINT` (Ctrl+C), finish writing the current stage checkpoint before exit,
  print the resume command, exit 130.
- A resumed run must produce byte-identical report inputs for already-completed
  stages (no re-crawl, re-scan). Stages are the natural resume boundary; do NOT
  checkpoint mid-stage except for the vuln scanner, which should checkpoint its
  URL progress list every 25 URLs so a 19-min stage can resume mid-list.
- Checkpoints older than 24h are ignored with a warning (stale results).
- Tests: simulate stage crash + resume; assert completed stages are not re-run
  (mock counters) and final report matches a no-crash baseline.

### 2. Real proof: timing + OOB verification

Today `inconclusive` means "we gave up". Add two verification strategies:

**a) Timing-based confirmation (SQLi / SSTI / LDAPi)**
- New module `modules/verification/timing.py`: N-round differential timing
  (default 3 benign probes vs 3 payload probes; median + MAD; flag only when
  payload median exceeds benign median by a configurable factor, default 2.5x,
  with a minimum absolute delta to avoid noise on fast responses).
- Must be WAF-aware: reuse the existing WAF gate result to keep delays in the
  configured stealth band; abort timing checks entirely if WAF verdict is
  `likely`/`confirmed` and the endpoint already returned 403/406 twice —
  record `skipped_waf` rather than burning time and risk.
- Result states: `confirmed_timing`, `inconclusive_timing`, `skipped_waf`.

**b) Out-of-band (OOB) confirmation**
- New module `modules/verification/oob.py` with pluggable collectors:
  `interactsh` (if binary on PATH), `webhook.site` (if `ATHENA_WEBHOOK_URL`
  env var set), and a built-in fallback that generates a unique
  `<uuid>.oob.<ATHENA_OOB_DOMAIN>` marker when the operator supplies
  `--oob-domain` (for DNS-log services they control).
- Payload injection points: SSTI (template syntax that triggers HTTP/DNS
  callback), SQLi `LOAD_FILE`/`xp_dtree` style probes ONLY in safe mode as
  evidence requests — never destructive, never file writes.
- Poll collector for up to `--oob-wait 60` seconds after the probe request.
- Result states: `confirmed_oob`, `inconclusive_oob`, `skipped_no_collector`.
- SECURITY: never send target data to third-party collectors without an
  explicit `--allow-oob-third-party` flag; default is local/domain collector
  only.

**c) Verification status model**
- Replace the binary confirmed/inconclusive framing in the report with a
  scored evidence model: each attempt gets `proof_kind`
  (`response_signature | timing | oob | manual`) and `confidence`
  (high/medium/low). Report HTML shows the proof kind column.
- Update `modules/exploitation_runner.py` and `modules/reporting.py`
  verification_detail rendering accordingly. Keep old keys populated for
  backward compat (`status`, `evidence`).

### 3. Cross-tool finding correlation

- New module `modules/correlation.py`: group native findings and nuclei
  template matches by (normalized URL path + param + vuln class).
- When both a native finding and a nuclei match hit the same group, emit a
  single merged finding with `sources: ['native', 'nuclei:<template>']` and
  bump confidence (e.g. native HIGH + nuclei match → `corroborated: true`).
- Unmatched nuclei-only findings are kept but labelled `tool_only`; the
  executive summary separates `corroborated` vs `tool_only` counts so the
  operator sees real signal.
- Dedup must be deterministic — no LLM required (reuse normalize helpers from
  `ai_integration.py` if suitable, do not duplicate logic).

## Constraints

- Safe-mode semantics unchanged: nothing destructive, no file writes on target,
  no auth attacks without the existing `AETHELRED_AUTHORIZATION.txt` gate.
- New network traffic stays inside existing rate-limiter and WAF-tuning bands.
- No new hard dependencies in requirements.txt beyond optional extras behind
  `try: import ... except ImportError` (interactsh client, if any).
- All new modules covered by unit tests; run `python -m pytest tests/ -q`
  before declaring done (935 tests currently).
- Console output style matches existing `cprint` conventions; no emoji.
- Do not touch prompt B/C scope (no Playwright, no SQLite, no API server).

## Acceptance criteria

1. Kill a scan during the vuln stage; `--resume` completes it without re-running
   discovery; final HTML identical to uninterrupted run (modulo timestamps).
2. A timing-verification unit test with mocked HTTP (benign 200ms, payload
   800ms) yields `confirmed_timing`; noise case (both ~200ms) yields
   `inconclusive_timing`.
3. OOB module unit test with a fake collector: callback received → `confirmed_oob`;
   no callback in wait window → `inconclusive_oob`.
4. Correlation unit test: one native + one nuclei finding on same path/param →
   merged, `corroborated: true`, summary counts updated.
5. `pytest tests/` fully green; `python athena.py --help` shows the new flags.

## Deliverable

Implement, test, and summarize changes with file:line references. If any
acceptance criterion cannot be met safely in this pass, document the gap in
`docs/PROMPT_A_GAPS.md` instead of shipping a silent partial.
