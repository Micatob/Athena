"""
tests/test_reporting.py – Consolidated report generation
========================================================
Covers:
  * Phase results (bruteforce / enumeration / CVE / AI) reaching the JSON
    report instead of being silently dropped
  * Finding-cap transparency (raw vs unique vs shown)
  * Deduplication that does not mutate the caller's data
  * HTML rendering of the consolidated sections
  * run_ai_analysis() consolidation of raw detections before LLM calls
"""

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.protocol_scanner import ServiceCredential
from modules.reporting import ReportGenerator


def _raw_findings(unique: int = 120, copies: int = 2):
    """``unique`` distinct (type, url) rows, each repeated ``copies`` times."""
    findings = []
    for i in range(unique):
        for _ in range(copies):
            findings.append({
                "type": f"Vuln {i % 7}",
                "url": f"https://target.example/page{i}",
                "severity": "CRITICAL" if i % 3 == 0 else "HIGH",
                "payload": "probe",
                "description": "detected",
            })
    return findings


def _results(**overrides):
    results = {
        "target": "https://target.example",
        "timestamp": "2026-09-27T00:00:00",
        "discovery": {
            "urls": ["https://target.example/"],
            "ports": [21, 22, 25],
            "technologies": ["Apache 2.4.49"],
            "technologies_with_confidence": [
                {"technology": "Apache 2.4.49", "version": "2.4.49",
                 "confidence": 0.9}
            ],
            "subdomains": [],
            "admin_panels": [
                {"url": "https://target.example/cpanel",
                 "panel_type": "CPANEL", "status": 200},
            ],
            "login_forms": [
                {"url": "https://target.example/wp-login.php",
                 "form_type": "admin_login", "method": "POST"},
            ],
        },
        "vulnerabilities": _raw_findings(),
        "exploitation": [],
        "bruteforce": {
            "web_logins": [
                {"url": "https://target.example/wp-login.php",
                 "username": "admin", "password": "admin123",
                 "method": "POST"},
            ],
            "service_creds": [
                ServiceCredential(service="ssh", host="target.example",
                                  port=22, username="root",
                                  password="root", success=True),
                ServiceCredential(service="ftp", host="target.example",
                                  port=21, username="anonymous",
                                  password="", success=False),
            ],
            "admin_panels": [
                {"url": "https://target.example/cpanel",
                 "panel_type": "CPANEL", "status": 200},
            ],
        },
        "enumeration": {
            "smtp": {"accessible": True, "banner": "220 mail ESMTP Exim"},
            "pop3": {"accessible": True, "banner": "+OK Dovecot ready."},
            "imap": {"accessible": False, "banner": ""},
        },
        "cve_mapping": [
            {"technology": "Apache", "version": "2.4.49", "confidence": 0.9,
             "max_cvss": 7.5,
             "cves": [{"cve_id": "CVE-2021-41773",
                       "description": "Path traversal & RCE",
                       "cvss_score": 7.5, "exploit_available": True}]},
        ],
        "ai_analysis": {
            "provider": "groq",
            "model": "test-model",
            "statements": [{"content": "dedup summary", "reasoning_type": "fact"}],
            "false_positive_hypotheses": [],
            "validated_findings": [],
            "filtered_indices": [0, 1],
            "filtered_findings": [
                {"index": 0, "type": "Vuln 0",
                 "url": "https://target.example/page0",
                 "severity": "CRITICAL", "confidence": 0.9,
                 "reason": "generic 200 response", "source": "validation"},
            ],
            "consolidation": {"raw_findings": 240, "unique_findings": 120},
        },
    }
    results.update(overrides)
    return results


class TestReportConsolidation:
    def test_phase_sections_are_included(self):
        report = ReportGenerator().generate_comprehensive_report(_results())
        audit = report["athena_security_audit"]

        creds = audit["bruteforce_findings"]
        assert creds["successful_web_logins"][0]["username"] == "admin"
        # Only successful service logins are reported
        assert len(creds["successful_service_logins"]) == 1
        assert creds["successful_service_logins"][0]["service"] == "ssh"

        enum = audit["service_enumeration"]
        assert enum["smtp"]["accessible"] is True
        assert "Dovecot" in enum["pop3"]["banner"]

        assert audit["cve_mapping"][0]["cves"][0]["cve_id"] == "CVE-2021-41773"

        ai = audit["ai_assistant"]
        assert ai["advisory_only"] is True
        assert ai["findings_suggested_as_false_positive"] == 1
        assert ai["consolidation"]["raw_findings"] == 240

    def test_discovery_keeps_admin_panels_and_login_forms(self):
        report = ReportGenerator().generate_comprehensive_report(_results())
        discovery = report["athena_security_audit"]["discovery_findings"]
        assert discovery["admin_panels"][0]["panel_type"] == "CPANEL"
        assert discovery["login_forms"][0]["form_type"] == "admin_login"

    def test_missing_phase_data_yields_empty_sections(self):
        report = ReportGenerator().generate_comprehensive_report({
            "target": "https://t", "vulnerabilities": [],
        })
        audit = report["athena_security_audit"]
        assert audit["bruteforce_findings"] == {}
        assert audit["service_enumeration"] == {}
        assert audit["ai_assistant"] == {}
        assert audit["cve_mapping"] == []


class TestFindingCapTransparency:
    def test_truncation_is_reported_not_silent(self):
        report = ReportGenerator().generate_comprehensive_report(_results())
        summary = report["athena_security_audit"]["audit_summary"]

        assert summary["raw_finding_count"] == 240
        assert summary["unique_finding_count"] == 120
        assert summary["total_vulnerabilities"] == 100
        trunc = summary["findings_truncated"]
        assert trunc["shown"] == 100
        assert trunc["total_unique"] == 120
        assert "100" in trunc["note"]

    def test_no_truncation_flag_under_the_cap(self):
        results = _results(vulnerabilities=_raw_findings(unique=10, copies=1))
        report = ReportGenerator().generate_comprehensive_report(results)
        summary = report["athena_security_audit"]["audit_summary"]
        assert "findings_truncated" not in summary
        assert summary["total_vulnerabilities"] == 10

    def test_dedup_does_not_mutate_input(self):
        findings = _raw_findings(unique=5, copies=1)
        original = [dict(f) for f in findings]
        ReportGenerator()._filter_important_vulnerabilities(findings)
        assert findings == original


class TestHtmlConsolidation:
    @pytest.fixture(scope="class")
    def html(self):
        import athena
        report = ReportGenerator().generate_comprehensive_report(_results())
        return athena._generate_html_report(report)

    def test_credential_section_rendered(self, html):
        assert "Authentication &amp; Credential Testing" in html
        assert "admin123" in html

    def test_service_and_cve_sections_rendered(self, html):
        assert "Service Enumeration" in html
        assert "CVE Mapping (version-based)" in html
        assert "CVE-2021-41773" in html

    def test_admin_panel_and_ai_sections_rendered(self, html):
        assert "Admin Panels &amp; High-Value Targets" in html
        assert "AI Advisory Notes" in html
        assert "Advisory only" in html

    def test_flagged_fp_list_not_rendered_in_html(self, html):
        # Operator rule: what the terminal hides, the HTML hides too.
        # The FP reason below exists ONLY in the flagged list, never in a
        # real finding description, so its absence proves the table is gone.
        assert "generic 200 response" not in html
        assert "flagged as likely false positives" in html

    def test_flagged_fp_audit_survives_in_json(self):
        audit = ReportGenerator().generate_comprehensive_report(
            _results())["athena_security_audit"]
        assert audit["ai_assistant"]["findings_suggested_as_false_positive"] == 1
        assert audit["ai_assistant"]["false_positive_details"][0]["url"] == \
            "https://target.example/page0"

    def test_truncation_banner_rendered(self, html):
        assert "Findings itemization capped" in html


class TestRunAIAnalysisConsolidation:
    @pytest.mark.asyncio
    async def test_raw_detections_are_consolidated(self, monkeypatch, capsys):
        import athena
        from modules.ai_integration import AIIntegration

        monkeypatch.setenv("ATHENA_AI_PROVIDER", "groq")
        monkeypatch.setenv("GROQ_API_KEY", "test-key")

        async def fake_call_llm(self, prompt, temperature=0.3):
            if "validated_findings" in prompt:
                return json.dumps({
                    "validated_findings": [
                        {"finding_index": 1,
                         "verdict": "likely_false_positive",
                         "confidence": 0.9,
                         "reason": "generic 200 response only"},
                    ]
                })
            return None

        monkeypatch.setattr(AIIntegration, "_call_llm", fake_call_llm)

        vulns = [
            {"type": "XSS", "url": "https://t/a", "severity": "HIGH",
             "payload": "<s>", "description": "reflected"},
            {"type": "XSS", "url": "https://t/a", "severity": "HIGH",
             "payload": "<img>", "description": "reflected"},
            {"type": "XSS", "url": "https://t/a", "severity": "HIGH",
             "payload": "<svg>", "description": "reflected"},
            {"type": "SQL Injection", "url": "https://t/b",
             "severity": "CRITICAL", "payload": "1'", "description": "time"},
            {"type": "SQL Injection", "url": "https://t/b",
             "severity": "CRITICAL", "payload": "1' OR", "description": "time"},
            {"type": "SSRF", "url": "https://t/c", "severity": "HIGH",
             "payload": "http://169.254.169.254", "description": "metadata"},
        ]

        ai = await athena.run_ai_analysis(
            "https://t", {"urls": ["https://t/"]}, vulns, {"mode": "full"})

        assert ai["consolidation"] == {"raw_findings": 6,
                                       "unique_findings": 3}
        # FP verdict on consolidated position 1 expands to both SQLi rows
        assert ai["filtered_indices"] == [3, 4]
        assert len(ai["filtered_findings"]) == 2
        assert ai["filtered_findings"][0]["type"] == "SQL Injection"
        assert ai["filtered_findings"][0]["reason"]

        out = capsys.readouterr().out
        assert "Validating 3 consolidated findings (from 6 raw detections)" in out
        assert "Consolidated 2 duplicate group(s)" in out
        assert "duplicate(s) of finding: unknown" not in out

    @pytest.mark.asyncio
    async def test_ai_header_shows_provider_chain(self, monkeypatch, capsys):
        import athena

        for name in ("ATHENA_AI_PROVIDER", "GEMINI_API_KEY", "GROQ_API_KEY",
                      "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        # Hermetic: ignore the operator's real .env keys.
        monkeypatch.setattr("modules.ai_integration._dotenv_values",
                            lambda: {})
        monkeypatch.setenv("ATHENA_AI_PROVIDER", "groq")
        monkeypatch.setenv("GROQ_API_KEY", "test-key")
        monkeypatch.setenv("OPENROUTER_API_KEY", "test-or-key")

        async def fake_call_llm(self, prompt, temperature=0.3):
            return None

        from modules.ai_integration import AIIntegration
        monkeypatch.setattr(AIIntegration, "_call_llm", fake_call_llm)
        await athena.run_ai_analysis(
            "https://t", {"urls": ["https://t/"]},
            [{"type": "XSS", "url": "https://t/a", "severity": "HIGH"}],
            {"mode": "full"})
        out = capsys.readouterr().out
        assert "AI provider chain: groq -> openrouter" in out


class TestReportHardening:
    def test_severity_counts_are_case_insensitive(self):
        findings = [
            {"type": "A", "url": "https://t/1", "severity": "critical"},
            {"type": "B", "url": "https://t/2", "severity": "High"},
            {"type": "C", "url": "https://t/3", "severity": "medium"},
            {"type": "D", "url": "https://t/4", "severity": "LOW"},
            {"type": "E", "url": "https://t/5", "severity": "info"},
        ]
        report = ReportGenerator().generate_comprehensive_report(
            _results(vulnerabilities=findings))
        sev = report["athena_security_audit"]["audit_summary"][
            "severity_breakdown"]
        assert sev == {"critical": 1, "high": 1, "medium": 1, "low": 1,
                       "info": 1}

    def test_findings_registry_falls_back_to_scan_findings(self):
        report = ReportGenerator().generate_comprehensive_report(_results())
        registry = report["athena_security_audit"]["findings_registry"]
        assert len(registry) == 100
        assert registry[0]["title"]
        assert registry[0]["severity"] in ("CRITICAL", "HIGH")
        assert registry[0]["affected_asset"].startswith("https://")

    def test_registry_prefers_explicit_findings(self):
        findings = [
            {"id": "F-1", "title": "Known issue", "severity": "HIGH",
             "state": "triaged", "affected_asset": "https://t/x",
             "confidence": 0.7},
        ]
        report = ReportGenerator().generate_comprehensive_report(
            _results(findings=findings))
        registry = report["athena_security_audit"]["findings_registry"]
        assert registry == [{
            "id": "F-1", "title": "Known issue", "severity": "HIGH",
            "state": "triaged", "affected_asset": "https://t/x",
            "confidence": 0.7,
        }]

    def test_web_logins_found_counts_successes_only(self):
        # bruteforce_login_forms() only returns confirmed successes, so the
        # summary must not label that count as "logins tested".
        creds = ReportGenerator().generate_comprehensive_report(
            _results())["athena_security_audit"]["bruteforce_findings"]
        assert creds["web_logins_found"] == 1
        assert "web_logins_tested" not in creds

    def test_generator_exposes_logger_for_pdf_fallback(self, tmp_path):
        gen = ReportGenerator()
        assert hasattr(gen, "logger")
        report = gen.generate_comprehensive_report(_results())
        # reportlab may be absent; PDF generation must degrade, not raise.
        assert gen.generate_pdf_report(report, str(tmp_path / "r.pdf")) in (True, False)


class TestSarifExport:
    def _sarif(self, vulns):
        from modules.reporting import build_sarif
        return build_sarif("https://target.example", vulns)

    def test_sarif_envelope(self):
        log = self._sarif([])
        assert log["version"] == "2.1.0"
        assert log["runs"][0]["tool"]["driver"]["name"] == "Athena Security Suite"
        assert log["runs"][0]["results"] == []
        assert log["runs"][0]["tool"]["driver"]["rules"] == []

    def test_sarif_severity_mapping(self):
        log = self._sarif([
            {"type": "SQL Injection", "severity": "CRITICAL",
             "url": "https://t/a?id=1", "description": "sqli"},
            {"type": "Missing Security Header", "severity": "MEDIUM",
             "url": "https://t/", "description": "no hsts"},
            {"type": "Info Leak", "severity": "INFO",
             "url": "https://t/i", "description": "banner"},
        ])
        levels = {r["ruleId"]: r["level"] for r in log["runs"][0]["results"]}
        assert levels["athena/sql-injection"] == "error"
        assert levels["athena/missing-security-header"] == "warning"
        assert levels["athena/info-leak"] == "note"

    def test_sarif_rule_ids_stable_and_deduped(self):
        log = self._sarif([
            {"type": "XSS", "severity": "HIGH", "url": "https://t/1"},
            {"type": "XSS", "severity": "HIGH", "url": "https://t/2"},
        ])
        run = log["runs"][0]
        assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["athena/xss"]
        assert len(run["results"]) == 2
        assert run["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"]["uri"] == "https://t/1"

    def test_false_positive_marked_findings_excluded(self):
        from modules.reporting import build_sarif, is_false_positive_finding
        assert is_false_positive_finding(
            {'type': 'XSS', 'false_positive': True}) is True
        assert is_false_positive_finding(
            {'type': 'XSS', 'state': 'false_positive'}) is True
        assert is_false_positive_finding(
            {'type': 'XSS', 'state': 'False_Positive'}) is True
        assert is_false_positive_finding(
            {'type': 'XSS', 'severity': 'HIGH'}) is False
        assert is_false_positive_finding(
            {'type': 'XSS', 'verification': {'status': 'inconclusive'}}) is False
        assert is_false_positive_finding(None) is False
        assert is_false_positive_finding('xss') is False

        log = build_sarif("t", [
            {"type": "XSS", "severity": "HIGH", "url": "https://t/1"},
            {"type": "XSS", "severity": "HIGH", "url": "https://t/2",
             "false_positive": True},
            {"type": "SQL Injection", "severity": "CRITICAL",
             "url": "https://t/3", "state": "false_positive"},
            # Inconclusive is NOT a false positive - it stays.
            {"type": "XSS", "severity": "HIGH", "url": "https://t/4",
             "verification": {"status": "inconclusive"}},
        ])
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in log["runs"][0]["results"]]
        assert uris == ["https://t/1", "https://t/4"]

    def test_sarif_drops_non_dicts_and_missing_url(self):
        log = self._sarif([None, "xss", {"type": "XSS", "severity": "HIGH"}])
        results = log["runs"][0]["results"]
        assert len(results) == 1
        assert "locations" not in results[0]

    def test_sarif_carries_verification(self):
        log = self._sarif([{
            "type": "SQL Injection", "severity": "CRITICAL",
            "url": "https://t/a", "verified": True,
            "verification": {"status": "confirmed"},
        }])
        props = log["runs"][0]["results"][0]["properties"]
        assert props["athenaVerification"] == "confirmed"
        assert props["athenaVerified"] is True

    def test_export_to_sarif_writes_file(self, tmp_path):
        gen = ReportGenerator()
        path = str(tmp_path / "r.sarif")
        gen.export_to_sarif(
            {"target": "t", "vulnerabilities": [
                {"type": "XSS", "severity": "HIGH", "url": "https://t/"}]},
            path)
        with open(path, encoding="utf-8") as fh:
            log = json.load(fh)
        assert log["version"] == "2.1.0"
        assert len(log["runs"][0]["results"]) == 1

    def test_history_export_sarif(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATHENA_DB_PATH", str(tmp_path / "h.db"))
        from modules.scan_store import ScanStore, export_scan
        store = ScanStore()
        try:
            sid = store.record_scan(
                "https://t", "vuln", "complete", {},
                [{"type": "XSS", "severity": "HIGH", "url": "https://t/"}])
            content = export_scan(store, sid, "sarif")
            assert content is not None
            log = json.loads(content)
            assert log["runs"][0]["results"][0]["ruleId"] == "athena/xss"
        finally:
            store.close()
