"""Prompt A criterion 4: native + nuclei correlation units."""

import sys
from pathlib import Path

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.correlation import correlate_tool_findings
from modules.reporting import ReportGenerator

URL = "http://target.test/search?q=x&id=2"


def _native_sqli():
    return {
        "id": "n1",
        "type": "SQL Injection",
        "url": URL,
        "severity": "HIGH",
        "description": "error-based SQLi in id",
        "payload": "' OR 1=1-- -",
        "evidence": {"param": "id"},
        "source": "athena-native",
        "confidence": "high",
    }


def _nuclei_sqli():
    return {
        "id": "nuc-1",
        "type": "SQL Injection",
        "url": URL,
        "severity": "HIGH",
        "description": "nuclei sqli template matched",
        "payload": "",
        "evidence": {
            "tool": "nuclei",
            "template": "http/vulnerabilities/other/sqli",
            "matcher": "word",
        },
        "source": "nuclei",
        "confidence": "high",
    }


class TestCorrelateToolFindings:
    def test_match_merges_and_marks_sources(self):
        result = correlate_tool_findings([_native_sqli()], [_nuclei_sqli()])

        assert result.corroborated == 1
        assert result.tool_only == 0
        assert len(result.merged) == 1
        merged = result.merged[0]
        assert merged["corroborated"] is True
        assert "athena-native" in merged["sources"]
        assert any(str(s).startswith("nuclei:") for s in merged["sources"])
        assert "sqli" in " ".join(merged.get("corroborated_by", []))

    def test_unmatched_nuclei_match_is_tool_only(self):
        other = _nuclei_sqli()
        other["id"] = "nuc-2"
        other["url"] = "http://target.test/other?x=1"

        result = correlate_tool_findings([_native_sqli()],
                                         [_nuclei_sqli(), other])

        assert result.corroborated == 1
        assert result.tool_only == 1
        leftovers = [f for f in result.merged if f.get("tool_only")]
        assert len(leftovers) == 1
        assert leftovers[0]["url"] == other["url"]

    def test_unmatched_native_stays_native_only(self):
        result = correlate_tool_findings([_native_sqli()], [])

        assert result.corroborated == 0
        assert result.tool_only == 0
        assert result.native_only == 1
        assert result.merged[0].get("corroborated") is not True

    def test_summary_counts_feed_the_report(self):
        other = _nuclei_sqli()
        other["id"] = "nuc-2"
        other["url"] = "http://target.test/other?x=1"

        result = correlate_tool_findings([_native_sqli()],
                                         [_nuclei_sqli(), other])
        summary = result.summary()
        assert summary["corroborated"] == 1
        assert summary["tool_only"] == 1

        report = ReportGenerator().generate_comprehensive_report({
            "target": "http://target.test",
            "vulnerabilities": result.merged,
            "discovery": {},
            "correlation": summary,
        })
        audit = report["athena_security_audit"]["audit_summary"]
        assert audit["corroborated_findings"] == 1
        assert audit["tool_only_findings"] == 1

    def test_empty_inputs_yield_empty_result(self):
        result = correlate_tool_findings([], [])
        assert result.merged == []
        assert result.summary()["total"] == 0
