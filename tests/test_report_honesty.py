"""
tests/test_report_honesty.py – Phase A report honesty fixes
============================================================
From the first live report review:

  * "-m vuln" printed "Open Ports / URLs / Subdomains: None detected" even
    though discovery never ran in that mode - unscanned must not read as
    clean;
  * raw scanner rows sat under a "Confirmed Findings:" banner while the row
    itself said "manual verification recommended";
  * remediation collapsed to one generic "General Hardening" line while
    real findings existed;
  * five MEDIUM findings produced a "LOW" risk rating;
  * the compliance block claimed PASS-ish statuses from an automated scan;
  * the AI note said "no finding was ... removed by the model" directly
    above a table of 8 findings excluded from testing.
"""

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import athena
from modules.reporting import ReportGenerator


def _report(**overrides):
    results = {'target': 'https://honesty.test',
               'vulnerabilities': [], 'discovery': {}}
    results.update(overrides)
    return ReportGenerator().generate_comprehensive_report(results)


class TestDiscoveryCoverage:
    def test_discovery_flagged_when_never_ran(self):
        audit = _report()['athena_security_audit']
        assert audit['discovery_findings']['ran'] is False

    def test_discovery_flagged_when_it_ran(self):
        audit = _report(discovery={'urls': ['https://honesty.test/']})[
            'athena_security_audit']
        assert audit['discovery_findings']['ran'] is True

    def test_unscanned_reads_as_not_scanned_in_html(self):
        report = _report()
        html = athena._generate_html_report(report)
        assert 'Not scanned in this mode' in html
        assert 'None detected' not in html

    def test_scanned_but_empty_still_reads_none_detected(self):
        report = _report(discovery={'urls': [], 'subdomains': [],
                                    'ports': [], 'technologies': []})
        html = athena._generate_html_report(report)
        assert 'None detected' in html
        assert 'Not scanned in this mode' not in html

    def test_discovered_assets_are_listed_when_present(self):
        report = _report(discovery={'urls': ['https://honesty.test/admin']})
        html = athena._generate_html_report(report)
        assert 'https://honesty.test/admin' in html


class TestObservationsNotConfirmed:
    def _finding(self, **extra):
        f = {'type': 'Possible Directory Listing',
             'url': 'https://honesty.test/admin/', 'severity': 'MEDIUM',
             'description': 'Directory listing observed'}
        f.update(extra)
        return f

    def test_unverified_rows_read_as_observations(self):
        report = _report(vulnerabilities=[self._finding()])
        html = athena._generate_html_report(report)
        # Hardened labels: unverified leads, never presented as confirmed
        assert ('Unverified observations' in html
                or 'Observations (scanner detections, not actively proven)' in html)
        assert '>CONFIRMED<' not in html

    def test_verified_rows_are_marked_confirmed(self):
        report = _report(vulnerabilities=[
            self._finding(verified=True,
                          verification={'status': 'confirmed'})])
        html = athena._generate_html_report(report)
        assert '>CONFIRMED<' in html
        assert ('Confirmed proof' in html
                or 'Detection Details (confirmed rows verified)' in html or
                'confirmed rows marked' in html)

    def test_rows_carry_verification_state(self):
        details = _report(vulnerabilities=[
            self._finding(verified=True, verification={'status': 'confirmed'}),
            self._finding(url='https://honesty.test/assets/',
                          description='second row'),
        ])['athena_security_audit']['detailed_analysis']
        rows = details['Possible Directory Listing']['confirmed_findings']
        assert [r['verified'] for r in rows] == [True, False]


class TestRiskRating:
    @pytest.mark.parametrize('sevs,expected', [
        (['CRITICAL'], 'CRITICAL'),
        (['HIGH', 'HIGH', 'HIGH', 'HIGH', 'HIGH'], 'HIGH'),
        (['HIGH'], 'MEDIUM'),
        (['MEDIUM', 'MEDIUM', 'MEDIUM', 'MEDIUM', 'MEDIUM'], 'MEDIUM'),
        (['LOW', 'LOW'], 'LOW'),
        ([], 'LOW'),
    ])
    def test_mediums_raise_the_rating(self, sevs, expected):
        vulns = [{'type': f'Thing {i}', 'url': f'https://honesty.test/{i}',
                  'severity': s} for i, s in enumerate(sevs)]
        report = _report(vulnerabilities=vulns)
        got = report['athena_security_audit']['audit_summary']['risk_rating']
        assert got == expected

    def test_calculate_takes_medium_argument(self):
        gen = ReportGenerator()
        assert gen._calculate_overall_risk([], [], ['m']) == 'MEDIUM'


class TestPerFindingRemediation:
    def test_specific_findings_get_specific_fixes(self):
        recs = ReportGenerator().generate_recommendations([
            {'type': 'Possible Directory Listing', 'severity': 'MEDIUM'},
            {'type': 'Missing Security Headers', 'severity': 'MEDIUM'},
            {'type': 'Sensitive Comment in Source', 'severity': 'LOW'},
            {'type': 'Open Redirect', 'severity': 'MEDIUM'},
        ])
        issues = [r['issue'] for r in recs]
        assert 'Directory Listing' in issues
        assert 'Missing Security Headers' in issues
        assert 'General Hardening' not in issues, \
            'generic line must not replace real, per-finding guidance'
        for rec in recs:
            assert rec['recommendation'] and len(rec['recommendation']) > 40

    def test_unmapped_types_still_get_an_entry(self):
        recs = ReportGenerator().generate_recommendations([
            {'type': 'Exotic Widget Desync', 'severity': 'HIGH'},
        ])
        assert len(recs) == 1
        assert recs[0]['issue'] == 'Exotic Widget Desync'
        assert recs[0]['severity'] == 'HIGH'
        assert recs[0]['timeline'] == 'Urgent'

    def test_generic_line_only_when_no_findings(self):
        recs = ReportGenerator().generate_recommendations([])
        assert [r['issue'] for r in recs] == ['General Hardening']

    def test_no_duplicate_entries_for_repeated_types(self):
        recs = ReportGenerator().generate_recommendations([
            {'type': 'Missing Security Headers', 'severity': 'MEDIUM'},
            {'type': 'Missing Security Headers', 'severity': 'MEDIUM'},
        ])
        assert len(recs) == 1


class TestComplianceNeverOverclaims:
    def test_clean_scan_is_not_a_pass(self):
        compliance = _report()['athena_security_audit']['compliance_audit']
        assert compliance['gdpr_assessment']['status'] == 'NOT_ASSESSED'
        assert compliance['pci_dss_assessment']['status'] == 'NOT_ASSESSED'
        assert 'meets basic requirement standard' not in str(compliance)
        assert 'manually' in str(compliance).lower() or \
            'manual' in str(compliance).lower()

    def test_real_violations_still_fail(self):
        compliance = _report(vulnerabilities=[
            {'type': 'SQL Injection', 'url': 'https://honesty.test/?id=1',
             'severity': 'CRITICAL'},
        ])['athena_security_audit']['compliance_audit']
        assert compliance['pci_dss_assessment']['status'] == 'FAIL'


class TestAiNoteWording:
    def test_note_explains_exclusion_instead_of_denying_it(self):
        report = _report(ai_analysis={
            'provider': 'groq', 'model': 'm',
            'statements': [], 'false_positive_hypotheses': [],
            'validated_findings': [], 'filtered_findings': [
                {'type': 'SSRF', 'url': 'https://honesty.test/admin',
                 'reason': 'no proof', 'confidence': 0.8},
            ],
            'filtered_indices': [0],
            'consolidation': {'raw_findings': 13, 'unique_findings': 13},
        })
        html = athena._generate_html_report(report)
        assert 'no finding was reclassified or removed' not in html
        assert 'excluded from active' in html
        # operator rule: what the terminal hides, the HTML hides too -
        # the flagged URL never renders; only the count line does
        assert 'https://honesty.test/admin' not in html
        assert 'flagged as likely false positives' in html
