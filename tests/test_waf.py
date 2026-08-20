"""Tests for WAF detection and evasion support."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from modules.waf import WAFDetector, WAFReport


class TestWAFTamper(unittest.TestCase):
    """Payload tamper transforms."""

    def test_sql_tamper_produces_variants(self):
        variants = WAFDetector.tamper("' OR 1=1--", 'sql')
        self.assertTrue(variants)
        for v in variants:
            self.assertNotEqual(v, "' OR 1=1--")

    def test_sql_comment_injection(self):
        variants = WAFDetector.tamper("UNION SELECT 1", 'sql')
        self.assertTrue(any('/**/' in v or '/*!50000' in v for v in variants))

    def test_xss_tamper(self):
        variants = WAFDetector.tamper("<script>alert(1)</script>", 'xss')
        self.assertTrue(variants)

    def test_cmd_tamper(self):
        variants = WAFDetector.tamper("; cat /etc/passwd ;", 'cmd')
        self.assertTrue(any('${IFS}' in v or '{IFS}' in v or '%09' in v for v in variants))

    def test_traversal_tamper(self):
        variants = WAFDetector.tamper("../../../../etc/passwd", 'traversal')
        self.assertTrue(variants)

    def test_limit_respected(self):
        variants = WAFDetector.tamper("' OR 1=1--", 'sql', limit=2)
        self.assertLessEqual(len(variants), 2)

    def test_empty_payload(self):
        self.assertEqual(WAFDetector.tamper("", 'sql'), [])

    def test_unknown_vuln_type(self):
        self.assertEqual(WAFDetector.tamper("foo", 'unknown'), [])

    def test_no_duplicates(self):
        variants = WAFDetector.tamper("' OR 1=1--", 'sql', limit=10)
        self.assertEqual(len(variants), len(set(variants)))


class TestWAFEvasionAdvice(unittest.TestCase):

    def test_specific_advice(self):
        advice = WAFDetector.evasion_advice('Cloudflare')
        self.assertTrue(any('origin' in a.lower() for a in advice))

    def test_modsecurity_advice(self):
        advice = WAFDetector.evasion_advice('ModSecurity')
        self.assertTrue(any('comment' in a.lower() for a in advice))

    def test_generic_advice(self):
        advice = WAFDetector.evasion_advice('UnknownWAF')
        self.assertTrue(advice)


class TestWAFDetect(unittest.TestCase):
    """Passive + active WAF detection."""

    def _fake_response(self, status=200, headers=None, cookies=None, text=""):
        resp = MagicMock()
        resp.status = status
        resp.headers = headers or {}
        resp.cookies = MagicMock()
        resp.cookies.values.return_value = []
        resp.text = AsyncMock(return_value=text)
        return resp

    def test_cloudflare_header_detected(self):
        async def _run():
            detector = WAFDetector()
            fake = self._fake_response(headers={'server': 'cloudflare', 'cf-ray': 'abc123'})
            detector._probe = AsyncMock(side_effect=[fake, None, None, None, None])
            report = await detector.detect('https://example.com')
            await detector.close()
            return report
        report = asyncio.run(_run())
        self.assertTrue(report.detected)
        self.assertEqual(report.waf_name, 'Cloudflare')
        self.assertGreater(report.confidence, 0.5)

    def test_no_waf_detected(self):
        async def _run():
            detector = WAFDetector()
            plain = self._fake_response(headers={'server': 'nginx'})
            detector._probe = AsyncMock(return_value=plain)
            report = await detector.detect('https://example.com')
            await detector.close()
            return report
        report = asyncio.run(_run())
        self.assertFalse(report.detected)

    def test_active_blocking_detected(self):
        async def _run():
            detector = WAFDetector()
            plain = self._fake_response(headers={'server': 'nginx'})
            blocked = self._fake_response(status=403)
            detector._probe = AsyncMock(side_effect=[plain, blocked, blocked, blocked, blocked])
            report = await detector.detect('https://example.com')
            await detector.close()
            return report
        report = asyncio.run(_run())
        self.assertTrue(report.detected)
        self.assertTrue(report.challenge_blocked)
        self.assertEqual(report.challenge_status, 403)

    def test_report_to_dict(self):
        report = WAFReport(detected=True, waf_name='Cloudflare', confidence=0.8,
                           matched_signatures=['header:server: cloudflare'])
        d = report.to_dict()
        self.assertTrue(d['detected'])
        self.assertEqual(d['waf_name'], 'Cloudflare')
        self.assertEqual(d['matched_signatures'], ['header:server: cloudflare'])


if __name__ == '__main__':
    unittest.main()
