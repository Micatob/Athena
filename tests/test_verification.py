"""Prompt A criteria 2-3: timing + OOB verification units.

All transports are stubbed or faked - no real network, no waiting on the
60s OOB window (the fake collector answers polls immediately).
"""

import asyncio
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import modules.verification.oob as oob_mod
from modules.verification.oob import OOBCollector, OOBConfig, attempt_oob
from modules.verification.timing import TimingConfig, verify_differential


def _sqli_builder(sleep):
    return "' AND SLEEP(%g)-- -" % float(sleep)


class TestTimingVerification:
    pytestmark = pytest.mark.asyncio

    async def test_confirmed_timing_with_mocked_http(self):
        """Benign ~200ms, payload ~800ms -> confirmed_timing (criterion 2)."""
        async def fetch(payload):
            await asyncio.sleep(0)
            return (0.8, 200) if payload is not None else (0.2, 200)

        result = await verify_differential(fetch, _sqli_builder)

        assert result.verdict == "confirmed_timing"
        assert len(result.levels) == 2
        assert all(lvl.passed for lvl in result.levels)

    async def test_noise_yields_inconclusive_timing(self):
        """Both ~200ms -> inconclusive_timing, never confirmed (criterion 2)."""
        async def fetch(payload):
            await asyncio.sleep(0)
            return (0.21, 200) if payload is not None else (0.2, 200)

        result = await verify_differential(fetch, _sqli_builder)

        assert result.verdict == "inconclusive_timing"
        assert result.levels
        assert not all(lvl.passed for lvl in result.levels)

    async def test_failed_baseline_is_inconclusive(self):
        async def fetch(payload):
            await asyncio.sleep(0)
            return None

        result = await verify_differential(fetch, _sqli_builder)

        assert result.verdict == "inconclusive_timing"

    async def test_explicit_config_is_honoured(self):
        probes = []

        async def fetch(payload):
            await asyncio.sleep(0)
            probes.append(payload)
            return (0.9, 200) if payload is not None else (0.1, 200)

        cfg = TimingConfig(benign_rounds=2, payload_rounds=2,
                           sleeps=(2.0,), delay=0)
        result = await verify_differential(fetch, _sqli_builder, config=cfg)

        assert result.verdict == "confirmed_timing"
        assert len(probes) == 4  # 2 benign + 2 payload

    async def test_blocked_benign_probe_aborts_with_skipped_waf(self):
        seen = []

        async def fetch(payload):
            await asyncio.sleep(0)
            seen.append(payload)
            return (0.1, 403)

        result = await verify_differential(
            fetch, _sqli_builder, waf_verdict="confirmed",
            host="waf.test", block_tracker={})

        assert result.verdict == "skipped_waf"
        assert result.blocked is True
        assert len(seen) == 1  # baseline through a block page is dishonest


class _FakeCollector(OOBCollector):
    name = "fake"
    third_party = False
    routable = True

    def __init__(self, will_hit=True):
        self.will_hit = will_hit
        self.seen = []

    def available(self):
        return True

    async def start(self):
        return True

    async def stop(self):
        pass

    def callback_url(self, token):
        return "http://oob.test.local/%s" % token

    async def poll(self, token, timeout, interval=5.0):
        self.seen.append(token)
        return self.will_hit


class TestOOBVerification:
    pytestmark = pytest.mark.asyncio

    async def test_callback_received_confirms_oob(self, monkeypatch):
        """Fake collector sees the callback -> confirmed_oob (criterion 3)."""
        fake = _FakeCollector(will_hit=True)
        monkeypatch.setattr(oob_mod, "select_collectors",
                            lambda config: [fake])

        async def inject(url):
            return True

        result = await attempt_oob(inject, OOBConfig(), token="fixedtoken1")

        assert result.verdict == "confirmed_oob"
        assert result.collector == "fake"
        assert result.token == "fixedtoken1"
        assert fake.seen == ["fixedtoken1"]

    async def test_no_callback_is_inconclusive_oob(self, monkeypatch):
        """Probe delivered, nothing calls back -> inconclusive_oob."""
        fake = _FakeCollector(will_hit=False)
        monkeypatch.setattr(oob_mod, "select_collectors",
                            lambda config: [fake])

        async def inject(url):
            return True

        result = await attempt_oob(inject, OOBConfig(), token="fixedtoken2")

        assert result.verdict == "inconclusive_oob"
        assert "no callback" in result.detail

    async def test_undelivered_probe_skips_the_wait_window(self, monkeypatch):
        """inject False means the probe never got through: no polling."""
        fake = _FakeCollector(will_hit=True)
        monkeypatch.setattr(oob_mod, "select_collectors",
                            lambda config: [fake])

        async def inject(url):
            return False

        result = await attempt_oob(inject, OOBConfig(), token="fixedtoken3")

        assert result.verdict == "inconclusive_oob"
        assert fake.seen == []  # poll never ran, no time burned
        assert "no proof" in result.detail

    async def test_delivery_failure_falls_through_to_next_channel(
            self, monkeypatch):
        """A dead first channel must not block a working second one."""
        first = _FakeCollector(will_hit=True)
        first.name = "fake-first"
        second = _FakeCollector(will_hit=True)
        second.name = "fake-second"
        monkeypatch.setattr(oob_mod, "select_collectors",
                            lambda config: [first, second])

        attempts = []

        async def inject(url):
            attempts.append(url)
            return len(attempts) > 1  # first delivery fails, second works

        result = await attempt_oob(inject, OOBConfig(), token="fixedtoken5")

        assert result.verdict == "confirmed_oob"
        assert result.collector == "fake-second"
        assert first.seen == []
        assert second.seen == ["fixedtoken5"]

    async def test_no_collector_is_skipped(self, monkeypatch):
        monkeypatch.setattr(oob_mod, "select_collectors", lambda config: [])

        async def inject(url):
            return True

        result = await attempt_oob(inject, OOBConfig(), token="fixedtoken4")

        assert result.verdict == "skipped_no_collector"
