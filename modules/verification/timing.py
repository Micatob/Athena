"""Differential timing verification for time-based injection.

A single slow response proves nothing - real hosts answer in 1-25s under
load.  A delay only counts as evidence when the *payload* responses are
statistically slower than *benign* responses to the same endpoint:

* ``benign_rounds`` (default 3) benign probes establish the baseline;
* ``payload_rounds`` (default 3) sleep-payload probes are measured per
  requested sleep level (default ``(2.0, 5.0)`` seconds);
* a level passes when ``payload_median >= benign_median +
  max(factor * MAD, min_delta)`` with ``factor = 2.5`` and
  ``min_delta = 0.5s`` - the MAD term absorbs host jitter, the absolute
  term absorbs timer noise on fast hosts;
* *every* sleep level must pass, otherwise one flaky measurement could
  confirm a vulnerability that does not exist.

WAF-aware abort: when the WAF gate already reported a blocking verdict and
this host has returned 403/406 twice, no further request is sent - the
result is ``skipped_waf``, not a wasted minute of blocked probes.  A blocked
benign probe also ends the check immediately (a baseline measured through
a block page is dishonest data).

Verdicts: ``confirmed_timing`` | ``inconclusive_timing`` | ``skipped_waf``.
"""

from __future__ import annotations

import asyncio
import logging
import statistics
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, MutableMapping, Optional, Tuple

logger = logging.getLogger("athena.verify.timing")

#: ``fetch`` takes a payload string (``None`` = benign probe) and returns
#: ``(elapsed_seconds, http_status)``, or ``None`` on network failure.
#: Payload construction (param substitution, encoding) is the caller's job.
Fetch = Callable[[Optional[str]], Awaitable[Optional[Tuple[float, Optional[int]]]]]

#: WAF gate verdicts that mean "probes will be blocked, not answered".
BLOCK_VERDICTS = frozenset({"likely", "confirmed", "hard-block", "blocked"})

#: HTTP statuses that mean "the WAF ate this request".
BLOCK_STATUSES = frozenset({403, 406})

#: Hosts that returned this many blocks are skipped without any new request.
SKIP_AFTER_BLOCKS = 2


@dataclass
class TimingConfig:
    benign_rounds: int = 3
    payload_rounds: int = 3
    sleeps: Tuple[float, ...] = (2.0, 5.0)
    factor: float = 2.5
    min_delta: float = 0.5
    delay: float = 0.6
    timeout: float = 0.0  # 0 = max(sleeps) + 10


@dataclass
class TimingLevel:
    sleep: float
    payload_median: float
    threshold: float
    passed: bool
    samples: List[float] = field(default_factory=list)


@dataclass
class TimingResult:
    verdict: str  # confirmed_timing | inconclusive_timing | skipped_waf
    benign_median: float = 0.0
    benign_mad: float = 0.0
    levels: List[TimingLevel] = field(default_factory=list)
    detail: str = ""
    blocked: bool = False

    def evidence(self) -> Dict[str, Any]:
        return {
            "method": "time_based_differential",
            "baseline_s": round(self.benign_median, 3),
            "baseline_mad_s": round(self.benign_mad, 3),
            "levels": [
                {"sleep_s": lvl.sleep,
                 "payload_median_s": round(lvl.payload_median, 3),
                 "threshold_s": round(lvl.threshold, 3),
                 "passed": lvl.passed}
                for lvl in self.levels
            ],
        }


def _median(values: List[float]) -> float:
    return float(statistics.median(values))


def _mad(values: List[float], median: float) -> float:
    if not values:
        return 0.0
    return float(statistics.median([abs(v - median) for v in values]))


async def verify_differential(
    fetch: Fetch,
    payload_for_sleep: Callable[[float], str],
    *,
    config: Optional[TimingConfig] = None,
    waf_verdict: str = "",
    host: str = "",
    block_tracker: Optional[MutableMapping[str, int]] = None,
) -> TimingResult:
    """Run the benign-vs-payload differential and return a verdict.

    ``payload_for_sleep`` builds the injected value for a requested sleep
    (e.g. ``lambda s: f"' AND SLEEP({s:g})-- -"``).  ``block_tracker`` is a
    caller-owned ``{host: block_count}`` mapping persisted across findings.
    """
    cfg = config or TimingConfig()
    benign_n = max(2, int(cfg.benign_rounds or 3))
    payload_n = max(2, int(cfg.payload_rounds or 3))
    sleeps = sorted({float(s) for s in (cfg.sleeps or (2.0,)) if float(s) > 0})
    if not sleeps:
        sleeps = [2.0]
    factor = float(cfg.factor or 2.5)
    min_delta = float(cfg.min_delta if cfg.min_delta is not None else 0.5)
    delay = max(0.0, float(cfg.delay or 0.0))
    timeout = float(cfg.timeout or 0.0) or (max(sleeps) + 10.0)
    tracker: MutableMapping[str, int] = (
        block_tracker if block_tracker is not None else {})
    host_key = host or "_"

    async def guarded(payload: Optional[str]) -> Optional[Tuple[float, Optional[int]]]:
        try:
            return await asyncio.wait_for(fetch(payload), timeout=timeout)
        except (asyncio.TimeoutError, Exception) as exc:  # network failure
            logger.debug("timing probe failed: %s", exc)
            return None

    def bump_block() -> int:
        try:
            tracker[host_key] = int(tracker.get(host_key, 0)) + 1
        except (TypeError, ValueError):
            tracker[host_key] = 1
        return int(tracker[host_key])

    # Full skip: this host already proved it blocks us.
    if str(waf_verdict or "").lower() in BLOCK_VERDICTS \
            and int(tracker.get(host_key, 0) or 0) >= SKIP_AFTER_BLOCKS:
        return TimingResult(
            verdict="skipped_waf", blocked=True,
            detail=(f"WAF verdict {waf_verdict!r} and {tracker.get(host_key)} "
                    f"prior 403/406 block(s) on {host_key}: timing aborted, "
                    f"no requests sent"))

    # -- benign baseline -------------------------------------------------
    benign: List[float] = []
    for _ in range(benign_n):
        sample = await guarded(None)
        if delay:
            await asyncio.sleep(delay)
        if sample is None:
            return TimingResult(
                verdict="inconclusive_timing",
                detail="benign baseline probe failed (network error); "
                       "timing cannot be trusted")
        elapsed, status = sample
        if status in BLOCK_STATUSES:
            count = bump_block()
            return TimingResult(
                verdict="skipped_waf", blocked=True,
                detail=(f"benign probe blocked (HTTP {status}); block "
                        f"#{count} on {host_key}: baseline through a block "
                        f"page would be dishonest"))
        benign.append(max(0.0, float(elapsed)))

    median_b = _median(benign)
    mad = _mad(benign, median_b)
    threshold_base = median_b + max(factor * mad, min_delta)

    # -- payload levels ----------------------------------------------------
    levels: List[TimingLevel] = []
    for sleep in sleeps:
        try:
            payload = payload_for_sleep(float(sleep))
        except Exception as exc:
            return TimingResult(
                verdict="inconclusive_timing", benign_median=median_b,
                benign_mad=mad,
                detail=f"payload builder failed for sleep {sleep:g}: {exc}")
        samples: List[float] = []
        level_blocked = False
        for _ in range(payload_n):
            sample = await guarded(payload)
            if delay:
                await asyncio.sleep(delay)
            if sample is None:
                return TimingResult(
                    verdict="inconclusive_timing", benign_median=median_b,
                    benign_mad=mad,
                    detail=(f"payload probe (sleep {sleep:g}s) failed "
                            f"(network error); timing cannot be trusted"))
            elapsed, status = sample
            if status in BLOCK_STATUSES:
                level_blocked = True
                break
            samples.append(max(0.0, float(elapsed)))
        if level_blocked:
            count = bump_block()
            return TimingResult(
                verdict="skipped_waf", benign_median=median_b,
                benign_mad=mad, blocked=True,
                detail=(f"payload probe blocked (HTTP 403/406); block "
                        f"#{count} on {host_key}: payload never executed"))
        med = _median(samples)
        passed = med >= threshold_base
        levels.append(TimingLevel(sleep=float(sleep), payload_median=med,
                                  threshold=threshold_base, passed=passed,
                                  samples=[round(s, 3) for s in samples]))

    if levels and all(lvl.passed for lvl in levels):
        parts = ", ".join(
            f"sleep {lvl.sleep:g}s -> {lvl.payload_median:.2f}s "
            f"(threshold {lvl.threshold:.2f}s)" for lvl in levels)
        return TimingResult(
            verdict="confirmed_timing", benign_median=median_b,
            benign_mad=mad, levels=levels,
            detail=(f"payload responses slower than benign baseline "
                    f"{median_b:.2f}s (MAD {mad:.2f}s) at every level: "
                    f"{parts}"))

    failed = [lvl for lvl in levels if not lvl.passed]
    parts = "; ".join(
        f"sleep {lvl.sleep:g}s -> {lvl.payload_median:.2f}s "
        f"(needed >= {lvl.threshold:.2f}s)" for lvl in failed)
    return TimingResult(
        verdict="inconclusive_timing", benign_median=median_b,
        benign_mad=mad, levels=levels,
        detail=(f"no timing oracle: payload responses within benign baseline "
                f"{median_b:.2f}s (MAD {mad:.2f}s): {parts}"))
