"""Confirmed timing-oracle verification.

A single slow HTTP response proves nothing: real hosts answer in 1-25s
depending on load, and a payload that "took 7.5s" against a 14s baseline is
a false positive, not an injection.

A delay only counts as evidence when **all** of the following hold:

1. the benign baseline is stable (spread below ``max_spread_ratio`` of the
   smallest sleep), otherwise the host is too jittery to measure;
2. every measured delay clears ``baseline + min_ratio * sleep``;
3. the delay *scales* with the requested sleep - ``SLEEP(5)`` must be at
   least ``min_scaling`` longer than ``SLEEP(2)``.

Anything else returns ``None`` so callers report "no proof" instead of a
confirmed vulnerability.
"""
from __future__ import annotations

import statistics
from typing import (Any, Awaitable, Callable, Dict, List, Optional, Sequence,
                    Tuple)

#: async callable returning elapsed seconds, or ``None`` when it failed.
Sample = Callable[[], Awaitable[Optional[float]]]
#: async callable returning elapsed seconds for a payload sleeping ``s``.
PayloadSample = Callable[[float], Awaitable[Optional[float]]]

#: Smallest/largest sleep used by callers that do not pick their own.
DEFAULT_SLEEPS: Tuple[float, ...] = (2.0, 5.0)

#: A delay must reach ``baseline + MIN_RATIO * sleep`` to count.
MIN_RATIO = 0.8
#: Extra delay between the smallest and largest sleep must reach
#: ``(max_sleep - min_sleep) * MIN_SCALING``.
MIN_SCALING = 0.6
#: Baseline jitter above ``max_spread_ratio * min_sleep`` makes timing
#: measurements meaningless.
MAX_SPREAD_RATIO = 0.5


def _spread_ratio(sleeps: Sequence[float]) -> float:
    return min(float(s) for s in sleeps) * MAX_SPREAD_RATIO


async def measure_baseline(sample: Sample, *, samples: int = 2,
                           max_spread: Optional[float] = None
                           ) -> Optional[Tuple[float, float]]:
    """Return ``(median_seconds, spread_seconds)`` for benign requests.

    ``None`` when any sample failed (timeout, connection error) or the host
    jitter exceeds ``max_spread`` - both mean timing cannot be trusted.
    """
    timings: List[float] = []
    for _ in range(max(2, int(samples))):
        elapsed = await sample()
        if elapsed is None or elapsed < 0:
            return None
        timings.append(float(elapsed))
    median = float(statistics.median(timings))
    spread = max(timings) - min(timings)
    if max_spread is not None and spread > max_spread:
        return None
    return median, spread


async def verify_with_baseline(payload_sample: PayloadSample,
                               baseline: Optional[Tuple[float, float]],
                               sleeps: Sequence[float] = DEFAULT_SLEEPS,
                               *, min_ratio: float = MIN_RATIO,
                               min_scaling: float = MIN_SCALING
                               ) -> Optional[Dict[str, Any]]:
    """Confirm a timing hit against ``baseline``; ``None`` when unproven."""
    if not baseline:
        return None
    ordered = sorted({float(s) for s in sleeps})
    if len(ordered) < 2:
        return None

    median, spread = baseline
    if spread > _spread_ratio(ordered):
        return None

    measured: List[float] = []
    for sleep in ordered:
        elapsed = await payload_sample(sleep)
        if elapsed is None:
            return None
        measured.append(float(elapsed))

    for sleep, elapsed in zip(ordered, measured):
        if elapsed < median + sleep * min_ratio:
            return None

    span = ordered[-1] - ordered[0]
    observed = measured[-1] - measured[0]
    if span <= 0 or observed < span * min_scaling:
        return None

    return {
        'method': 'time_based',
        'baseline_s': round(median, 2),
        'baseline_spread_s': round(spread, 2),
        'requested_s': [round(s, 2) for s in ordered],
        'measured_s': [round(e, 2) for e in measured],
        'overhead_s': round(observed - span, 2),
    }


async def verify_sleep_delay(payload_sample: PayloadSample,
                             baseline_sample: Sample,
                             sleeps: Sequence[float] = DEFAULT_SLEEPS,
                             *, baseline_samples: int = 2,
                             min_ratio: float = MIN_RATIO,
                             min_scaling: float = MIN_SCALING
                             ) -> Optional[Dict[str, Any]]:
    """Measure the baseline and confirm the delay in one call."""
    baseline = await measure_baseline(
        baseline_sample, samples=baseline_samples,
        max_spread=_spread_ratio(sleeps))
    if baseline is None:
        return None
    return await verify_with_baseline(payload_sample, baseline, sleeps,
                                      min_ratio=min_ratio,
                                      min_scaling=min_scaling)


def format_delay_evidence(evidence: Optional[Dict[str, Any]]) -> str:
    """Human-readable one-liner for a confirmed timing oracle."""
    if not evidence:
        return 'no timing evidence'
    requested = evidence.get('requested_s') or []
    measured = evidence.get('measured_s') or []
    parts = ', '.join(
        'sleep %gs -> %.2fs' % (float(req), float(meas))
        for req, meas in zip(requested, measured))
    return ('baseline %.2fs (spread %.2fs), %s'
            % (float(evidence.get('baseline_s', 0.0)),
               float(evidence.get('baseline_spread_s', 0.0)), parts))
