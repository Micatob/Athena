"""
tests/test_rate_limiter.py – Per-Engagement Rate Limiter Tests
==============================================================
Covers:
  * Basic rate limiting
  * Burst limiting
  * Per-engagement configuration
  * Violation tracking
  * Usage statistics
"""

import time
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from modules.rate_limiter import (
    EngagementRateLimiter,
    RateLimitConfig,
    RateLimitResult,
)


@pytest.fixture()
def limiter():
    return EngagementRateLimiter()


@pytest.fixture()
def custom_config():
    return RateLimitConfig(
        max_requests=10,
        window_seconds=60,
        burst_size=3,
        burst_window=1,
    )


class TestRateLimitConfig:
    def test_default_config(self):
        config = RateLimitConfig()
        assert config.max_requests == 100
        assert config.window_seconds == 60

    def test_custom_config(self):
        config = RateLimitConfig(max_requests=50, window_seconds=30)
        assert config.max_requests == 50
        assert config.window_seconds == 30


class TestBasicRateLimiting:
    def test_allows_under_limit(self, limiter):
        result = limiter.check("eng1", operator="user1")
        assert result.allowed
        assert result.remaining >= 0

    def test_denies_over_limit(self, limiter):
        config = RateLimitConfig(max_requests=5, window_seconds=60)
        limiter.configure_engagement("eng1", config)
        
        # Make 5 requests (at limit)
        for _ in range(5):
            limiter.check("eng1", operator="user1")
        
        # 6th request should be denied
        result = limiter.check("eng1", operator="user1")
        assert not result.allowed
        assert result.remaining == 0

    def test_remaining_count(self, limiter):
        config = RateLimitConfig(max_requests=10, window_seconds=60)
        limiter.configure_engagement("eng1", config)
        
        limiter.check("eng1", operator="user1")
        result = limiter.check("eng1", operator="user1")
        assert result.remaining == 8  # 10 - 2


class TestBurstLimiting:
    def test_allows_under_burst(self, limiter):
        config = RateLimitConfig(max_requests=100, window_seconds=60, burst_size=5, burst_window=1)
        limiter.configure_engagement("eng1", config)
        
        # Make 4 burst requests (under limit of 5)
        for _ in range(4):
            result = limiter.check("eng1", operator="user1")
            assert result.allowed

    def test_denies_over_burst(self, limiter):
        config = RateLimitConfig(max_requests=100, window_seconds=60, burst_size=3, burst_window=1)
        limiter.configure_engagement("eng1", config)
        
        # Make 3 burst requests (at limit)
        for _ in range(3):
            limiter.check("eng1", operator="user1")
        
        # 4th request in burst window should be denied
        result = limiter.check("eng1", operator="user1")
        assert not result.allowed
        assert "Burst limit" in result.reason


class TestPerEngagementConfig:
    def test_different_limits_per_engagement(self, limiter):
        config1 = RateLimitConfig(max_requests=10, window_seconds=60)
        config2 = RateLimitConfig(max_requests=20, window_seconds=60)
        
        limiter.configure_engagement("eng1", config1)
        limiter.configure_engagement("eng2", config2)
        
        # eng1 should allow 10 requests
        for _ in range(10):
            result = limiter.check("eng1", operator="user1")
            assert result.allowed
        
        # eng1 11th should be denied
        result = limiter.check("eng1", operator="user1")
        assert not result.allowed
        
        # eng2 should still allow requests
        result = limiter.check("eng2", operator="user1")
        assert result.allowed


class TestViolationTracking:
    def test_tracks_violations(self, limiter):
        config = RateLimitConfig(max_requests=2, window_seconds=60)
        limiter.configure_engagement("eng1", config)
        
        # Make 2 requests (at limit)
        for _ in range(2):
            limiter.check("eng1", operator="user1")
        
        # 3rd request should be denied and tracked
        limiter.check("eng1", operator="user1")
        
        violations = limiter.get_violations("eng1")
        assert len(violations) >= 1

    def test_violations_per_engagement(self, limiter):
        config = RateLimitConfig(max_requests=1, window_seconds=60)
        limiter.configure_engagement("eng1", config)
        limiter.configure_engagement("eng2", config)
        
        # Trigger violation on eng1
        limiter.check("eng1", operator="user1")
        limiter.check("eng1", operator="user1")
        
        # eng2 violations should be empty
        violations = limiter.get_violations("eng2")
        assert len(violations) == 0


class TestUsageStatistics:
    def test_usage_stats(self, limiter):
        config = RateLimitConfig(max_requests=100, window_seconds=60)
        limiter.configure_engagement("eng1", config)
        
        # Make some requests
        for _ in range(5):
            limiter.check("eng1", operator="user1")
        
        usage = limiter.get_usage("eng1")
        assert usage["engagement_id"] == "eng1"
        assert usage["total_requests"] == 5
        assert usage["max_requests"] == 100
        assert "user1" in usage["operators"]

    def test_usage_multiple_operators(self, limiter):
        config = RateLimitConfig(max_requests=100, window_seconds=60)
        limiter.configure_engagement("eng1", config)
        
        limiter.check("eng1", operator="user1")
        limiter.check("eng1", operator="user2")
        
        usage = limiter.get_usage("eng1")
        assert usage["unique_operators"] == 2


class TestReset:
    def test_reset_engagement(self, limiter):
        config = RateLimitConfig(max_requests=10, window_seconds=60)
        limiter.configure_engagement("eng1", config)
        
        # Make some requests
        for _ in range(5):
            limiter.check("eng1", operator="user1")
        
        # Reset
        limiter.reset("eng1")
        
        # Usage should be zero
        usage = limiter.get_usage("eng1")
        assert usage["total_requests"] == 0

    def test_reset_all(self, limiter):
        config = RateLimitConfig(max_requests=10, window_seconds=60)
        limiter.configure_engagement("eng1", config)
        limiter.configure_engagement("eng2", config)
        
        # Make requests on both
        for _ in range(3):
            limiter.check("eng1", operator="user1")
            limiter.check("eng2", operator="user1")
        
        # Reset all
        limiter.reset()
        
        # Both should be zero
        usage1 = limiter.get_usage("eng1")
        usage2 = limiter.get_usage("eng2")
        assert usage1["total_requests"] == 0
        assert usage2["total_requests"] == 0


class TestRateLimitResult:
    def test_to_dict(self):
        result = RateLimitResult(
            allowed=True,
            remaining=5,
            reset_at=1000.0,
        )
        data = result.to_dict()
        assert data["allowed"] is True
        assert data["remaining"] == 5

    def test_denied_result(self):
        result = RateLimitResult(
            allowed=False,
            remaining=0,
            reset_at=1000.0,
            retry_after=30.0,
            reason="Limit exceeded",
        )
        data = result.to_dict()
        assert data["allowed"] is False
        assert data["retry_after"] == 30.0
