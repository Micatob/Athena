"""
Athena Per-Engagement Rate Limiter
===================================
Provides rate limiting scoped to individual engagements.

This module ensures that:
1. Each engagement has its own rate limit bucket
2. Rate limits are enforced per-operator
3. Rate limits can be configured per-engagement
4. Rate limit violations are logged for audit
"""

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("athena.rate_limit")


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit bucket."""
    max_requests: int = 100
    window_seconds: int = 60
    burst_size: int = 10
    burst_window: int = 1


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    remaining: int
    reset_at: float
    retry_after: Optional[float] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "remaining": self.remaining,
            "reset_at": self.reset_at,
            "retry_after": self.retry_after,
            "reason": self.reason,
        }


class EngagementRateLimiter:
    """Per-engagement rate limiter with sliding window."""
    
    def __init__(self, default_config: Optional[RateLimitConfig] = None):
        self._default_config = default_config or RateLimitConfig()
        self._buckets: Dict[str, deque] = defaultdict(deque)
        self._configs: Dict[str, RateLimitConfig] = {}
        self._violations: Dict[str, int] = defaultdict(int)
        self._lock = None  # Would use asyncio.Lock in async context
    
    def configure_engagement(
        self,
        engagement_id: str,
        config: RateLimitConfig
    ) -> None:
        """Set rate limit configuration for an engagement."""
        self._configs[engagement_id] = config
    
    def check(
        self,
        engagement_id: str,
        operator: str = "",
        action: str = ""
    ) -> RateLimitResult:
        """Check if a request is allowed under the rate limit.
        
        Args:
            engagement_id: The engagement to check
            operator: The operator making the request
            action: The action being performed
            
        Returns:
            RateLimitResult with allow/deny decision
        """
        config = self._configs.get(engagement_id, self._default_config)
        bucket_key = f"{engagement_id}:{operator}"
        
        now = time.time()
        bucket = self._buckets[bucket_key]
        
        # Remove expired entries
        while bucket and bucket[0] < now - config.window_seconds:
            bucket.popleft()
        
        # Check burst limit
        recent_count = sum(1 for t in bucket if t > now - config.burst_window)
        if recent_count >= config.burst_size:
            self._violations[bucket_key] += 1
            logger.warning(
                f"Rate limit burst exceeded for {bucket_key}: "
                f"{recent_count}/{config.burst_size}"
            )
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_at=now + config.burst_window,
                retry_after=config.burst_window,
                reason=f"Burst limit exceeded: {recent_count}/{config.burst_size}",
            )
        
        # Check window limit
        if len(bucket) >= config.max_requests:
            oldest = bucket[0]
            reset_at = oldest + config.window_seconds
            self._violations[bucket_key] += 1
            logger.warning(
                f"Rate limit exceeded for {bucket_key}: "
                f"{len(bucket)}/{config.max_requests}"
            )
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_at=reset_at,
                retry_after=reset_at - now,
                reason=f"Window limit exceeded: {len(bucket)}/{config.max_requests}",
            )
        
        # Allow request
        bucket.append(now)
        remaining = config.max_requests - len(bucket)
        
        return RateLimitResult(
            allowed=True,
            remaining=remaining,
            reset_at=now + config.window_seconds,
        )
    
    def get_violations(self, engagement_id: str = "") -> Dict[str, int]:
        """Get rate limit violations for an engagement or all."""
        if engagement_id:
            return {
                k: v for k, v in self._violations.items()
                if k.startswith(engagement_id)
            }
        return dict(self._violations)
    
    def reset(self, engagement_id: str = "") -> None:
        """Reset rate limit state for an engagement or all."""
        if engagement_id:
            keys_to_remove = [
                k for k in self._buckets
                if k.startswith(engagement_id)
            ]
            for key in keys_to_remove:
                del self._buckets[key]
                self._violations.pop(key, None)
        else:
            self._buckets.clear()
            self._violations.clear()
    
    def get_usage(self, engagement_id: str) -> Dict[str, Any]:
        """Get current usage statistics for an engagement."""
        config = self._configs.get(engagement_id, self._default_config)
        now = time.time()
        
        total_requests = 0
        operators = set()
        
        for key, bucket in self._buckets.items():
            if key.startswith(engagement_id):
                # Remove expired entries
                while bucket and bucket[0] < now - config.window_seconds:
                    bucket.popleft()
                total_requests += len(bucket)
                operator = key.split(":", 1)[1] if ":" in key else "unknown"
                operators.add(operator)
        
        return {
            "engagement_id": engagement_id,
            "total_requests": total_requests,
            "max_requests": config.max_requests,
            "window_seconds": config.window_seconds,
            "unique_operators": len(operators),
            "operators": list(operators),
            "utilization": total_requests / max(config.max_requests, 1),
        }


# ============================================================================
# FACTORY FUNCTION
# ============================================================================


def create_rate_limiter(
    default_config: Optional[RateLimitConfig] = None
) -> EngagementRateLimiter:
    """Create a rate limiter instance."""
    return EngagementRateLimiter(default_config=default_config)
