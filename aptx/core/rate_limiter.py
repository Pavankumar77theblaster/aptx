"""
APT-X Rate Limiter
==================

Rate limiting implementation for controlling request frequency
to prevent overwhelming targets and maintain stealth.
"""

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass
from threading import Lock
from typing import Dict, Optional, Callable, Any
from functools import wraps

from aptx.core.exceptions import RateLimitError
from aptx.core.logger import get_logger


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    requests_per_second: float = 10.0
    burst_size: int = 20
    per_target_limit: Optional[float] = None
    cooldown_multiplier: float = 1.5
    max_cooldown: float = 60.0


class TokenBucket:
    """
    Token bucket algorithm implementation for rate limiting.

    Allows burst traffic while enforcing average rate limits.
    """

    def __init__(
        self,
        rate: float,
        capacity: int,
        initial_tokens: Optional[int] = None
    ):
        """
        Initialize token bucket.

        Args:
            rate: Token refill rate per second
            capacity: Maximum bucket capacity (burst size)
            initial_tokens: Initial token count (defaults to capacity)
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = initial_tokens if initial_tokens is not None else capacity
        self.last_update = time.monotonic()
        self._lock = Lock()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now

    def acquire(self, tokens: int = 1) -> bool:
        """
        Try to acquire tokens.

        Args:
            tokens: Number of tokens to acquire

        Returns:
            True if tokens were acquired, False otherwise
        """
        with self._lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def wait_time(self, tokens: int = 1) -> float:
        """
        Calculate wait time for tokens to become available.

        Args:
            tokens: Number of tokens needed

        Returns:
            Wait time in seconds
        """
        with self._lock:
            self._refill()
            if self.tokens >= tokens:
                return 0.0
            needed = tokens - self.tokens
            return needed / self.rate

    async def acquire_async(self, tokens: int = 1) -> None:
        """
        Asynchronously wait and acquire tokens.

        Args:
            tokens: Number of tokens to acquire
        """
        while True:
            if self.acquire(tokens):
                return
            wait = self.wait_time(tokens)
            if wait > 0:
                await asyncio.sleep(wait)


class SlidingWindowCounter:
    """
    Sliding window rate limiter for precise rate limiting.

    Tracks requests in a sliding time window for accurate rate enforcement.
    """

    def __init__(self, window_size: float, max_requests: int):
        """
        Initialize sliding window counter.

        Args:
            window_size: Window size in seconds
            max_requests: Maximum requests allowed in window
        """
        self.window_size = window_size
        self.max_requests = max_requests
        self.requests: list = []
        self._lock = Lock()

    def _cleanup(self, now: float) -> None:
        """Remove expired entries from window."""
        cutoff = now - self.window_size
        self.requests = [t for t in self.requests if t > cutoff]

    def allow(self) -> bool:
        """
        Check if a request is allowed.

        Returns:
            True if request is allowed
        """
        now = time.monotonic()
        with self._lock:
            self._cleanup(now)
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            return False

    def wait_time(self) -> float:
        """Calculate wait time until next request is allowed."""
        now = time.monotonic()
        with self._lock:
            self._cleanup(now)
            if len(self.requests) < self.max_requests:
                return 0.0
            oldest = min(self.requests)
            return max(0, (oldest + self.window_size) - now)


class RateLimiter:
    """
    Rate limiter for APT-X framework.

    Supports global and per-target rate limiting with configurable
    burst handling and automatic cooldown.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        """
        Initialize rate limiter.

        Args:
            config: Rate limit configuration
        """
        self.config = config or RateLimitConfig()
        self.logger = get_logger().get_child("ratelimit")

        # Global rate limiter
        self._global_bucket = TokenBucket(
            rate=self.config.requests_per_second,
            capacity=self.config.burst_size
        )

        # Per-target rate limiters
        self._target_buckets: Dict[str, TokenBucket] = {}
        self._target_lock = Lock()

        # Cooldown tracking
        self._cooldowns: Dict[str, float] = defaultdict(float)
        self._consecutive_blocks: Dict[str, int] = defaultdict(int)

        # Statistics
        self._stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "total_wait_time": 0.0,
        }

    def _get_target_bucket(self, target: str) -> TokenBucket:
        """Get or create a token bucket for a target."""
        with self._target_lock:
            if target not in self._target_buckets:
                rate = self.config.per_target_limit or self.config.requests_per_second
                self._target_buckets[target] = TokenBucket(
                    rate=rate,
                    capacity=max(1, int(rate * 2))
                )
            return self._target_buckets[target]

    def _check_cooldown(self, target: str) -> float:
        """Check if target is in cooldown period."""
        cooldown_end = self._cooldowns.get(target, 0)
        now = time.monotonic()
        if cooldown_end > now:
            return cooldown_end - now
        return 0.0

    def _apply_cooldown(self, target: str) -> None:
        """Apply cooldown to a target after being blocked."""
        self._consecutive_blocks[target] += 1
        cooldown = min(
            self.config.cooldown_multiplier ** self._consecutive_blocks[target],
            self.config.max_cooldown
        )
        self._cooldowns[target] = time.monotonic() + cooldown
        self.logger.debug(f"Applied {cooldown:.1f}s cooldown to {target}")

    def _reset_cooldown(self, target: str) -> None:
        """Reset cooldown for a target after successful request."""
        self._consecutive_blocks[target] = 0
        if target in self._cooldowns:
            del self._cooldowns[target]

    def acquire(
        self,
        target: Optional[str] = None,
        tokens: int = 1,
        blocking: bool = True,
        timeout: Optional[float] = None
    ) -> bool:
        """
        Acquire rate limit tokens.

        Args:
            target: Optional target for per-target limiting
            tokens: Number of tokens to acquire
            blocking: Wait for tokens if not available
            timeout: Maximum wait time (None for unlimited)

        Returns:
            True if tokens were acquired

        Raises:
            RateLimitError: If blocking is False and limit exceeded
        """
        self._stats["total_requests"] += 1

        # Check target cooldown
        if target:
            cooldown = self._check_cooldown(target)
            if cooldown > 0:
                if not blocking:
                    raise RateLimitError(
                        target=target or "global",
                        limit=int(self.config.requests_per_second),
                        window=1
                    )
                self.logger.debug(f"Waiting {cooldown:.1f}s for cooldown on {target}")
                time.sleep(cooldown)
                self._stats["total_wait_time"] += cooldown

        start = time.monotonic()

        # Try global bucket first
        if not self._global_bucket.acquire(tokens):
            if not blocking:
                self._stats["blocked_requests"] += 1
                raise RateLimitError(
                    target=target or "global",
                    limit=int(self.config.requests_per_second),
                    window=1
                )

            # Wait for global bucket
            wait = self._global_bucket.wait_time(tokens)
            if timeout and wait > timeout:
                self._stats["blocked_requests"] += 1
                return False

            time.sleep(wait)
            self._global_bucket.acquire(tokens)

        # Try target bucket if specified
        if target:
            target_bucket = self._get_target_bucket(target)
            if not target_bucket.acquire(tokens):
                if not blocking:
                    self._apply_cooldown(target)
                    self._stats["blocked_requests"] += 1
                    raise RateLimitError(
                        target=target,
                        limit=int(self.config.per_target_limit or self.config.requests_per_second),
                        window=1
                    )

                wait = target_bucket.wait_time(tokens)
                if timeout:
                    elapsed = time.monotonic() - start
                    if wait > (timeout - elapsed):
                        self._stats["blocked_requests"] += 1
                        return False

                time.sleep(wait)
                target_bucket.acquire(tokens)

            self._reset_cooldown(target)

        elapsed = time.monotonic() - start
        self._stats["total_wait_time"] += elapsed
        return True

    async def acquire_async(
        self,
        target: Optional[str] = None,
        tokens: int = 1,
        timeout: Optional[float] = None
    ) -> bool:
        """
        Asynchronously acquire rate limit tokens.

        Args:
            target: Optional target for per-target limiting
            tokens: Number of tokens to acquire
            timeout: Maximum wait time

        Returns:
            True if tokens were acquired
        """
        self._stats["total_requests"] += 1

        # Check target cooldown
        if target:
            cooldown = self._check_cooldown(target)
            if cooldown > 0:
                self.logger.debug(f"Async waiting {cooldown:.1f}s for cooldown on {target}")
                await asyncio.sleep(cooldown)
                self._stats["total_wait_time"] += cooldown

        start = time.monotonic()

        # Global bucket
        await self._global_bucket.acquire_async(tokens)

        # Target bucket
        if target:
            target_bucket = self._get_target_bucket(target)
            await target_bucket.acquire_async(tokens)
            self._reset_cooldown(target)

        elapsed = time.monotonic() - start
        self._stats["total_wait_time"] += elapsed
        return True

    def set_rate(
        self,
        requests_per_second: float,
        target: Optional[str] = None
    ) -> None:
        """
        Update rate limit.

        Args:
            requests_per_second: New rate limit
            target: Target to update (None for global)
        """
        if target:
            bucket = self._get_target_bucket(target)
            bucket.rate = requests_per_second
            bucket.capacity = max(1, int(requests_per_second * 2))
        else:
            self._global_bucket.rate = requests_per_second
            self._global_bucket.capacity = max(1, int(requests_per_second * 2))
            self.config.requests_per_second = requests_per_second

        self.logger.info(
            f"Updated rate limit to {requests_per_second}/s"
            + (f" for {target}" if target else " (global)")
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        return {
            **self._stats,
            "current_rate": self.config.requests_per_second,
            "burst_size": self.config.burst_size,
            "active_targets": len(self._target_buckets),
            "targets_in_cooldown": sum(
                1 for t, end in self._cooldowns.items()
                if end > time.monotonic()
            ),
        }

    def reset_stats(self) -> None:
        """Reset statistics."""
        self._stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "total_wait_time": 0.0,
        }

    def clear_target(self, target: str) -> None:
        """Clear rate limit state for a target."""
        with self._target_lock:
            if target in self._target_buckets:
                del self._target_buckets[target]
        self._reset_cooldown(target)


def rate_limited(
    limiter: RateLimiter,
    target_arg: Optional[str] = None,
    tokens: int = 1
) -> Callable:
    """
    Decorator for rate-limited functions.

    Args:
        limiter: RateLimiter instance
        target_arg: Name of argument containing target (for per-target limiting)
        tokens: Number of tokens per call

    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            target = None
            if target_arg:
                # Try to get target from kwargs or args
                if target_arg in kwargs:
                    target = kwargs[target_arg]
                else:
                    # Get from function signature
                    import inspect
                    sig = inspect.signature(func)
                    params = list(sig.parameters.keys())
                    if target_arg in params:
                        idx = params.index(target_arg)
                        if idx < len(args):
                            target = args[idx]

            limiter.acquire(target=target, tokens=tokens, blocking=True)
            return func(*args, **kwargs)

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            target = None
            if target_arg:
                if target_arg in kwargs:
                    target = kwargs[target_arg]

            await limiter.acquire_async(target=target, tokens=tokens)
            return await func(*args, **kwargs)

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator
