"""
Rate limiting and retry policies for scanner operations.

Implements token bucket rate limiting and configurable retry strategies
with exponential backoff support.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set, Type


@dataclass
class RetryPolicy:
    """
    Configuration for retry behavior on failed scan operations.
    """
    max_retries: int = 3
    backoff_factor: float = 2.0
    initial_delay: float = 0.1
    max_delay: float = 10.0
    retryable_errors: Set[Type[Exception]] = field(
        default_factory=lambda: {
            TimeoutError,
            ConnectionError,
            OSError,
        }
    )
    
    def __post_init__(self) -> None:
        """Validate retry policy parameters."""
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if self.backoff_factor < 1.0:
            raise ValueError("backoff_factor must be >= 1.0")
        if self.initial_delay <= 0:
            raise ValueError("initial_delay must be positive")
        if self.max_delay <= 0:
            raise ValueError("max_delay must be positive")
    
    def get_delay(self, attempt: int) -> float:
        """
        Calculate delay for retry attempt using exponential backoff.
        
        Args:
            attempt: Zero-indexed attempt number
            
        Returns:
            Delay in seconds
        """
        delay = self.initial_delay * (self.backoff_factor ** attempt)
        return min(delay, self.max_delay)
    
    def should_retry(self, error: Exception) -> bool:
        """
        Determine if an error is retryable.
        
        Args:
            error: The exception that occurred
            
        Returns:
            True if the error should trigger a retry
        """
        return any(isinstance(error, err_type) for err_type in self.retryable_errors)


@dataclass
class TimeoutPolicy:
    """
    Configuration for timeout behavior in scanner operations.
    """
    connect_timeout: float = 5.0
    read_timeout: float = 5.0
    overall_timeout: Optional[float] = None
    
    def __post_init__(self) -> None:
        """Validate timeout policy parameters."""
        if self.connect_timeout <= 0:
            raise ValueError("connect_timeout must be positive")
        if self.read_timeout <= 0:
            raise ValueError("read_timeout must be positive")
        if self.overall_timeout is not None and self.overall_timeout <= 0:
            raise ValueError("overall_timeout must be positive or None")


class TokenBucketRateLimiter:
    """
    Asynchronous token bucket rate limiter.
    
    Implements a token bucket algorithm to control the rate of operations.
    Tokens are added at a specified rate and consumed when operations occur.
    Burst capacity allows temporary exceeding of the rate limit.
    """
    
    def __init__(
        self,
        rate: float,
        burst: Optional[float] = None,
        start_tokens: Optional[float] = None
    ) -> None:
        """
        Initialize the rate limiter.
        
        Args:
            rate: Number of operations allowed per second
            burst: Maximum tokens that can accumulate (default: rate)
            start_tokens: Initial number of tokens (default: burst value)
            
        Raises:
            ValueError: If rate is not positive
        """
        if rate <= 0:
            raise ValueError("Rate must be positive")
        
        self.rate = rate
        self.burst = burst or rate
        self.max_tokens = max(self.burst, rate)
        self.tokens = float(start_tokens or self.max_tokens)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: float = 1.0) -> float:
        """
        Acquire tokens from the bucket, waiting if necessary.
        
        This method will block until the requested number of tokens
        are available in the bucket.
        
        Args:
            tokens: Number of tokens to acquire (default: 1)
            
        Returns:
            Time spent waiting in seconds
            
        Raises:
            ValueError: If tokens is not positive
        """
        if tokens <= 0:
            raise ValueError("Tokens to acquire must be positive")
        
        start_time = time.monotonic()
        
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.tokens = min(
                    self.max_tokens,
                    self.tokens + elapsed * self.rate
                )
                self.last_update = now
                
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return 0.0
                
                # Calculate time to wait for tokens
                tokens_needed = tokens - self.tokens
                wait_time = tokens_needed / self.rate
                
                # Release lock while waiting
                await asyncio.sleep(wait_time)
    
    async def try_acquire(self, tokens: float = 1.0) -> bool:
        """
        Try to acquire tokens without waiting.
        
        Args:
            tokens: Number of tokens to acquire
            
        Returns:
            True if tokens were acquired, False otherwise
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(
                self.max_tokens,
                self.tokens + elapsed * self.rate
            )
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    async def reset(self) -> None:
        """Reset the rate limiter to full capacity."""
        async with self._lock:
            self.tokens = self.max_tokens
            self.last_update = time.monotonic()
    
    @property
    async def get_available_tokens(self) -> float:
        """Get the current number of available tokens."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(
                self.max_tokens,
                self.tokens + elapsed * self.rate
            )
            self.last_update = now
            return self.tokens


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that adjusts based on response codes.
    
    Decreases rate on errors (429, 503) and slowly increases on success.
    """
    
    def __init__(
        self,
        initial_rate: float,
        min_rate: float = 0.1,
        max_rate: float = 1000.0
    ) -> None:
        """
        Initialize the adaptive rate limiter.
        
        Args:
            initial_rate: Starting operations per second
            min_rate: Minimum rate floor
            max_rate: Maximum rate ceiling
        """
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.current_rate = initial_rate
        self.limiter = TokenBucketRateLimiter(rate=initial_rate)
        self._error_count = 0
        self._success_count = 0
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: float = 1.0) -> float:
        """Acquire tokens at current rate."""
        return await self.limiter.acquire(tokens)
    
    async def record_success(self) -> None:
        """Record a successful operation."""
        async with self._lock:
            self._success_count += 1
            self._error_count = max(0, self._error_count - 1)
            
            # Slowly increase rate on success
            if self._success_count >= 10:
                new_rate = min(
                    self.max_rate,
                    self.current_rate * 1.05
                )
                await self._update_rate(new_rate)
                self._success_count = 0
    
    async def record_error(self, status_code: Optional[int] = None) -> None:
        """Record a failed operation and adjust rate accordingly."""
        async with self._lock:
            self._error_count += 1
            self._success_count = 0
            
            # Decrease rate on errors
            if status_code in (429, 503) or self._error_count >= 3:
                new_rate = max(
                    self.min_rate,
                    self.current_rate * 0.5
                )
                await self._update_rate(new_rate)
                self._error_count = 0
    
    async def _update_rate(self, new_rate: float) -> None:
        """Update the limiter with a new rate."""
        self.current_rate = new_rate
        self.limiter = TokenBucketRateLimiter(rate=new_rate)
    
    @property
    def rate(self) -> float:
        """Get current rate."""
        return self.current_rate
