"""스캔 정책: 레이트 리밋, 재시도, 타임아웃."""
import asyncio
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class TimeoutPolicy:
    connect_timeout: float = 3.0
    total_timeout: Optional[float] = None


@dataclass
class RetryPolicy:
    max_retries: int = 2
    retry_delay: float = 0.5


class RateLimiter:
    """초당 N개 작업 제한 (토큰 버킷 스타일)."""

    def __init__(self, rate_per_sec: float = 100.0):
        self.rate = rate_per_sec
        self._interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self._interval:
                await asyncio.sleep(self._interval - elapsed)
            self._last = time.monotonic()
