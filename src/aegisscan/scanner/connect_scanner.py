"""TCP Connect 스캔 (asyncio). 애플리케이션 레벨 연결 기반."""
import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set, Tuple

from .policy import RateLimiter, RetryPolicy, TimeoutPolicy

logger = logging.getLogger(__name__)


@dataclass
class ConnectScanResult:
    host: str
    port: int
    state: str  # open | closed | filtered
    rtt_ms: Optional[float] = None
    error: Optional[str] = None


@dataclass
class ConnectScanSummary:
    total_hosts: int = 0
    total_ports_checked: int = 0
    open_count: int = 0
    closed_count: int = 0
    filtered_count: int = 0
    duration_sec: float = 0.0
    results: List[ConnectScanResult] = field(default_factory=list)


def _expand_targets(targets: Iterable[str]) -> Set[str]:
    """대역(CIDR) 또는 단일 IP를 개별 IP set으로."""
    out: Set[str] = set()
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if "/" in t:
            try:
                for ip in ipaddress.ip_network(t, strict=False).hosts():
                    out.add(str(ip))
            except ValueError:
                out.add(t)
        else:
            try:
                ipaddress.ip_address(t)
                out.add(t)
            except ValueError:
                out.add(t)
    return out


def _parse_ports(ports_arg: Iterable[int] | str) -> List[int]:
    """포트 목록. "1-1024" 또는 "80,443,22" 형태 지원."""
    if isinstance(ports_arg, str):
        result: List[int] = []
        for part in ports_arg.replace(" ", "").split(","):
            if "-" in part:
                a, b = part.split("-", 1)
                result.extend(range(int(a), int(b) + 1))
            else:
                result.append(int(part))
        return sorted(set(result))
    return list(ports_arg)


async def _probe_connect(
    host: str,
    port: int,
    timeout: float,
    retry: RetryPolicy,
    rate_limiter: Optional[RateLimiter] = None,
) -> ConnectScanResult:
    if rate_limiter:
        await rate_limiter.acquire()
    last_error: Optional[str] = None
    rtt_ms: Optional[float] = None
    for attempt in range(retry.max_retries + 1):
        try:
            start = time.perf_counter()
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            rtt_ms = (time.perf_counter() - start) * 1000
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            return ConnectScanResult(host=host, port=port, state="open", rtt_ms=rtt_ms)
        except asyncio.TimeoutError:
            last_error = "timeout"
            if attempt < retry.max_retries:
                await asyncio.sleep(retry.retry_delay)
        except ConnectionRefusedError:
            return ConnectScanResult(host=host, port=port, state="closed", rtt_ms=rtt_ms)
        except OSError as e:
            last_error = str(e)
            if "timed out" in last_error.lower() or "errno 60" in str(e):
                if attempt < retry.max_retries:
                    await asyncio.sleep(retry.retry_delay)
                continue
            return ConnectScanResult(host=host, port=port, state="closed", error=last_error)
    return ConnectScanResult(
        host=host, port=port, state="filtered", rtt_ms=rtt_ms, error=last_error
    )


async def run_connect_scan(
    targets: Iterable[str],
    ports: List[int] | str,
    timeout_policy: Optional[TimeoutPolicy] = None,
    retry_policy: Optional[RetryPolicy] = None,
    rate_per_sec: Optional[float] = None,
    concurrency: int = 500,
) -> ConnectScanSummary:
    timeout_policy = timeout_policy or TimeoutPolicy()
    retry_policy = retry_policy or RetryPolicy()
    rate_limiter = RateLimiter(rate_per_sec) if rate_per_sec else None

    hosts = _expand_targets(targets)
    port_list = _parse_ports(ports)
    tasks: List[Tuple[str, int, asyncio.Task]] = []
    for host in hosts:
        for port in port_list:
            t = asyncio.create_task(
                _probe_connect(
                    host, port,
                    timeout=timeout_policy.connect_timeout,
                    retry=retry_policy,
                    rate_limiter=rate_limiter,
                )
            )
            tasks.append((host, port, t))

    sem = asyncio.Semaphore(concurrency)

    async def bounded(task: asyncio.Task) -> ConnectScanResult:
        async with sem:
            return await task

    start_time = time.perf_counter()
    results_list = await asyncio.gather(*[bounded(t) for _, _, t in tasks])
    duration = time.perf_counter() - start_time

    summary = ConnectScanSummary(
        total_hosts=len(hosts),
        total_ports_checked=len(hosts) * len(port_list),
        duration_sec=duration,
        results=list(results_list),
    )
    for r in results_list:
        if r.state == "open":
            summary.open_count += 1
        elif r.state == "closed":
            summary.closed_count += 1
        else:
            summary.filtered_count += 1

    return summary


class ConnectScanner:
    """Connect 스캔 래퍼."""

    def __init__(
        self,
        timeout: float = 3.0,
        retries: int = 2,
        rate_per_sec: Optional[float] = None,
        concurrency: int = 500,
    ):
        self.timeout_policy = TimeoutPolicy(connect_timeout=timeout)
        self.retry_policy = RetryPolicy(max_retries=retries)
        self.rate_per_sec = rate_per_sec
        self.concurrency = concurrency

    async def scan(
        self,
        targets: Iterable[str],
        ports: List[int] | str,
    ) -> ConnectScanSummary:
        return await run_connect_scan(
            targets=targets,
            ports=ports,
            timeout_policy=self.timeout_policy,
            retry_policy=self.retry_policy,
            rate_per_sec=self.rate_per_sec,
            concurrency=self.concurrency,
        )
