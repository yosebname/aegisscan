"""SYN 스캔 (패킷 레벨). 네트워크 레벨 SYN/ACK·RST 기반 상태 판정. 관리자 권한 필요."""
import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .policy import RateLimiter, TimeoutPolicy

logger = logging.getLogger(__name__)

SYN_SCAN_AVAILABLE = False
try:
    from scapy.all import IP, TCP, sr1, conf
    conf.verb = 0
    SYN_SCAN_AVAILABLE = True
except ImportError:
    pass


@dataclass
class SynScanResult:
    host: str
    port: int
    state: str  # open | closed | filtered
    error: Optional[str] = None


@dataclass
class SynScanSummary:
    total_hosts: int = 0
    total_ports_checked: int = 0
    open_count: int = 0
    closed_count: int = 0
    filtered_count: int = 0
    duration_sec: float = 0.0
    results: List[SynScanResult] = None
    permission_hint: Optional[str] = None

    def __post_init__(self):
        if self.results is None:
            self.results = []


def _expand_targets(targets: Iterable[str]) -> Set[str]:
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


def _parse_ports(ports_arg) -> List[int]:
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


def _syn_probe_sync(host: str, port: int, timeout: float) -> Tuple[str, Optional[str]]:
    """동기 SYN 프로브. 스레드 풀에서 실행."""
    if not SYN_SCAN_AVAILABLE:
        return "filtered", "scapy not available"
    try:
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        ans = sr1(pkt, timeout=timeout, verbose=0)
        if ans is None:
            return "filtered", "no response"
        if ans.haslayer(TCP):
            flags = ans.getlayer(TCP).flags
            if flags == 0x12:  # SYN-ACK
                return "open", None
            if flags == 0x14:  # RST
                return "closed", None
        return "filtered", "unexpected response"
    except PermissionError as e:
        return "filtered", f"permission denied: {e}"
    except Exception as e:
        return "filtered", str(e)


async def run_syn_scan(
    targets: Iterable[str],
    ports: List[int] | str,
    timeout: float = 3.0,
    rate_per_sec: Optional[float] = None,
    concurrency: int = 200,
) -> SynScanSummary:
    """SYN 스캔 실행. asyncio + run_in_executor로 블로킹 scapy 호출."""
    loop = asyncio.get_event_loop()
    rate_limiter = RateLimiter(rate_per_sec) if rate_per_sec else None
    hosts = _expand_targets(targets)
    port_list = _parse_ports(ports)

    if not SYN_SCAN_AVAILABLE:
        return SynScanSummary(
            total_hosts=len(hosts),
            total_ports_checked=len(hosts) * len(port_list),
            permission_hint="SYN scan requires 'scapy'. Install: pip install scapy. Run with root/admin for raw sockets.",
        )

    results: List[SynScanResult] = []
    sem = asyncio.Semaphore(concurrency)

    async def probe_one(host: str, port: int) -> SynScanResult:
        if rate_limiter:
            await rate_limiter.acquire()
        async with sem:
            state, err = await loop.run_in_executor(
                None, lambda: _syn_probe_sync(host, port, timeout)
            )
            return SynScanResult(host=host, port=port, state=state, error=err)

    tasks = [probe_one(h, p) for h in hosts for p in port_list]
    start_time = time.perf_counter()
    results = await asyncio.gather(*tasks)
    duration = time.perf_counter() - start_time

    summary = SynScanSummary(
        total_hosts=len(hosts),
        total_ports_checked=len(hosts) * len(port_list),
        duration_sec=duration,
        results=list(results),
    )
    for r in results:
        if r.state == "open":
            summary.open_count += 1
        elif r.state == "closed":
            summary.closed_count += 1
        else:
            summary.filtered_count += 1

    return summary


class SynScanner:
    """SYN 스캔 래퍼."""

    def __init__(
        self,
        timeout: float = 3.0,
        rate_per_sec: Optional[float] = None,
        concurrency: int = 200,
    ):
        self.timeout = timeout
        self.rate_per_sec = rate_per_sec
        self.concurrency = concurrency

    @staticmethod
    def is_available() -> bool:
        return SYN_SCAN_AVAILABLE

    async def scan(
        self,
        targets: Iterable[str],
        ports: List[int] | str,
    ) -> SynScanSummary:
        return await run_syn_scan(
            targets=targets,
            ports=ports,
            timeout=self.timeout,
            rate_per_sec=self.rate_per_sec,
            concurrency=self.concurrency,
        )


def compare_connect_syn(
    connect_results: List["ConnectScanResult"],
    syn_results: List[SynScanResult],
) -> List[Dict]:
    """Connect vs SYN 불일치 리스트. (host, port) 기준 매칭."""
    from .connect_scanner import ConnectScanResult  # noqa: avoid circular import

    syn_by_key = {(r.host, r.port): r for r in syn_results}
    mismatches = []
    for c in connect_results:
        key = (c.host, c.port)
        s = syn_by_key.get(key)
        if s is None:
            continue
        if c.state != s.state:
            mismatches.append({
                "host": c.host,
                "port": c.port,
                "state_connect": c.state,
                "state_syn": s.state,
                "interpretation": "filtered_or_firewall" if s.state == "filtered" and c.state == "open" else "state_mismatch",
            })
    return mismatches
