"""
AsyncIO TCP Connect Scanner implementation.

Performs TCP connect scans using asyncio for concurrent port scanning
with rate limiting and retry logic.
"""

import asyncio
import logging
import socket
import time
from typing import Callable, List, Optional

from .models import HostResult, PortResult, PortState, Protocol, ScanTarget
from .rate_limiter import RetryPolicy, TimeoutPolicy, TokenBucketRateLimiter

logger = logging.getLogger(__name__)


class ConnectScanner:
    """
    TCP Connect scanner using asyncio.
    
    Performs complete TCP handshakes to determine port state.
    - Open: Connection successful (SYN-ACK received)
    - Closed: Connection refused (RST received)
    - Filtered: Timeout or no response
    """
    
    def __init__(
        self,
        timeout: float = 5.0,
        concurrency: int = 10,
        rate_limit: Optional[float] = None,
        retry_policy: Optional[RetryPolicy] = None,
        timeout_policy: Optional[TimeoutPolicy] = None,
        verbose: bool = False
    ) -> None:
        """
        Initialize the TCP Connect scanner.
        
        Args:
            timeout: Default timeout for connections in seconds
            concurrency: Maximum concurrent connections
            rate_limit: Operations per second (None for unlimited)
            retry_policy: Retry configuration (uses defaults if None)
            timeout_policy: Timeout configuration (uses defaults if None)
            verbose: Enable verbose logging
        """
        self.timeout = timeout
        self.concurrency = concurrency
        self.verbose = verbose
        
        self.retry_policy = retry_policy or RetryPolicy()
        self.timeout_policy = timeout_policy or TimeoutPolicy(
            connect_timeout=timeout,
            read_timeout=timeout
        )
        
        self.semaphore = asyncio.Semaphore(concurrency)
        self.rate_limiter = (
            TokenBucketRateLimiter(rate=rate_limit)
            if rate_limit
            else None
        )
        
        self._progress_callback: Optional[Callable[[str], None]] = None
        
        if verbose:
            logger.setLevel(logging.DEBUG)
    
    def set_progress_callback(
        self,
        callback: Callable[[str], None]
    ) -> None:
        """
        Set a callback for progress updates.
        
        Args:
            callback: Callable that accepts a progress message string
        """
        self._progress_callback = callback
    
    def _log_progress(self, message: str) -> None:
        """Log progress message and call callback if set."""
        logger.debug(message)
        if self._progress_callback:
            self._progress_callback(message)
    
    async def scan_port(
        self,
        ip: str,
        port: int,
        timeout: Optional[float] = None
    ) -> PortResult:
        """
        Scan a single port on a target IP.
        
        Args:
            ip: Target IP address
            port: Port number to scan
            timeout: Override default timeout
            
        Returns:
            PortResult with scan results
        """
        timeout = timeout or self.timeout_policy.connect_timeout
        
        async with self.semaphore:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            return await self._scan_port_with_retry(ip, port, timeout)
    
    async def _scan_port_with_retry(
        self,
        ip: str,
        port: int,
        timeout: float
    ) -> PortResult:
        """
        Scan a port with retry logic.
        
        Args:
            ip: Target IP address
            port: Port number
            timeout: Connection timeout
            
        Returns:
            PortResult
        """
        last_error: Optional[Exception] = None
        
        for attempt in range(self.retry_policy.max_retries + 1):
            try:
                return await self._perform_connect(ip, port, timeout)
            except Exception as e:
                last_error = e
                
                if attempt < self.retry_policy.max_retries:
                    if self.retry_policy.should_retry(e):
                        delay = self.retry_policy.get_delay(attempt)
                        self._log_progress(
                            f"Retrying {ip}:{port} in {delay:.2f}s "
                            f"(attempt {attempt + 1}/{self.retry_policy.max_retries})"
                        )
                        await asyncio.sleep(delay)
                    else:
                        # Non-retryable error, return immediately
                        break
        
        # All retries failed, return error result
        error_msg = f"Connection error: {str(last_error)}"
        logger.warning(f"{ip}:{port} - {error_msg}")
        
        return PortResult(
            port=port,
            protocol=Protocol.TCP,
            state=PortState.UNKNOWN,
            error=error_msg
        )
    
    async def _perform_connect(
        self,
        ip: str,
        port: int,
        timeout: float
    ) -> PortResult:
        """
        Perform actual TCP connection attempt.
        
        Args:
            ip: Target IP address
            port: Port number
            timeout: Connection timeout
            
        Returns:
            PortResult with state and timing information
        """
        start_time = time.monotonic()
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            
            elapsed = time.monotonic() - start_time
            rtt_ms = elapsed * 1000
            
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            
            self._log_progress(f"{ip}:{port} is OPEN (RTT: {rtt_ms:.2f}ms)")
            
            return PortResult(
                port=port,
                protocol=Protocol.TCP,
                state=PortState.OPEN,
                rtt_ms=rtt_ms
            )
        
        except (asyncio.TimeoutError, socket.timeout):
            elapsed = time.monotonic() - start_time
            rtt_ms = elapsed * 1000
            
            self._log_progress(f"{ip}:{port} is FILTERED (timeout)")
            
            return PortResult(
                port=port,
                protocol=Protocol.TCP,
                state=PortState.FILTERED,
                rtt_ms=rtt_ms,
                error="Connection timeout"
            )
        
        except (
            ConnectionRefusedError,
            asyncio.TimeoutError,
            OSError
        ) as e:
            elapsed = time.monotonic() - start_time
            rtt_ms = elapsed * 1000
            
            # Connection refused indicates closed port
            if isinstance(e, ConnectionRefusedError):
                self._log_progress(f"{ip}:{port} is CLOSED")
                
                return PortResult(
                    port=port,
                    protocol=Protocol.TCP,
                    state=PortState.CLOSED,
                    rtt_ms=rtt_ms
                )
            
            # Other OS errors treated as filtered
            self._log_progress(f"{ip}:{port} is FILTERED ({type(e).__name__})")
            
            return PortResult(
                port=port,
                protocol=Protocol.TCP,
                state=PortState.FILTERED,
                rtt_ms=rtt_ms,
                error=str(e)
            )
    
    async def scan_host(
        self,
        target: ScanTarget,
        ports: Optional[List[int]] = None
    ) -> HostResult:
        """
        Scan all ports on a target host.
        
        Args:
            target: ScanTarget specifying the host
            ports: Ports to scan (uses target.ports if not provided)
            
        Returns:
            HostResult with aggregated scan results
        """
        ports = ports or target.ports or []
        
        if not ports:
            logger.warning(f"No ports specified for {target.ip}")
            return HostResult(ip=target.ip, hostname=target.hostname)
        
        self._log_progress(
            f"Starting scan of {target.ip} ({len(ports)} ports)"
        )
        
        start_time = time.monotonic()
        
        # Create scan tasks for all ports
        tasks = [
            self.scan_port(target.ip, port)
            for port in ports
        ]
        
        # Execute all port scans concurrently
        port_results = await asyncio.gather(*tasks)
        
        scan_duration = time.monotonic() - start_time
        
        result = HostResult(
            ip=target.ip,
            hostname=target.hostname,
            port_results=port_results,
            scan_duration=scan_duration,
            engine="tcp_connect"
        )
        
        open_count = len(result.open_ports)
        closed_count = len(result.closed_ports)
        filtered_count = len(result.filtered_ports)
        
        self._log_progress(
            f"Completed scan of {target.ip}: "
            f"{open_count} open, {closed_count} closed, "
            f"{filtered_count} filtered in {scan_duration:.2f}s"
        )
        
        return result
    
    async def scan_targets(
        self,
        targets: List[ScanTarget],
        ports: Optional[List[int]] = None
    ) -> List[HostResult]:
        """
        Scan multiple targets.
        
        Args:
            targets: List of ScanTarget objects
            ports: Ports to scan on all targets (overrides target.ports)
            
        Returns:
            List of HostResult objects
        """
        self._log_progress(
            f"Starting scan of {len(targets)} targets"
        )
        
        tasks = [
            self.scan_host(target, ports)
            for target in targets
        ]
        
        results = await asyncio.gather(*tasks)
        
        total_open = sum(len(r.open_ports) for r in results)
        self._log_progress(
            f"Completed scan of {len(targets)} targets: "
            f"{total_open} open ports found"
        )
        
        return results
