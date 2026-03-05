"""
SYN Scanner implementation using scapy.

Performs SYN scanning by sending raw SYN packets and analyzing responses.
Requires root/administrator privileges.
"""

import asyncio
import logging
import os
import platform
import time
from typing import List, Optional, Tuple

from .models import HostResult, PortResult, PortState, Protocol, ScanTarget
from .rate_limiter import RetryPolicy, TimeoutPolicy, TokenBucketRateLimiter

logger = logging.getLogger(__name__)

# Scapy import with graceful fallback
try:
    from scapy.all import IP, TCP, RandShort, conf, send, sr1, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - SYN scanner will not work")


class SynScanner:
    """
    SYN scanner using raw packets (requires root/admin privileges).
    
    Sends SYN packets directly and analyzes responses:
    - Open: SYN-ACK received
    - Closed: RST received
    - Filtered: No response (timeout)
    """
    
    def __init__(
        self,
        timeout: float = 5.0,
        concurrency: int = 10,
        rate_limit: Optional[float] = None,
        retry_policy: Optional[RetryPolicy] = None,
        timeout_policy: Optional[TimeoutPolicy] = None,
        verbose: bool = False,
        iface: Optional[str] = None
    ) -> None:
        """
        Initialize the SYN scanner.
        
        Args:
            timeout: Default timeout for responses in seconds
            concurrency: Maximum concurrent scans
            rate_limit: Packets per second (None for unlimited)
            retry_policy: Retry configuration
            timeout_policy: Timeout configuration
            verbose: Enable verbose logging
            iface: Network interface to use (auto-detect if None)
            
        Raises:
            RuntimeError: If scapy is not available
            PermissionError: If insufficient privileges for raw sockets
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is required for SYN scanning. "
                "Install with: pip install scapy"
            )
        
        self._check_privileges()
        
        self.timeout = timeout
        self.concurrency = concurrency
        self.verbose = verbose
        self.iface = iface
        
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
        
        self._progress_callback: Optional[callable] = None
        
        # Configure scapy
        if iface:
            conf.iface = iface
    
    @staticmethod
    def _check_privileges() -> None:
        """
        Check if running with sufficient privileges for raw sockets.
        
        Raises:
            PermissionError: If not running with required privileges
        """
        if platform.system() == "Windows":
            # Windows requires admin
            try:
                import ctypes
                if not ctypes.windll.shell.IsUserAnAdmin():
                    raise PermissionError(
                        "Administrator privileges required for SYN scanning on Windows"
                    )
            except Exception as e:
                if isinstance(e, PermissionError):
                    raise
                logger.warning("Could not verify Windows admin privileges")
        else:
            # Unix-like systems require root
            if os.geteuid() != 0:
                raise PermissionError(
                    "Root privileges required for SYN scanning"
                )
    
    def set_progress_callback(self, callback: callable) -> None:
        """
        Set a callback for progress updates.
        
        Args:
            callback: Callable accepting a progress message
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
        Scan a single port using SYN packet.
        
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
            timeout: Timeout in seconds
            
        Returns:
            PortResult
        """
        last_error: Optional[Exception] = None
        
        for attempt in range(self.retry_policy.max_retries + 1):
            try:
                return await self._perform_syn_scan(ip, port, timeout)
            except Exception as e:
                last_error = e
                
                if attempt < self.retry_policy.max_retries:
                    if self.retry_policy.should_retry(e):
                        delay = self.retry_policy.get_delay(attempt)
                        self._log_progress(
                            f"Retrying SYN scan {ip}:{port} "
                            f"in {delay:.2f}s"
                        )
                        await asyncio.sleep(delay)
        
        error_msg = f"SYN scan error: {str(last_error)}"
        logger.warning(f"{ip}:{port} - {error_msg}")
        
        return PortResult(
            port=port,
            protocol=Protocol.TCP,
            state=PortState.UNKNOWN,
            error=error_msg
        )
    
    async def _perform_syn_scan(
        self,
        ip: str,
        port: int,
        timeout: float
    ) -> PortResult:
        """
        Perform actual SYN scan using raw packets.
        
        Args:
            ip: Target IP address
            port: Port number
            timeout: Timeout in seconds
            
        Returns:
            PortResult with state information
        """
        start_time = time.monotonic()
        
        try:
            # Build SYN packet
            packet = IP(dst=ip) / TCP(
                dport=port,
                sport=RandShort(),
                flags="S"
            )
            
            # Send packet and wait for response
            response = sr1(
                packet,
                timeout=timeout,
                verbose=self.verbose,
                iface=self.iface
            )
            
            elapsed = time.monotonic() - start_time
            rtt_ms = elapsed * 1000
            
            if response is None:
                # No response = filtered
                self._log_progress(f"{ip}:{port} is FILTERED (no response)")
                
                return PortResult(
                    port=port,
                    protocol=Protocol.TCP,
                    state=PortState.FILTERED,
                    rtt_ms=rtt_ms,
                    error="No response to SYN packet"
                )
            
            # Check response flags
            if response[TCP].flags == "SA":  # SYN-ACK
                self._log_progress(f"{ip}:{port} is OPEN (SYN-ACK)")
                
                # Send RST to close connection (polite)
                rst = IP(dst=ip) / TCP(
                    dport=port,
                    sport=response[TCP].dport,
                    seq=response[TCP].ack,
                    flags="R"
                )
                send(rst, verbose=False)
                
                return PortResult(
                    port=port,
                    protocol=Protocol.TCP,
                    state=PortState.OPEN,
                    rtt_ms=rtt_ms
                )
            
            elif response[TCP].flags == "RA" or response[TCP].flags == "R":
                # RST = closed port
                self._log_progress(f"{ip}:{port} is CLOSED (RST)")
                
                return PortResult(
                    port=port,
                    protocol=Protocol.TCP,
                    state=PortState.CLOSED,
                    rtt_ms=rtt_ms
                )
            
            else:
                # Unexpected response
                self._log_progress(
                    f"{ip}:{port} received unexpected flags: "
                    f"{response[TCP].flags}"
                )
                
                return PortResult(
                    port=port,
                    protocol=Protocol.TCP,
                    state=PortState.UNKNOWN,
                    rtt_ms=rtt_ms,
                    error=f"Unexpected TCP flags: {response[TCP].flags}"
                )
        
        except Exception as e:
            elapsed = time.monotonic() - start_time
            rtt_ms = elapsed * 1000
            
            self._log_progress(f"{ip}:{port} SYN scan error: {str(e)}")
            
            return PortResult(
                port=port,
                protocol=Protocol.TCP,
                state=PortState.UNKNOWN,
                rtt_ms=rtt_ms,
                error=str(e)
            )
    
    async def scan_host(
        self,
        target: ScanTarget,
        ports: Optional[List[int]] = None
    ) -> HostResult:
        """
        Scan all ports on a target host using SYN.
        
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
            f"Starting SYN scan of {target.ip} ({len(ports)} ports)"
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
            engine="syn_scan"
        )
        
        open_count = len(result.open_ports)
        closed_count = len(result.closed_ports)
        filtered_count = len(result.filtered_ports)
        
        self._log_progress(
            f"Completed SYN scan of {target.ip}: "
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
        Scan multiple targets using SYN.
        
        Args:
            targets: List of ScanTarget objects
            ports: Ports to scan on all targets
            
        Returns:
            List of HostResult objects
        """
        self._log_progress(
            f"Starting SYN scan of {len(targets)} targets"
        )
        
        tasks = [
            self.scan_host(target, ports)
            for target in targets
        ]
        
        results = await asyncio.gather(*tasks)
        
        total_open = sum(len(r.open_ports) for r in results)
        self._log_progress(
            f"Completed SYN scan of {len(targets)} targets: "
            f"{total_open} open ports found"
        )
        
        return results
    
    @staticmethod
    def compare_with_connect(
        syn_results: List[HostResult],
        connect_results: List[HostResult]
    ) -> List[Tuple[str, int, str, str]]:
        """
        Compare SYN scan results with TCP Connect results.
        
        Identifies discrepancies between the two scanning methods.
        
        Args:
            syn_results: Results from SYN scanning
            connect_results: Results from TCP Connect scanning
            
        Returns:
            List of (ip, port, syn_state, connect_state) tuples
            for ports with different states
        """
        discrepancies: List[Tuple[str, int, str, str]] = []
        
        # Build lookup for connect results
        connect_by_ip = {r.ip: r for r in connect_results}
        
        for syn_result in syn_results:
            if syn_result.ip not in connect_by_ip:
                continue
            
            connect_result = connect_by_ip[syn_result.ip]
            
            # Build port mappings
            syn_ports = {pr.port: pr.state for pr in syn_result.port_results}
            connect_ports = {
                pr.port: pr.state
                for pr in connect_result.port_results
            }
            
            # Find differences
            all_ports = set(syn_ports.keys()) | set(connect_ports.keys())
            
            for port in all_ports:
                syn_state = syn_ports.get(port, PortState.UNKNOWN)
                connect_state = connect_ports.get(port, PortState.UNKNOWN)
                
                if syn_state != connect_state:
                    discrepancies.append((
                        syn_result.ip,
                        port,
                        syn_state.value,
                        connect_state.value
                    ))
        
        return discrepancies
