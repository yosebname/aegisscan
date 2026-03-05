"""
Data models for scan results and configuration.

Provides standardized data structures for representing network scan targets,
port scan results, and scan configurations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from ipaddress import IPv4Network, IPv4Address
from typing import List, Optional, Set, Tuple
import re


class PortState(str, Enum):
    """Enumeration of possible port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class Protocol(str, Enum):
    """Enumeration of common protocols."""
    TCP = "tcp"
    UDP = "udp"


@dataclass
class ScanTarget:
    """
    Represents a target for scanning.
    
    Can be a single IP, hostname, or CIDR network range.
    """
    ip: str
    ports: Optional[List[int]] = None
    hostname: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Validate IP address format."""
        try:
            IPv4Address(self.ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {self.ip}") from e


@dataclass
class PortResult:
    """
    Represents the scan result for a single port.
    """
    port: int
    protocol: Protocol
    state: PortState
    rtt_ms: Optional[float] = None
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    service: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Validate port number range."""
        if not 0 < self.port < 65536:
            raise ValueError(f"Port must be between 1 and 65535, got {self.port}")


@dataclass
class HostResult:
    """
    Represents the aggregated scan results for a single host.
    """
    ip: str
    hostname: Optional[str] = None
    port_results: List[PortResult] = field(default_factory=list)
    scan_duration: float = 0.0
    engine: str = "tcp_connect"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self) -> None:
        """Validate IP address format."""
        try:
            IPv4Address(self.ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {self.ip}") from e
    
    @property
    def open_ports(self) -> List[int]:
        """Return list of open ports."""
        return [pr.port for pr in self.port_results if pr.state == PortState.OPEN]
    
    @property
    def closed_ports(self) -> List[int]:
        """Return list of closed ports."""
        return [pr.port for pr in self.port_results if pr.state == PortState.CLOSED]
    
    @property
    def filtered_ports(self) -> List[int]:
        """Return list of filtered ports."""
        return [pr.port for pr in self.port_results if pr.state == PortState.FILTERED]


@dataclass
class ScanConfig:
    """
    Configuration for a scan operation.
    """
    targets: List[str]
    ports: List[int]
    timeout: float = 5.0
    retries: int = 1
    rate_limit: Optional[float] = None  # requests per second
    concurrency: int = 10
    verbose: bool = False
    dns_lookup: bool = True
    
    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")
        if self.retries < 0:
            raise ValueError("Retries cannot be negative")
        if self.concurrency < 1:
            raise ValueError("Concurrency must be at least 1")
        if self.rate_limit is not None and self.rate_limit <= 0:
            raise ValueError("Rate limit must be positive")


def parse_targets(target_strings: List[str]) -> List[ScanTarget]:
    """
    Parse target strings into ScanTarget objects.
    
    Supports formats:
    - Single IP: "192.168.1.1"
    - CIDR notation: "192.168.1.0/24"
    - Hostname: "example.com" (will resolve to IP)
    
    Args:
        target_strings: List of target specifications
        
    Returns:
        List of ScanTarget objects
        
    Raises:
        ValueError: If target format is invalid
    """
    targets = []
    
    for target_str in target_strings:
        target_str = target_str.strip()
        
        # Check if CIDR notation
        if "/" in target_str:
            try:
                network = IPv4Network(target_str, strict=False)
                for ip in network.hosts():
                    targets.append(ScanTarget(ip=str(ip)))
            except ValueError as e:
                raise ValueError(f"Invalid CIDR notation: {target_str}") from e
        else:
            # Try as IP address or hostname
            try:
                IPv4Address(target_str)
                targets.append(ScanTarget(ip=target_str))
            except ValueError:
                # Treat as hostname
                targets.append(ScanTarget(ip=target_str, hostname=target_str))
    
    return targets


def parse_ports(port_strings: List[str]) -> List[int]:
    """
    Parse port specifications into a list of port numbers.
    
    Supports formats:
    - Single port: "80"
    - Port range: "1-1024"
    - Comma-separated: "22,80,443"
    - Mixed: ["22", "80-443", "3000-3010"]
    
    Args:
        port_strings: List of port specifications
        
    Returns:
        Sorted list of unique port numbers
        
    Raises:
        ValueError: If port specification is invalid
    """
    ports: Set[int] = set()
    
    for port_spec in port_strings:
        port_spec = port_spec.strip()
        
        # Handle comma-separated values
        for part in port_spec.split(","):
            part = part.strip()
            
            # Check if range
            if "-" in part:
                match = re.match(r"^(\d+)-(\d+)$", part)
                if not match:
                    raise ValueError(f"Invalid port range: {part}")
                
                start, end = int(match.group(1)), int(match.group(2))
                
                if not (0 < start <= 65535 and 0 < end <= 65535):
                    raise ValueError(f"Port out of range (1-65535): {part}")
                
                if start > end:
                    raise ValueError(f"Invalid range (start > end): {part}")
                
                ports.update(range(start, end + 1))
            else:
                # Single port
                try:
                    port = int(part)
                    if not (0 < port <= 65535):
                        raise ValueError(f"Port out of range (1-65535): {port}")
                    ports.add(port)
                except ValueError as e:
                    raise ValueError(f"Invalid port specification: {part}") from e
    
    return sorted(list(ports))


def expand_port_ranges(ports: List[int]) -> List[int]:
    """
    Expand a list of ports that may contain ranges.
    
    Args:
        ports: List that may contain range tuples or individual ports
        
    Returns:
        Sorted list of unique individual port numbers
    """
    expanded: Set[int] = set()
    
    for port in ports:
        if isinstance(port, tuple):
            start, end = port
            expanded.update(range(start, end + 1))
        else:
            expanded.add(port)
    
    return sorted(list(expanded))
