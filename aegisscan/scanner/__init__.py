"""
AegisScan scanner module.

Provides network scanning capabilities including TCP Connect scanning
and SYN scanning with support for rate limiting, retries, and concurrent operations.

Main exports:
- ConnectScanner: TCP Connect-based port scanner
- SynScanner: SYN packet-based port scanner
- Models: ScanTarget, HostResult, PortResult, ScanConfig
- Utilities: parse_targets, parse_ports
"""

from .connect_scanner import ConnectScanner
from .models import (
    HostResult,
    PortResult,
    PortState,
    Protocol,
    ScanConfig,
    ScanTarget,
    parse_ports,
    parse_targets,
)
from .rate_limiter import (
    AdaptiveRateLimiter,
    RetryPolicy,
    TimeoutPolicy,
    TokenBucketRateLimiter,
)
from .syn_scanner import SynScanner

__all__ = [
    # Scanners
    "ConnectScanner",
    "SynScanner",
    # Data models
    "ScanTarget",
    "HostResult",
    "PortResult",
    "ScanConfig",
    "PortState",
    "Protocol",
    # Parsing utilities
    "parse_targets",
    "parse_ports",
    # Rate limiting
    "TokenBucketRateLimiter",
    "AdaptiveRateLimiter",
    "RetryPolicy",
    "TimeoutPolicy",
]

__version__ = "0.1.0"
