# AegisScan Scanner Core Modules Implementation

## Overview
Production-quality Python scanner core modules for the AegisScan project, built to 3-year developer standards with comprehensive type hints, docstrings, and proper async patterns.

## File Structure

```
aegisscan/
├── scanner/
│   ├── __init__.py              # Module exports
│   ├── models.py                # Data classes and parsing utilities
│   ├── rate_limiter.py          # Rate limiting and retry policies
│   ├── connect_scanner.py       # TCP Connect scanner implementation
│   └── syn_scanner.py           # SYN scanner implementation (requires root)
└── config.py                    # Application configuration management
```

## Modules

### 1. `aegisscan/scanner/models.py`
Data classes for network scan results and configuration.

**Classes:**
- `PortState` - Enum: OPEN, CLOSED, FILTERED, UNKNOWN
- `Protocol` - Enum: TCP, UDP
- `ScanTarget` - Target specification (IP, ports, hostname)
- `PortResult` - Single port scan result with state, RTT, error handling
- `HostResult` - Aggregated host results with filtering utilities
- `ScanConfig` - Scan configuration with validation

**Utilities:**
- `parse_targets()` - Parse target strings (IPs, CIDR notation, hostnames)
- `parse_ports()` - Parse port specifications (ranges, comma-separated)
- `expand_port_ranges()` - Expand port range tuples

**Features:**
- Full IP address validation
- CIDR network expansion (e.g., "192.168.1.0/24" → 254 hosts)
- Port range parsing (e.g., "1-1024" → individual ports)
- Dataclass field validation on initialization
- Property accessors for filtered port lists (open_ports, closed_ports, filtered_ports)

### 2. `aegisscan/scanner/rate_limiter.py`
Asynchronous rate limiting and retry mechanisms.

**Classes:**
- `RetryPolicy` - Configurable retry with exponential backoff
  - max_retries, backoff_factor, initial_delay, max_delay
  - Retryable error types (TimeoutError, ConnectionError, OSError)
  - Method `get_delay(attempt)` for backoff calculation
  - Method `should_retry(error)` for error classification

- `TimeoutPolicy` - Timeout configuration
  - connect_timeout, read_timeout, overall_timeout
  - All fields configurable and validated

- `TokenBucketRateLimiter` - Async rate limiter
  - Token bucket algorithm with burst support
  - Async `acquire(tokens)` - blocks until tokens available
  - Async `try_acquire(tokens)` - non-blocking attempt
  - Async `reset()` - return to full capacity
  - Thread-safe via asyncio.Lock

- `AdaptiveRateLimiter` - Self-adjusting rate limiter
  - Decreases rate on errors (429, 503)
  - Increases rate on successful operations
  - Methods: acquire(), record_success(), record_error()

**Features:**
- Proper async/await patterns
- Token bucket prevents request bursts
- Exponential backoff with configurable floor/ceiling
- Detailed error tracking for decision making

### 3. `aegisscan/scanner/connect_scanner.py`
TCP Connect port scanner using asyncio.

**Class: ConnectScanner**
- Full TCP handshakes for accurate state determination
- Concurrent scanning with semaphore-based limiting
- Optional rate limiting integration
- Automatic retry with backoff

**Key Methods:**
- `__init__()` - Initialize with timeout, concurrency, rate limiting
- `set_progress_callback(callback)` - Register progress updates
- `scan_port(ip, port, timeout)` - Scan single port (async)
- `scan_host(target, ports)` - Scan all ports on a host (async)
- `scan_targets(targets, ports)` - Scan multiple targets (async)

**State Detection:**
- OPEN: Connection successful (full TCP handshake)
- CLOSED: Connection refused (immediate RST)
- FILTERED: Timeout or no response
- UNKNOWN: Unclassified errors

**Features:**
- Detailed RTT (Round Trip Time) measurement in milliseconds
- Graceful connection cleanup
- Comprehensive logging throughout
- Progress callbacks for UI integration
- Retry policy with exponential backoff
- Semaphore for concurrency control
- Clean error messages for debugging

**Example:**
```python
scanner = ConnectScanner(timeout=5.0, concurrency=20, rate_limit=10.0)
results = await scanner.scan_targets(targets, ports=[22, 80, 443])
```

### 4. `aegisscan/scanner/syn_scanner.py`
SYN scanner using raw packets (requires root/admin).

**Class: SynScanner**
- Sends raw SYN packets
- Analyzes response flags (SYN-ACK, RST)
- Graceful RST sending to close connections
- Privilege checking on initialization
- Fallback error handling if scapy unavailable

**Key Methods:**
- Same interface as ConnectScanner for consistency
- `scan_port()`, `scan_host()`, `scan_targets()`
- `compare_with_connect()` - Identify discrepancies vs TCP Connect

**Requirements:**
- Root/Administrator privileges
- Scapy library (`pip install scapy`)
- Raw socket capabilities

**Features:**
- Faster than TCP Connect (no full handshake)
- Network interface selection support
- Privilege validation with helpful error messages
- Graceful degradation if scapy unavailable
- Comprehensive discrepancy reporting

**Privilege Checking:**
- Windows: Administrator flag validation
- Linux/Unix: UID == 0 (root)
- Raises PermissionError with helpful message

### 5. `aegisscan/config.py`
Global application configuration management.

**Dataclasses:**
- `ScanDefaults` - Scan operation defaults
  - timeout, retries, concurrency, rate_limit
  - Default ports: [22, 80, 443, 3306, 5432, 6379, 8080, 8443]

- `DatabaseConfig` - Database settings
  - engine (sqlite/postgresql)
  - Connection pool configuration
  - Debug mode

- `LoggingConfig` - Logging configuration
  - Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  - Custom format strings
  - File and console output

- `APIConfig` - API server settings
  - Host, port, worker count
  - Request timeout

- `CredentialConfig` - Secrets management
  - SSH key paths
  - API key storage paths
  - Environment variable prefix

- `AppConfig` - Main configuration aggregator
  - All sections above
  - Validation with error reporting
  - YAML serialization/deserialization
  - Environment variable support

**Loading Methods:**
1. `from_yaml(path)` - Load from YAML file
2. `from_env(prefix)` - Load from environment variables
3. `AppConfig()` - Use defaults
4. `from_dict(dict)` - Programmatic creation

**Environment Variables:**
Supported with double-underscore nesting:
```
AEGISSCAN_SCAN_DEFAULTS__TIMEOUT=10.0
AEGISSCAN_DATABASE__ENGINE=postgresql
AEGISSCAN_LOGGING__LEVEL=DEBUG
```

**Features:**
- Automatic type inference (int, float, bool, string)
- Configuration validation with error collection
- YAML export capability
- Lazy-loaded global singleton via `get_config()`
- Automatic logging setup on initialization

### 6. `aegisscan/scanner/__init__.py`
Module exports for convenient importing.

**Exports:**
- All scanner classes (ConnectScanner, SynScanner)
- Data models (ScanTarget, HostResult, PortResult, etc.)
- Utilities (parse_targets, parse_ports)
- Rate limiting components

## Code Quality Features

### Type Hints
- Full type annotations on all functions/methods
- Return type hints on all functions
- Optional type support for nullable fields
- Complex types (List, Dict, Tuple, Union, Callable)

### Docstrings
- Module-level docstrings on all files
- Class docstrings with usage context
- Method docstrings with Args/Returns/Raises sections
- Google-style format for consistency

### Error Handling
- Custom exceptions with context
- Validation errors on bad configuration
- Permission checking for privileged operations
- Graceful fallbacks for optional dependencies

### Async Patterns
- Proper asyncio.Lock usage for thread safety
- asyncio.Semaphore for concurrency control
- asyncio.wait_for() for timeout handling
- asyncio.gather() for concurrent task execution
- Proper cleanup (writer.wait_closed())

### Logging
- Logger per module (using __name__)
- Configurable log levels
- Progress callbacks for integration
- Detailed error logging

## Validation Examples

All parsing and configuration validates input:

```python
# Port validation
parse_ports(["1-65536"])  # ValueError: Port out of range
parse_ports(["80-20"])    # ValueError: Invalid range (start > end)

# IP validation  
ScanTarget(ip="invalid")  # ValueError: Invalid IP address

# Configuration validation
ScanConfig(timeout=-1)    # ValueError: Timeout must be positive
ScanConfig(concurrency=0) # ValueError: Concurrency must be at least 1
```

## Testing

All modules compile successfully and pass basic instantiation tests:
- Syntax validation via py_compile
- Import chain verification
- Data class creation and validation
- Configuration loading and validation
- Async rate limiter functionality
- AsyncIO event loop integration

## Dependencies

**Required:**
- Python 3.8+
- asyncio (stdlib)
- dataclasses (stdlib)
- logging (stdlib)
- ipaddress (stdlib)

**Optional:**
- scapy (for SYN scanner): `pip install scapy`
- pyyaml (for YAML config): `pip install pyyaml`

## Integration Points

These modules are designed to integrate with:
- Database layer (models for storage)
- Web API (configuration and scanning)
- CLI tools (configuration files and parsing)
- Reporting systems (HostResult and PortResult data structures)

All code follows production standards suitable for a 3-year professional developer.
