"""
AegisScan Scanner - Usage Examples

This file demonstrates how to use the scanner core modules.
Not intended to be run directly, but to serve as documentation.
"""

import asyncio
from aegisscan.scanner import (
    ConnectScanner,
    SynScanner,
    ScanTarget,
    parse_targets,
    parse_ports,
    RetryPolicy,
    TimeoutPolicy,
)
from aegisscan.config import AppConfig, get_config


# ============================================================================
# Example 1: Basic TCP Connect Scanning
# ============================================================================

async def example_basic_connect_scan():
    """Scan a single host with default settings."""
    
    # Create scanner with defaults
    scanner = ConnectScanner(timeout=5.0, concurrency=10)
    
    # Define target
    target = ScanTarget(ip="192.168.1.1", ports=[22, 80, 443])
    
    # Scan the target
    result = await scanner.scan_host(target)
    
    # Access results
    print(f"Target: {result.ip}")
    print(f"Open ports: {result.open_ports}")
    print(f"Closed ports: {result.closed_ports}")
    print(f"Filtered ports: {result.filtered_ports}")
    print(f"Scan duration: {result.scan_duration:.2f}s")


# ============================================================================
# Example 2: Parsing Targets and Ports
# ============================================================================

async def example_parsing():
    """Parse various target and port specifications."""
    
    # Parse targets from various formats
    targets = parse_targets([
        "192.168.1.1",          # Single IP
        "10.0.0.0/24",          # CIDR notation (254 hosts)
        "example.com",          # Hostname (will be used as hostname field)
    ])
    print(f"Parsed {len(targets)} targets")
    
    # Parse ports from various formats
    ports = parse_ports([
        "22",                   # Single port
        "80,443",               # Comma-separated
        "1-1024",               # Range
        "8000-8010",            # Another range
    ])
    print(f"Parsed {len(ports)} ports: {sorted(ports)[:10]}...")


# ============================================================================
# Example 3: Scanning Multiple Targets
# ============================================================================

async def example_multiple_targets():
    """Scan multiple targets concurrently."""
    
    # Create scanner
    scanner = ConnectScanner(
        timeout=5.0,
        concurrency=20,  # Up to 20 concurrent connections
        rate_limit=50.0,  # 50 operations per second
    )
    
    # Create targets
    targets = [
        ScanTarget(ip="192.168.1.1", ports=[22, 80, 443]),
        ScanTarget(ip="192.168.1.2", ports=[22, 80, 443]),
        ScanTarget(ip="192.168.1.3", ports=[22, 80, 443]),
    ]
    
    # Scan all targets
    results = await scanner.scan_targets(targets)
    
    # Process results
    for result in results:
        print(f"{result.ip}: {len(result.open_ports)} open ports")


# ============================================================================
# Example 4: Progress Tracking
# ============================================================================

async def example_progress_tracking():
    """Track scanning progress with callbacks."""
    
    scanner = ConnectScanner(
        timeout=5.0,
        concurrency=10,
        verbose=True
    )
    
    # Set progress callback
    def on_progress(message: str):
        print(f"[PROGRESS] {message}")
    
    scanner.set_progress_callback(on_progress)
    
    # Scan
    target = ScanTarget(ip="192.168.1.1", ports=[22, 80, 443])
    result = await scanner.scan_host(target)


# ============================================================================
# Example 5: Retry and Timeout Configuration
# ============================================================================

async def example_advanced_configuration():
    """Use custom retry and timeout policies."""
    
    # Define retry policy
    retry_policy = RetryPolicy(
        max_retries=3,
        backoff_factor=2.0,
        initial_delay=0.1,
        max_delay=5.0,
    )
    
    # Define timeout policy
    timeout_policy = TimeoutPolicy(
        connect_timeout=5.0,
        read_timeout=5.0,
    )
    
    # Create scanner with policies
    scanner = ConnectScanner(
        timeout=5.0,
        concurrency=15,
        rate_limit=20.0,
        retry_policy=retry_policy,
        timeout_policy=timeout_policy,
    )
    
    # Scan
    target = ScanTarget(ip="192.168.1.1", ports=[22, 80, 443])
    result = await scanner.scan_host(target)


# ============================================================================
# Example 6: SYN Scanning (Requires Root)
# ============================================================================

async def example_syn_scan():
    """Perform SYN scanning (requires root/admin privileges)."""
    
    try:
        # Create SYN scanner
        scanner = SynScanner(
            timeout=5.0,
            concurrency=20,
            rate_limit=100.0,  # Faster than TCP Connect
        )
        
        # Scan
        target = ScanTarget(ip="192.168.1.1", ports=[22, 80, 443])
        result = await scanner.scan_host(target)
        
        print(f"SYN scan: {result.ip} - {len(result.open_ports)} open")
        
    except PermissionError as e:
        print(f"SYN scanning requires root: {e}")
    except RuntimeError as e:
        print(f"Scapy not available: {e}")


# ============================================================================
# Example 7: Comparing SYN vs TCP Connect
# ============================================================================

async def example_compare_scanners():
    """Compare results between SYN and TCP Connect scanning."""
    
    target = ScanTarget(ip="192.168.1.1", ports=[22, 80, 443, 445])
    
    # TCP Connect scan
    connect_scanner = ConnectScanner(timeout=5.0, concurrency=10)
    connect_results = [await connect_scanner.scan_host(target)]
    
    try:
        # SYN scan
        syn_scanner = SynScanner(timeout=5.0, concurrency=10)
        syn_results = [await syn_scanner.scan_host(target)]
        
        # Compare results
        discrepancies = SynScanner.compare_with_connect(
            syn_results,
            connect_results
        )
        
        if discrepancies:
            print("Differences found:")
            for ip, port, syn_state, connect_state in discrepancies:
                print(f"  {ip}:{port} - SYN: {syn_state}, TCP: {connect_state}")
        else:
            print("No discrepancies between SYN and TCP Connect")
    
    except (PermissionError, RuntimeError):
        print("SYN scanning not available")


# ============================================================================
# Example 8: Configuration Management
# ============================================================================

def example_configuration():
    """Manage application configuration."""
    
    # Use default configuration
    config = AppConfig()
    print(f"App: {config.app_name} v{config.version}")
    print(f"Default timeout: {config.scan_defaults.timeout}s")
    print(f"Default concurrency: {config.scan_defaults.concurrency}")
    
    # Load from environment variables
    # Set: AEGISSCAN_SCAN_DEFAULTS__TIMEOUT=10.0
    # Set: AEGISSCAN_LOGGING__LEVEL=DEBUG
    config = AppConfig.from_env()
    
    # Validate configuration
    errors = config.validate()
    if errors:
        for error in errors:
            print(f"Config error: {error}")
    else:
        print("Configuration is valid")
    
    # Save to YAML (requires pyyaml)
    # config.save_yaml("aegisscan.yaml")
    
    # Load from YAML
    # config = AppConfig.from_yaml("aegisscan.yaml")


def example_configuration_yaml():
    """Example YAML configuration file."""
    
    yaml_config = """
scan_defaults:
  timeout: 10.0
  retries: 2
  concurrency: 20
  rate_limit: 50.0
  verbose: false
  dns_lookup: true
  ports: [22, 80, 443, 8080, 8443]

database:
  engine: sqlite
  path: aegisscan.db
  pool_size: 10
  echo: false

logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  log_file: null
  console_output: true

api:
  enabled: false
  host: 127.0.0.1
  port: 8000
  workers: 4
  timeout: 30.0

credentials:
  ssh_key_path: null
  api_keys_path: null
  env_var_prefix: AEGISSCAN_

debug: false
app_name: AegisScan
version: 0.1.0
"""
    
    print(yaml_config)


# ============================================================================
# Example 9: Complete Workflow
# ============================================================================

async def example_complete_workflow():
    """Complete scanning workflow."""
    
    # Load configuration
    config = AppConfig()
    
    # Parse targets and ports
    targets = parse_targets(["192.168.1.0/24"])
    ports = parse_ports(["22", "80", "443", "8080"])
    
    print(f"Scanning {len(targets)} targets on {len(ports)} ports")
    
    # Create scanner with config
    scanner = ConnectScanner(
        timeout=config.scan_defaults.timeout,
        concurrency=config.scan_defaults.concurrency,
        rate_limit=config.scan_defaults.rate_limit,
        verbose=config.scan_defaults.verbose,
    )
    
    # Add progress callback
    progress_messages = []
    scanner.set_progress_callback(lambda msg: progress_messages.append(msg))
    
    # Create target objects
    scan_targets = [
        ScanTarget(ip=t.ip, ports=ports)
        for t in targets[:5]  # Limit to first 5 for example
    ]
    
    # Run scans
    results = await scanner.scan_targets(scan_targets)
    
    # Process and report results
    total_open = sum(len(r.open_ports) for r in results)
    total_closed = sum(len(r.closed_ports) for r in results)
    total_filtered = sum(len(r.filtered_ports) for r in results)
    
    print(f"\n=== Scan Results ===")
    print(f"Open ports: {total_open}")
    print(f"Closed ports: {total_closed}")
    print(f"Filtered ports: {total_filtered}")
    
    for result in results:
        if result.open_ports:
            print(f"{result.ip}: Open ports: {result.open_ports}")


# ============================================================================
# Example 10: Error Handling
# ============================================================================

async def example_error_handling():
    """Demonstrate error handling."""
    
    from aegisscan.scanner import ScanTarget, ScanConfig, parse_ports
    
    try:
        # Invalid IP address
        target = ScanTarget(ip="invalid.ip.address")
    except ValueError as e:
        print(f"Target error: {e}")
    
    try:
        # Invalid port range
        ports = parse_ports(["80-20"])  # start > end
    except ValueError as e:
        print(f"Port parsing error: {e}")
    
    try:
        # Invalid configuration
        config = ScanConfig(
            targets=["192.168.1.1"],
            ports=[80],
            timeout=-1  # Invalid
        )
    except ValueError as e:
        print(f"Config error: {e}")


# ============================================================================
# Running Examples
# ============================================================================

if __name__ == "__main__":
    print("This file contains usage examples.")
    print("Import and run the async examples in your code:")
    print("")
    print("  asyncio.run(example_basic_connect_scan())")
    print("  asyncio.run(example_multiple_targets())")
    print("  asyncio.run(example_complete_workflow())")
    print("")
    print("For non-async examples:")
    print("")
    print("  example_configuration()")
    print("  example_error_handling()")
