# AegisScan Implementation Details

## Architecture Overview

```
aegisscan/
├── cli.py                 # Command-line interface (argparse)
├── main.py               # Orchestrator (ScanOrchestrator)
├── __init__.py           # Package metadata
└── [future modules]
    ├── scanner/          # Scanning backends
    ├── enrichment/       # Enrichment modules
    ├── external/         # External intelligence
    ├── analysis/         # Result analysis
    ├── report/           # Report generation
    ├── db/              # Database layer
    └── web/             # Web interface
```

## Core Classes

### 1. ScanResult (main.py)

```python
@dataclass
class ScanResult:
    """Individual scan result for a target/port combination."""
    target: str
    port: int
    protocol: str
    state: str  # open, closed, filtered
    service: Optional[str] = None
    banner: Optional[str] = None
    tls_info: Optional[Dict[str, Any]] = None
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
```

Properties:
- Immutable by default (can be frozen with frozen=True)
- Auto-initializes timestamps
- Optional enrichment fields
- Serializable to dict()

### 2. ScanRun (main.py)

```python
@dataclass
class ScanRun:
    """Complete scan run record."""
    id: str
    scan_type: str
    targets: List[str]
    ports: str
    start_time: datetime
    end_time: Optional[datetime] = None
    results: List[ScanResult] = field(default_factory=list)
    enriched: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
```

Methods:
- `duration()` -> Optional[float]: Calculate scan duration
- `to_dict()` -> Dict: JSON-serializable representation

### 3. ScanOrchestrator (main.py)

```python
class ScanOrchestrator:
    """Main orchestrator for AegisScan operations."""
    
    # Configuration & Validation
    def _validate_config(config: Dict) -> None
    
    # Scanning Operations
    async def _execute_scan(config: Dict) -> List[ScanResult]
    def run_full_scan(config: Dict) -> ScanRun
    def run_scan_only(config: Dict) -> List[ScanResult]
    
    # Enrichment
    async def _enrich_results(results: List) -> List[ScanResult]
    def run_enrichment(scan_run_id: str) -> List[ScanResult]
    
    # Analysis
    def run_comparison(scan_run_id: Union[str, Tuple]) -> List[Dict]
    
    # External Intelligence
    def run_external_lookup(scan_run_id: str, providers: List) -> Dict
    
    # Reporting
    def generate_report(scan_run_id: str, format: str) -> str
    
    # Import/Export
    def import_nmap(file_path: str) -> List[ScanResult]
    def _save_results(scan_run: ScanRun, file: str, format: str) -> None
    
    # Web Interface
    def serve(host: str, port: int, reload: bool) -> None
```

## CLI Command Handlers

Each subcommand has a dedicated handler function:

```python
def cmd_scan(args, orchestrator, logger) -> int
def cmd_import(args, orchestrator, logger) -> int
def cmd_enrich(args, orchestrator, logger) -> int
def cmd_compare(args, orchestrator, logger) -> int
def cmd_report(args, orchestrator, logger) -> int
def cmd_serve(args, orchestrator, logger) -> int
def cmd_external(args, orchestrator, logger) -> int
```

Pattern:
1. Validate arguments
2. Create appropriate config
3. Call orchestrator method
4. Handle errors and return exit code
5. Output results with colors

## Type System

Full type hints throughout:

```python
# Function signatures
def validate_targets(targets_str: str) -> List[str]
def run_comparison(scan_run_id: Union[str, Tuple[str, str]],
                  comparison_type: str = 'custom') -> List[Dict[str, Any]]

# Complex types
config: Dict[str, Any]
results: List[ScanResult]
provider_data: Union[str, List[str]]

# Optional types
merge_scan_run_id: Optional[str] = None
enrich_config: Optional[Dict[str, Any]] = None
```

## Error Handling Strategy

1. **Input Validation**: Check arguments before operations
2. **File Operations**: Handle IOError, FileNotFoundError
3. **Execution**: Try-except with specific exception types
4. **Exit Codes**:
   - 0 = Success
   - 1 = General error
   - 130 = Interrupted (Ctrl+C)

Example:
```python
try:
    targets = validate_targets(args.targets)
except ValueError as e:
    print(colored(f"ERROR: {e}", Colors.RED))
    return 1
except KeyboardInterrupt:
    print(colored("\nOperation cancelled", Colors.YELLOW))
    return 130
except Exception as e:
    logger.exception("Unexpected error")
    return 1
```

## Configuration Validation

Comprehensive config validation in orchestrator:

```python
def _validate_config(self, config: Dict[str, Any]) -> None:
    # Check required keys
    required_keys = {'targets', 'ports', 'scan_type'}
    
    # Validate data types
    if not isinstance(config['targets'], list):
        raise ValueError("targets must be a list")
    
    # Validate values
    if config['scan_type'] not in ('connect', 'syn', 'both'):
        raise ValueError("Invalid scan_type")
    
    # Validate ranges
    if config['concurrency'] <= 0:
        raise ValueError("concurrency must be positive")
```

## Output Formatting

### JSON Format
```python
{
    "id": "scan_abc123def456",
    "scan_type": "connect",
    "targets": ["192.168.1.0/24"],
    "ports": "1-1024",
    "results": [
        {
            "target": "192.168.1.1",
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http"
        }
    ]
}
```

### CSV Format
```csv
target,port,protocol,state,service
192.168.1.1,80,tcp,open,http
192.168.1.2,443,tcp,open,https
```

### Table Format
```
Scan Run: scan_abc123def456
Type: connect
Duration: 2.34s
Results: 24

Target              Port     Protocol   State        Service
------------------------------------------------------------------
192.168.1.1         80       tcp        open         http
192.168.1.2         443      tcp        open        https
```

## Async/Await Patterns

Used for concurrent I/O operations:

```python
async def _execute_scan(self, config):
    results = []
    for target in config['targets']:
        result = await scan_target(target)
        results.append(result)
        await asyncio.sleep(0.01)  # Yield to event loop
    return results

# Called from sync context
results = asyncio.run(self._execute_scan(config))
```

## Color Output (ANSI Codes)

No external dependencies, pure ANSI codes:

```python
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Usage
print(colored("Success!", Colors.GREEN))
print(f"{Colors.BOLD}Bold text{Colors.ENDC}")
```

## Logging Configuration

Structured logging with colored output:

```python
def setup_logging(level: str = "INFO") -> logging.Logger:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        f'{Colors.CYAN}[%(asctime)s]{Colors.ENDC} '
        f'%(levelname)-8s %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    
    logger = logging.getLogger('aegisscan')
    logger.setLevel(getattr(logging, level.upper()))
    logger.addHandler(handler)
    return logger
```

## Argument Parser Structure

Hierarchical command structure:

```
aegisscan [--version] [--log-level LEVEL]
├── scan [--targets TARGETS] [--ports PORTS] [--type TYPE]
│         [--timeout TIMEOUT] [--concurrency CONC]
│         [--rate-limit RATE] [--retries RETRIES]
│         [--enrich] [--output FILE] [--format FORMAT]
│         --i-own-or-am-authorized
├── import [--file FILE] [--merge-with SCAN_RUN_ID]
├── enrich [--scan-run ID] [--banners] [--tls]
├── compare (--connect-vs-syn ID | --internal-vs-external ID | --runs ID ID)
├── report [--scan-run ID] [--format FORMAT] [--output FILE]
├── serve [--host HOST] [--port PORT] [--reload]
└── external [--scan-run ID] [--provider PROVIDER]
```

## Package Dependencies

Minimal core requirements:
- sqlalchemy (2.0+): Database ORM
- jinja2 (3.1+): Template rendering
- aiohttp (3.8+): Async HTTP client

Optional add-ons available:
- scapy: Raw packet manipulation
- weasyprint: PDF generation
- pyyaml: YAML parsing
- shodan/censys: External intelligence
- fastapi/uvicorn: Web framework

## Installation Entry Point

setup.py defines console script:
```python
entry_points={
    "console_scripts": [
        "aegisscan=aegisscan.cli:main",
    ],
}
```

After installation: `pip install -e .`
Command available: `aegisscan` from anywhere

## Development Standards

✓ All functions have complete docstrings
✓ All parameters have type hints
✓ All return values have type hints
✓ Exception handling with specific types
✓ Validation before operations
✓ Configuration validation
✓ Consistent error messages
✓ Proper resource cleanup
✓ Logging for debugging
✓ Constants in UPPERCASE
✓ PEP 8 compliance
✓ Line length: 100 characters max
✓ Import ordering with isort
✓ Code formatting with black

## Future Extension Points

The architecture supports easy addition of:

1. **Scanners**: Implement scanner interface
2. **Enrichment**: Add new enrichment plugins
3. **External Providers**: Create provider connectors
4. **Analysis**: Add comparison/analysis modules
5. **Reporting**: Add custom report templates
6. **Database**: Implement SQLAlchemy models
7. **Web API**: Add FastAPI endpoints
8. **Storage**: Implement persistence layer

