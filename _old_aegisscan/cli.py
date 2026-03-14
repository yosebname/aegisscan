"""
Command-line interface for AegisScan.

Provides a comprehensive CLI with subcommands for scanning, enrichment,
analysis, and reporting. Uses argparse for minimal dependencies.
"""

import argparse
import sys
import logging
from typing import Optional, List, Tuple
from pathlib import Path

from aegisscan import __version__
from aegisscan.main import ScanOrchestrator


# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_banner() -> None:
    """Print the AegisScan ASCII banner."""
    banner = f"""
{Colors.BOLD}{Colors.CYAN}
    ___    _______ _____  _____ _____   _____ _____ _____ _   _ 
   / _ |  / / ____/ ____|/ ____/ ____|  / ____|  __ \\ |_   _| |
  / /_| |/ / |  | |  __| |  | |  __|   | (___ | |  | |  | | | |
 / ____ \\ | |  | | |_ | |  | | |_ |    \\___ \\| |  | |  | | | |
/ _|  |_\\ \\ |__| |  __| |  |__| |__|    ____) | |__| | _| |_|_|
\\____|____\\_____|_|     \\_____|_____|  |_____/|_____/ |_____(_)

{Colors.BOLD}Professional Network Security Scanner{Colors.ENDC}
Version {__version__}
{Colors.ENDC}
    """
    print(banner)


def print_progress(current: int, total: int, label: str = "Progress") -> None:
    """
    Print a simple text-based progress bar.
    
    Args:
        current: Current progress count
        total: Total count
        label: Label for the progress bar
    """
    if total <= 0:
        return
    
    percent = int((current / total) * 100)
    filled = int((current / total) * 40)
    bar = "█" * filled + "░" * (40 - filled)
    print(f"\r{label}: [{bar}] {percent}% ({current}/{total})", end="", flush=True)


def colored(text: str, color: str) -> str:
    """
    Return colored text for terminal output.
    
    Args:
        text: Text to colorize
        color: Color code from Colors class
        
    Returns:
        Colored text string
    """
    return f"{color}{text}{Colors.ENDC}"


def validate_targets(targets_str: str) -> List[str]:
    """
    Validate and parse targets string.
    
    Args:
        targets_str: Comma-separated IPs, CIDRs, or file path
        
    Returns:
        List of valid targets
        
    Raises:
        ValueError: If targets are invalid
    """
    targets = []
    
    # Check if it's a file path
    path = Path(targets_str)
    if path.exists() and path.is_file():
        try:
            with open(path, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except IOError as e:
            raise ValueError(f"Failed to read targets file: {e}")
    else:
        # Parse comma-separated targets
        targets = [t.strip() for t in targets_str.split(',') if t.strip()]
    
    if not targets:
        raise ValueError("No valid targets provided")
    
    return targets


def validate_port_spec(port_spec: str) -> str:
    """
    Validate port specification.
    
    Args:
        port_spec: Port specification (e.g., "1-1024", "80,443", "80-443,8080")
        
    Returns:
        Validated port specification
        
    Raises:
        ValueError: If port spec is invalid
    """
    # Basic validation - more detailed validation happens in scanner
    if not port_spec or not isinstance(port_spec, str):
        raise ValueError("Invalid port specification")
    
    return port_spec


def setup_logging(level: str = "INFO") -> logging.Logger:
    """
    Setup logging configuration.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        
    Returns:
        Configured logger instance
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        f'{Colors.CYAN}[%(asctime)s]{Colors.ENDC} '
        f'%(levelname)-8s %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    
    logger = logging.getLogger('aegisscan')
    logger.setLevel(log_level)
    logger.addHandler(handler)
    
    return logger


def cmd_scan(args: argparse.Namespace, orchestrator: ScanOrchestrator, 
             logger: logging.Logger) -> int:
    """
    Handle the 'scan' subcommand.
    
    Args:
        args: Parsed command arguments
        orchestrator: ScanOrchestrator instance
        logger: Logger instance
        
    Returns:
        Exit code
    """
    try:
        # Validate authorization
        if not args.i_own_or_am_authorized:
            print(colored(
                "ERROR: You must confirm that you own or are authorized to scan "
                "these targets (--i-own-or-am-authorized)",
                Colors.RED
            ))
            return 1
        
        # Validate and parse targets
        targets = validate_targets(args.targets)
        logger.info(f"Loaded {len(targets)} target(s)")
        
        # Validate port specification
        validate_port_spec(args.ports)
        
        # Validate scan type
        if args.type not in ('connect', 'syn', 'both'):
            print(colored(f"ERROR: Invalid scan type '{args.type}'", Colors.RED))
            return 1
        
        # Validate numeric arguments
        try:
            timeout = float(args.timeout)
            concurrency = int(args.concurrency)
            rate_limit = float(args.rate_limit)
            retries = int(args.retries)
        except ValueError as e:
            print(colored(f"ERROR: Invalid argument value: {e}", Colors.RED))
            return 1
        
        if timeout <= 0 or concurrency <= 0 or retries < 0 or rate_limit < 0:
            print(colored(
                "ERROR: timeout, concurrency, retries, and rate_limit must be positive",
                Colors.RED
            ))
            return 1
        
        # Build scan configuration
        config = {
            'targets': targets,
            'ports': args.ports,
            'scan_type': args.type,
            'timeout': timeout,
            'concurrency': concurrency,
            'rate_limit': rate_limit,
            'retries': retries,
            'enrich': args.enrich,
            'output_file': args.output,
            'output_format': args.format,
        }
        
        logger.info(
            f"Starting scan: {len(targets)} target(s), "
            f"ports={args.ports}, type={args.type}, "
            f"concurrency={concurrency}"
        )
        
        # Run scan
        print(colored(f"\n{Colors.BOLD}Initiating scan...{Colors.ENDC}", Colors.BLUE))
        scan_run = orchestrator.run_full_scan(config)
        
        print(colored(f"\n{Colors.BOLD}Scan completed!{Colors.ENDC}", Colors.GREEN))
        logger.info(f"Scan run ID: {scan_run.id}")
        
        if args.output:
            print(colored(f"Results saved to: {args.output}", Colors.GREEN))
        
        return 0
        
    except ValueError as e:
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1
    except KeyboardInterrupt:
        print(colored("\nScan cancelled by user", Colors.YELLOW))
        return 130
    except Exception as e:
        logger.exception("Scan failed with unexpected error")
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1


def cmd_import(args: argparse.Namespace, orchestrator: ScanOrchestrator,
               logger: logging.Logger) -> int:
    """
    Handle the 'import' subcommand.
    
    Args:
        args: Parsed command arguments
        orchestrator: ScanOrchestrator instance
        logger: Logger instance
        
    Returns:
        Exit code
    """
    try:
        import_file = Path(args.file)
        
        if not import_file.exists():
            print(colored(f"ERROR: File not found: {args.file}", Colors.RED))
            return 1
        
        logger.info(f"Importing nmap XML from: {args.file}")
        print(colored("\nImporting nmap scan...", Colors.BLUE))
        
        imported_data = orchestrator.import_nmap(
            str(import_file),
            merge_scan_run_id=args.merge_with
        )
        
        print(colored(
            f"Successfully imported scan data\n",
            Colors.GREEN
        ))
        logger.info(f"Imported {len(imported_data)} result(s)")
        
        return 0
        
    except ValueError as e:
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1
    except Exception as e:
        logger.exception("Import failed")
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1


def cmd_enrich(args: argparse.Namespace, orchestrator: ScanOrchestrator,
               logger: logging.Logger) -> int:
    """
    Handle the 'enrich' subcommand.
    
    Args:
        args: Parsed command arguments
        orchestrator: ScanOrchestrator instance
        logger: Logger instance
        
    Returns:
        Exit code
    """
    try:
        if not args.scan_run:
            print(colored("ERROR: --scan-run is required", Colors.RED))
            return 1
        
        logger.info(f"Enriching scan run: {args.scan_run}")
        print(colored("\nEnriching scan data...", Colors.BLUE))
        
        enrich_config = {
            'banners': args.banners,
            'tls': args.tls,
        }
        
        enriched_data = orchestrator.run_enrichment(
            args.scan_run,
            enrich_config
        )
        
        print(colored("Enrichment completed", Colors.GREEN))
        logger.info(f"Enriched {len(enriched_data)} result(s)")
        
        return 0
        
    except ValueError as e:
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1
    except Exception as e:
        logger.exception("Enrichment failed")
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1


def cmd_compare(args: argparse.Namespace, orchestrator: ScanOrchestrator,
                logger: logging.Logger) -> int:
    """
    Handle the 'compare' subcommand.
    
    Args:
        args: Parsed command arguments
        orchestrator: ScanOrchestrator instance
        logger: Logger instance
        
    Returns:
        Exit code
    """
    try:
        comparison_type = None
        scan_run_id = None
        
        if args.connect_vs_syn:
            comparison_type = 'connect_vs_syn'
            scan_run_id = args.connect_vs_syn
        elif args.internal_vs_external:
            comparison_type = 'internal_vs_external'
            scan_run_id = args.internal_vs_external
        elif args.runs and len(args.runs) == 2:
            comparison_type = 'custom'
            scan_run_id = tuple(args.runs)
        else:
            print(colored(
                "ERROR: Must specify one comparison type "
                "(--connect-vs-syn, --internal-vs-external, or --runs)",
                Colors.RED
            ))
            return 1
        
        logger.info(f"Running {comparison_type} comparison")
        print(colored(f"\nComparing scans ({comparison_type})...", Colors.BLUE))
        
        findings = orchestrator.run_comparison(scan_run_id, comparison_type)
        
        print(colored("Comparison completed", Colors.GREEN))
        logger.info(f"Found {len(findings)} difference(s)")
        
        return 0
        
    except ValueError as e:
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1
    except Exception as e:
        logger.exception("Comparison failed")
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1


def cmd_report(args: argparse.Namespace, orchestrator: ScanOrchestrator,
               logger: logging.Logger) -> int:
    """
    Handle the 'report' subcommand.
    
    Args:
        args: Parsed command arguments
        orchestrator: ScanOrchestrator instance
        logger: Logger instance
        
    Returns:
        Exit code
    """
    try:
        if not args.scan_run:
            print(colored("ERROR: --scan-run is required", Colors.RED))
            return 1
        
        if args.format not in ('html', 'pdf'):
            print(colored(f"ERROR: Invalid format '{args.format}'", Colors.RED))
            return 1
        
        logger.info(f"Generating {args.format.upper()} report for scan: {args.scan_run}")
        print(colored(f"\nGenerating {args.format.upper()} report...", Colors.BLUE))
        
        report_path = orchestrator.generate_report(
            args.scan_run,
            args.format,
            args.output
        )
        
        print(colored(f"Report generated: {report_path}", Colors.GREEN))
        logger.info(f"Report saved to: {report_path}")
        
        return 0
        
    except ValueError as e:
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1
    except Exception as e:
        logger.exception("Report generation failed")
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1


def cmd_serve(args: argparse.Namespace, orchestrator: ScanOrchestrator,
              logger: logging.Logger) -> int:
    """
    Handle the 'serve' subcommand.
    
    Args:
        args: Parsed command arguments
        orchestrator: ScanOrchestrator instance
        logger: Logger instance
        
    Returns:
        Exit code
    """
    try:
        host = args.host
        port = int(args.port)
        
        if port < 1 or port > 65535:
            print(colored("ERROR: Port must be between 1 and 65535", Colors.RED))
            return 1
        
        logger.info(f"Starting web server on {host}:{port}")
        print(colored(
            f"\nStarting AegisScan web interface on http://{host}:{port}\n",
            Colors.BLUE
        ))
        
        orchestrator.serve(host=host, port=port, reload=args.reload)
        
        return 0
        
    except ValueError as e:
        print(colored(f"ERROR: Invalid port: {e}", Colors.RED))
        return 1
    except KeyboardInterrupt:
        print(colored("\nServer stopped", Colors.YELLOW))
        return 0
    except Exception as e:
        logger.exception("Server error")
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1


def cmd_external(args: argparse.Namespace, orchestrator: ScanOrchestrator,
                 logger: logging.Logger) -> int:
    """
    Handle the 'external' subcommand.
    
    Args:
        args: Parsed command arguments
        orchestrator: ScanOrchestrator instance
        logger: Logger instance
        
    Returns:
        Exit code
    """
    try:
        if not args.scan_run:
            print(colored("ERROR: --scan-run is required", Colors.RED))
            return 1
        
        providers = args.provider.split(',')
        valid_providers = {'shodan', 'censys'}
        
        for provider in providers:
            if provider not in valid_providers and provider != 'all':
                print(colored(
                    f"ERROR: Invalid provider '{provider}'. "
                    f"Valid options: shodan, censys, all",
                    Colors.RED
                ))
                return 1
        
        logger.info(f"Looking up external data for scan: {args.scan_run}")
        print(colored("\nQuerying external data sources...", Colors.BLUE))
        
        external_data = orchestrator.run_external_lookup(args.scan_run, providers)
        
        print(colored("External lookup completed", Colors.GREEN))
        logger.info(f"Retrieved data from {len(external_data)} source(s)")
        
        return 0
        
    except ValueError as e:
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1
    except Exception as e:
        logger.exception("External lookup failed")
        print(colored(f"ERROR: {e}", Colors.RED))
        return 1


def create_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog='aegisscan',
        description='Professional Network Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a network with default settings
  aegisscan scan --targets 192.168.1.0/24 --i-own-or-am-authorized

  # Scan specific ports with SYN technique
  aegisscan scan --targets 10.0.0.0/8 --ports 80,443,8080 \\
    --type syn --i-own-or-am-authorized

  # Generate report from previous scan
  aegisscan report --scan-run <scan-id> --format html --output report.html

  # Query external intelligence
  aegisscan external --scan-run <scan-id> --provider shodan

For more help on a subcommand, use:
  aegisscan <subcommand> --help
        """
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )
    
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level (default: INFO)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan subcommand
    scan_parser = subparsers.add_parser(
        'scan',
        help='Perform network security scan'
    )
    scan_parser.add_argument(
        '--targets',
        required=True,
        help='Comma-separated IPs, CIDRs, or path to targets file'
    )
    scan_parser.add_argument(
        '--ports',
        default='1-1024',
        help='Port specification (default: 1-1024)'
    )
    scan_parser.add_argument(
        '--type',
        choices=['connect', 'syn', 'both'],
        default='connect',
        help='Scan type (default: connect)'
    )
    scan_parser.add_argument(
        '--timeout',
        type=float,
        default=2.0,
        help='Connection timeout in seconds (default: 2.0)'
    )
    scan_parser.add_argument(
        '--concurrency',
        type=int,
        default=200,
        help='Maximum concurrent connections (default: 200)'
    )
    scan_parser.add_argument(
        '--rate-limit',
        type=float,
        default=0,
        help='Maximum connections per second (0=unlimited, default: 0)'
    )
    scan_parser.add_argument(
        '--retries',
        type=int,
        default=1,
        help='Number of retries for failed connections (default: 1)'
    )
    scan_parser.add_argument(
        '--enrich',
        action='store_true',
        help='Automatically enrich with banners and TLS information'
    )
    scan_parser.add_argument(
        '--output',
        help='Output file path for results'
    )
    scan_parser.add_argument(
        '--format',
        choices=['json', 'csv', 'table'],
        default='table',
        help='Output format (default: table)'
    )
    scan_parser.add_argument(
        '--i-own-or-am-authorized',
        action='store_true',
        help='Confirm you own or are authorized to scan these targets (required)'
    )
    
    # Import subcommand
    import_parser = subparsers.add_parser(
        'import',
        help='Import nmap XML results'
    )
    import_parser.add_argument(
        '--file',
        required=True,
        help='Path to nmap XML file'
    )
    import_parser.add_argument(
        '--merge-with',
        help='Merge with existing scan run ID'
    )
    
    # Enrich subcommand
    enrich_parser = subparsers.add_parser(
        'enrich',
        help='Enrich scan results with additional data'
    )
    enrich_parser.add_argument(
        '--scan-run',
        required=True,
        help='Scan run ID to enrich'
    )
    enrich_parser.add_argument(
        '--banners',
        action='store_true',
        help='Grab service banners'
    )
    enrich_parser.add_argument(
        '--tls',
        action='store_true',
        help='Inspect TLS certificates'
    )
    
    # Compare subcommand
    compare_parser = subparsers.add_parser(
        'compare',
        help='Compare scan results'
    )
    compare_group = compare_parser.add_mutually_exclusive_group(required=True)
    compare_group.add_argument(
        '--connect-vs-syn',
        metavar='SCAN_RUN_ID',
        help='Compare connect vs SYN results from a scan run'
    )
    compare_group.add_argument(
        '--internal-vs-external',
        metavar='SCAN_RUN_ID',
        help='Compare internal vs external perspectives'
    )
    compare_group.add_argument(
        '--runs',
        nargs=2,
        metavar='SCAN_RUN_ID',
        help='Compare two different scan runs'
    )
    
    # Report subcommand
    report_parser = subparsers.add_parser(
        'report',
        help='Generate report from scan results'
    )
    report_parser.add_argument(
        '--scan-run',
        required=True,
        help='Scan run ID to generate report for'
    )
    report_parser.add_argument(
        '--format',
        choices=['html', 'pdf'],
        default='html',
        help='Report format (default: html)'
    )
    report_parser.add_argument(
        '--output',
        help='Output file path'
    )
    
    # Serve subcommand
    serve_parser = subparsers.add_parser(
        'serve',
        help='Start web server for AegisScan interface'
    )
    serve_parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Bind host (default: 127.0.0.1)'
    )
    serve_parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Bind port (default: 8080)'
    )
    serve_parser.add_argument(
        '--reload',
        action='store_true',
        help='Enable auto-reload for development'
    )
    
    # External subcommand
    external_parser = subparsers.add_parser(
        'external',
        help='Query external intelligence sources'
    )
    external_parser.add_argument(
        '--scan-run',
        required=True,
        help='Scan run ID to look up'
    )
    external_parser.add_argument(
        '--provider',
        default='all',
        help='External provider(s): shodan, censys, all (default: all)'
    )
    
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main entry point for the AegisScan CLI.
    
    Args:
        argv: Command-line arguments (defaults to sys.argv[1:])
        
    Returns:
        Exit code
    """
    parser = create_parser()
    args = parser.parse_args(argv)
    
    # Setup logging
    logger = setup_logging(args.log_level)
    
    # Print banner on first run
    if not argv or (argv and argv[0] not in ['-h', '--help', '--version']):
        print_banner()
    
    # Initialize orchestrator
    orchestrator = ScanOrchestrator()
    
    # Dispatch to appropriate subcommand
    if args.command == 'scan':
        return cmd_scan(args, orchestrator, logger)
    elif args.command == 'import':
        return cmd_import(args, orchestrator, logger)
    elif args.command == 'enrich':
        return cmd_enrich(args, orchestrator, logger)
    elif args.command == 'compare':
        return cmd_compare(args, orchestrator, logger)
    elif args.command == 'report':
        return cmd_report(args, orchestrator, logger)
    elif args.command == 'serve':
        return cmd_serve(args, orchestrator, logger)
    elif args.command == 'external':
        return cmd_external(args, orchestrator, logger)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
