"""
Core orchestrator for AegisScan operations.

Coordinates scanning, enrichment, analysis, and reporting workflows.
Provides high-level abstractions over component-specific functionality.
"""

import asyncio
import uuid
import logging
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
import json


logger = logging.getLogger(__name__)


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
    
    def duration(self) -> Optional[float]:
        """Get scan duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        data = asdict(self)
        data['start_time'] = self.start_time.isoformat()
        data['end_time'] = self.end_time.isoformat() if self.end_time else None
        data['results'] = [asdict(r) for r in self.results]
        data['duration'] = self.duration()
        return data


class ScanOrchestrator:
    """
    Main orchestrator for AegisScan operations.
    
    Coordinates all scanning, enrichment, analysis, and reporting workflows.
    Manages state and provides async orchestration.
    """
    
    def __init__(self) -> None:
        """Initialize the ScanOrchestrator."""
        self._scan_runs: Dict[str, ScanRun] = {}
        self._logger = logging.getLogger(__name__)
    
    def _generate_scan_run_id(self) -> str:
        """
        Generate a unique scan run ID.
        
        Returns:
            Unique scan run identifier
        """
        return f"scan_{uuid.uuid4().hex[:12]}"
    
    def _validate_config(self, config: Dict[str, Any]) -> None:
        """
        Validate scan configuration.
        
        Args:
            config: Scan configuration dictionary
            
        Raises:
            ValueError: If configuration is invalid
        """
        required_keys = {'targets', 'ports', 'scan_type'}
        
        if not all(key in config for key in required_keys):
            raise ValueError(
                f"Configuration missing required keys: {required_keys - set(config.keys())}"
            )
        
        if not isinstance(config['targets'], list) or not config['targets']:
            raise ValueError("targets must be a non-empty list")
        
        if config['scan_type'] not in ('connect', 'syn', 'both'):
            raise ValueError(f"Invalid scan_type: {config['scan_type']}")
        
        if config.get('concurrency', 200) <= 0:
            raise ValueError("concurrency must be positive")
        
        if config.get('timeout', 2.0) <= 0:
            raise ValueError("timeout must be positive")
    
    async def _execute_scan(self, config: Dict[str, Any]) -> List[ScanResult]:
        """
        Execute the actual scanning operation.
        
        Args:
            config: Scan configuration
            
        Returns:
            List of scan results
        """
        results: List[ScanResult] = []
        targets = config['targets']
        scan_type = config['scan_type']
        timeout = config.get('timeout', 2.0)
        concurrency = config.get('concurrency', 200)
        rate_limit = config.get('rate_limit', 0)
        retries = config.get('retries', 1)
        
        self._logger.info(
            f"Starting scan: {len(targets)} targets, "
            f"scan_type={scan_type}, concurrency={concurrency}"
        )
        
        # Simulate scanning operation
        # In production, this would interface with actual scanning backends
        for target in targets:
            # Simulate per-target results
            result = ScanResult(
                target=target,
                port=80,
                protocol='tcp',
                state='open',
                service='http',
            )
            results.append(result)
            
            self._logger.debug(f"Scanned {target}:80 - open")
            await asyncio.sleep(0.01)  # Simulate async I/O
        
        self._logger.info(f"Scan execution completed: {len(results)} results")
        return results
    
    async def _enrich_results(self, results: List[ScanResult],
                             enrich_config: Optional[Dict[str, Any]] = None
                             ) -> List[ScanResult]:
        """
        Enrich scan results with additional data.
        
        Args:
            results: Original scan results
            enrich_config: Enrichment configuration
            
        Returns:
            Enriched scan results
        """
        if not enrich_config:
            enrich_config = {}
        
        enrich_banners = enrich_config.get('banners', True)
        enrich_tls = enrich_config.get('tls', True)
        
        self._logger.info(f"Enriching {len(results)} result(s)")
        
        for result in results:
            if enrich_banners and result.state == 'open':
                result.banner = f"Simulated banner for {result.target}:{result.port}"
                self._logger.debug(f"Enriched {result.target}:{result.port} with banner")
            
            if enrich_tls and result.port == 443:
                result.tls_info = {
                    'valid': True,
                    'issuer': 'Self-Signed',
                    'subject': result.target,
                }
                self._logger.debug(f"Enriched {result.target}:{result.port} with TLS info")
            
            await asyncio.sleep(0.01)
        
        self._logger.info("Enrichment completed")
        return results
    
    def run_full_scan(self, config: Dict[str, Any]) -> ScanRun:
        """
        Execute a complete scan workflow including enrichment.
        
        Runs: scan -> enrich -> analyze -> save
        
        Args:
            config: Scan configuration dictionary
                - targets: List[str]
                - ports: str
                - scan_type: str (connect/syn/both)
                - timeout: float (default: 2.0)
                - concurrency: int (default: 200)
                - rate_limit: float (default: 0)
                - retries: int (default: 1)
                - enrich: bool (default: False)
                - output_file: str (optional)
                - output_format: str (default: table)
        
        Returns:
            ScanRun object with results
            
        Raises:
            ValueError: If configuration is invalid
        """
        self._validate_config(config)
        
        scan_run_id = self._generate_scan_run_id()
        start_time = datetime.utcnow()
        
        # Create scan run record
        scan_run = ScanRun(
            id=scan_run_id,
            scan_type=config['scan_type'],
            targets=config['targets'],
            ports=config['ports'],
            start_time=start_time,
        )
        
        try:
            # Execute scan
            results = asyncio.run(self._execute_scan(config))
            
            # Optionally enrich
            if config.get('enrich', False):
                enrich_config = {
                    'banners': True,
                    'tls': True,
                }
                results = asyncio.run(self._enrich_results(results, enrich_config))
                scan_run.enriched = True
            
            # Update scan run
            scan_run.results = results
            scan_run.end_time = datetime.utcnow()
            
            # Save results if output file specified
            if config.get('output_file'):
                self._save_results(scan_run, config['output_file'],
                                 config.get('output_format', 'table'))
            
            # Store in memory
            self._scan_runs[scan_run_id] = scan_run
            
            self._logger.info(
                f"Scan run completed: {scan_run_id} "
                f"({len(results)} results, {scan_run.duration():.2f}s)"
            )
            
            return scan_run
            
        except Exception as e:
            scan_run.end_time = datetime.utcnow()
            self._logger.error(f"Scan run failed: {e}")
            raise
    
    def run_scan_only(self, config: Dict[str, Any]) -> List[ScanResult]:
        """
        Execute scan without enrichment.
        
        Args:
            config: Scan configuration
            
        Returns:
            List of scan results
        """
        self._validate_config(config)
        self._logger.info(f"Running scan-only mode for {len(config['targets'])} target(s)")
        
        results = asyncio.run(self._execute_scan(config))
        return results
    
    def run_enrichment(self, scan_run_id: str,
                      enrich_config: Optional[Dict[str, Any]] = None
                      ) -> List[ScanResult]:
        """
        Enrich results of an existing scan run.
        
        Args:
            scan_run_id: ID of scan run to enrich
            enrich_config: Enrichment configuration
            
        Returns:
            List of enriched results
            
        Raises:
            ValueError: If scan run not found
        """
        if scan_run_id not in self._scan_runs:
            raise ValueError(f"Scan run not found: {scan_run_id}")
        
        scan_run = self._scan_runs[scan_run_id]
        self._logger.info(f"Enriching scan run {scan_run_id}")
        
        enriched = asyncio.run(
            self._enrich_results(scan_run.results, enrich_config)
        )
        scan_run.results = enriched
        scan_run.enriched = True
        
        return enriched
    
    def run_comparison(self, scan_run_id: Union[str, Tuple[str, str]],
                      comparison_type: str = 'custom'
                      ) -> List[Dict[str, Any]]:
        """
        Compare scan results.
        
        Args:
            scan_run_id: Scan run ID or tuple of two IDs to compare
            comparison_type: Type of comparison (connect_vs_syn, internal_vs_external, custom)
            
        Returns:
            List of differences/findings
            
        Raises:
            ValueError: If scan runs not found
        """
        self._logger.info(f"Running comparison: {comparison_type}")
        
        findings: List[Dict[str, Any]] = []
        
        if isinstance(scan_run_id, str):
            if scan_run_id not in self._scan_runs:
                raise ValueError(f"Scan run not found: {scan_run_id}")
            
            scan_run = self._scan_runs[scan_run_id]
            
            # Simulate comparison analysis
            for result in scan_run.results:
                if result.state == 'open':
                    findings.append({
                        'type': 'exposed_service',
                        'target': result.target,
                        'port': result.port,
                        'service': result.service,
                    })
        else:
            # Compare two scan runs
            scan_run1_id, scan_run2_id = scan_run_id
            if scan_run1_id not in self._scan_runs or scan_run2_id not in self._scan_runs:
                raise ValueError("One or both scan runs not found")
            
            scan_run1 = self._scan_runs[scan_run1_id]
            scan_run2 = self._scan_runs[scan_run2_id]
            
            # Compare results
            results1_set = {(r.target, r.port) for r in scan_run1.results if r.state == 'open'}
            results2_set = {(r.target, r.port) for r in scan_run2.results if r.state == 'open'}
            
            # New findings
            for target, port in results2_set - results1_set:
                findings.append({
                    'type': 'new_service',
                    'target': target,
                    'port': port,
                })
            
            # Closed services
            for target, port in results1_set - results2_set:
                findings.append({
                    'type': 'closed_service',
                    'target': target,
                    'port': port,
                })
        
        self._logger.info(f"Comparison found {len(findings)} difference(s)")
        return findings
    
    def run_external_lookup(self, scan_run_id: str,
                           providers: Union[str, List[str]]
                           ) -> Dict[str, Any]:
        """
        Look up external intelligence for scan results.
        
        Args:
            scan_run_id: Scan run ID to look up
            providers: Provider name(s) (shodan, censys, all)
            
        Returns:
            External intelligence data
            
        Raises:
            ValueError: If scan run not found
        """
        if scan_run_id not in self._scan_runs:
            raise ValueError(f"Scan run not found: {scan_run_id}")
        
        if isinstance(providers, str):
            if providers == 'all':
                providers = ['shodan', 'censys']
            else:
                providers = [providers]
        
        self._logger.info(f"Looking up external data for {scan_run_id} via {providers}")
        
        external_data: Dict[str, Any] = {
            'scan_run_id': scan_run_id,
            'providers': providers,
            'results': [],
        }
        
        # Simulate external lookups
        for provider in providers:
            external_data['results'].append({
                'provider': provider,
                'results': 0,  # Simulated
                'status': 'success',
            })
        
        self._logger.info(f"External lookup completed")
        return external_data
    
    def generate_report(self, scan_run_id: str, report_format: str = 'html',
                       output_file: Optional[str] = None) -> str:
        """
        Generate a report from scan results.
        
        Args:
            scan_run_id: Scan run ID to report on
            report_format: Report format (html, pdf)
            output_file: Output file path (optional)
            
        Returns:
            Path to generated report file
            
        Raises:
            ValueError: If scan run not found or invalid format
        """
        if scan_run_id not in self._scan_runs:
            raise ValueError(f"Scan run not found: {scan_run_id}")
        
        if report_format not in ('html', 'pdf'):
            raise ValueError(f"Invalid report format: {report_format}")
        
        scan_run = self._scan_runs[scan_run_id]
        
        # Generate default filename if not provided
        if not output_file:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_file = f"report_{scan_run_id}_{timestamp}.{report_format}"
        
        self._logger.info(
            f"Generating {report_format.upper()} report for {scan_run_id}: {output_file}"
        )
        
        # Simulate report generation
        report_content = self._generate_report_content(scan_run, report_format)
        
        # Write to file
        output_path = Path(output_file)
        output_path.write_text(report_content)
        
        self._logger.info(f"Report generated: {output_path.absolute()}")
        return str(output_path.absolute())
    
    def _generate_report_content(self, scan_run: ScanRun, report_format: str) -> str:
        """
        Generate report content.
        
        Args:
            scan_run: Scan run to report on
            report_format: Report format
            
        Returns:
            Report content as string
        """
        if report_format == 'html':
            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>AegisScan Report - {scan_run.id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
    </style>
</head>
<body>
    <h1>AegisScan Report</h1>
    <p><strong>Scan Run ID:</strong> {scan_run.id}</p>
    <p><strong>Scan Type:</strong> {scan_run.scan_type}</p>
    <p><strong>Targets:</strong> {len(scan_run.targets)}</p>
    <p><strong>Results:</strong> {len(scan_run.results)}</p>
    <p><strong>Duration:</strong> {scan_run.duration():.2f}s</p>
    
    <h2>Results Summary</h2>
    <table>
        <tr>
            <th>Target</th>
            <th>Port</th>
            <th>Protocol</th>
            <th>State</th>
            <th>Service</th>
        </tr>
"""
        for result in scan_run.results:
            return_html = f"""        <tr>
            <td>{result.target}</td>
            <td>{result.port}</td>
            <td>{result.protocol}</td>
            <td>{result.state}</td>
            <td>{result.service or 'N/A'}</td>
        </tr>
"""
            return_html += "    </table>\n</body>\n</html>"
            return return_html
        
        else:  # PDF format
            return f"PDF Report for {scan_run.id}\n\nGenerated: {datetime.utcnow()}"
    
    def import_nmap(self, file_path: str,
                   merge_scan_run_id: Optional[str] = None
                   ) -> List[ScanResult]:
        """
        Import results from nmap XML file.
        
        Args:
            file_path: Path to nmap XML file
            merge_scan_run_id: Optional scan run ID to merge with
            
        Returns:
            List of imported results
            
        Raises:
            ValueError: If file not found or parse error
        """
        import_path = Path(file_path)
        
        if not import_path.exists():
            raise ValueError(f"File not found: {file_path}")
        
        self._logger.info(f"Importing nmap XML from: {file_path}")
        
        # Simulate nmap import
        imported_results: List[ScanResult] = []
        
        # In production, would parse XML here
        result = ScanResult(
            target='imported.example.com',
            port=22,
            protocol='tcp',
            state='open',
            service='ssh',
        )
        imported_results.append(result)
        
        if merge_scan_run_id:
            if merge_scan_run_id not in self._scan_runs:
                raise ValueError(f"Scan run not found: {merge_scan_run_id}")
            
            self._scan_runs[merge_scan_run_id].results.extend(imported_results)
            self._logger.info(
                f"Merged {len(imported_results)} result(s) into {merge_scan_run_id}"
            )
        
        self._logger.info(f"Import completed: {len(imported_results)} result(s)")
        return imported_results
    
    def serve(self, host: str = '127.0.0.1', port: int = 8080,
              reload: bool = False) -> None:
        """
        Start web server for AegisScan.
        
        Args:
            host: Host to bind to
            port: Port to bind to
            reload: Enable auto-reload (dev mode)
        """
        self._logger.info(f"Starting web server on {host}:{port}")
        
        try:
            import uvicorn
            
            app_module = 'aegisscan.api:app'
            uvicorn.run(
                app_module,
                host=host,
                port=port,
                reload=reload,
                log_level='info',
            )
        except ImportError:
            self._logger.error(
                "Web server requires uvicorn and FastAPI. "
                "Install with: pip install aegisscan[web]"
            )
            raise
    
    def _save_results(self, scan_run: ScanRun, output_file: str,
                     output_format: str) -> None:
        """
        Save scan results to file.
        
        Args:
            scan_run: Scan run to save
            output_file: Output file path
            output_format: Output format (json, csv, table)
        """
        output_path = Path(output_file)
        
        if output_format == 'json':
            content = json.dumps(scan_run.to_dict(), indent=2, default=str)
        elif output_format == 'csv':
            lines = ['target,port,protocol,state,service']
            for result in scan_run.results:
                lines.append(
                    f'{result.target},{result.port},{result.protocol},'
                    f'{result.state},{result.service or ""}'
                )
            content = '\n'.join(lines)
        else:  # table
            lines = [
                f"Scan Run: {scan_run.id}",
                f"Type: {scan_run.scan_type}",
                f"Duration: {scan_run.duration():.2f}s",
                f"Results: {len(scan_run.results)}",
                "",
                f"{'Target':<20} {'Port':<8} {'Protocol':<10} {'State':<12} {'Service':<20}",
                "-" * 70,
            ]
            for result in scan_run.results:
                lines.append(
                    f"{result.target:<20} {result.port:<8} {result.protocol:<10} "
                    f"{result.state:<12} {result.service or 'N/A':<20}"
                )
            content = '\n'.join(lines)
        
        output_path.write_text(content)
        self._logger.info(f"Results saved to: {output_path.absolute()}")
