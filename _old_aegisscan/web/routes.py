"""
API routes for the AegisScan web application.

Implements endpoints for:
- Dashboard and HTML rendering
- Scan management (list, create, details)
- Host inventory and details
- Port and service information
- Findings and vulnerability reporting
- Scan comparisons and diffs
- Nmap import functionality
- Report generation
- Statistics and metrics
"""

import io
import logging
from datetime import datetime, timedelta
from typing import Annotated, Any, Optional
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Request, UploadFile, Query
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter()


# ============================================================================
# Pydantic Models (Request/Response Schemas)
# ============================================================================


class ScanConfig(BaseModel):
    """Configuration for initiating a new scan."""

    name: str = Field(..., min_length=1, max_length=255, description="Scan name/description")
    targets: str = Field(..., min_length=1, description="Target hosts (CIDR, IP, hostname)")
    port_range: str = Field(default="1-65535", description="Port range to scan (e.g., 1-1024, 22,80,443)")
    scan_type: str = Field(
        default="syn",
        description="Scan type: syn (SYN scan), connect (TCP connect), service (service detection)"
    )
    intensity: int = Field(default=4, ge=1, le=5, description="Scan intensity (1-5)")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Production Network Scan",
                "targets": "192.168.1.0/24",
                "port_range": "1-1024",
                "scan_type": "syn",
                "intensity": 4
            }
        }


class ScanRun(BaseModel):
    """Scan run information."""

    id: str
    name: str
    status: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    targets: str
    port_range: str
    scan_type: str
    hosts_scanned: int = 0
    ports_found: int = 0
    services_detected: int = 0

    class Config:
        json_schema_extra = {
            "example": {
                "id": "scan-001",
                "name": "Production Network Scan",
                "status": "completed",
                "created_at": "2026-03-05T10:00:00",
                "started_at": "2026-03-05T10:01:00",
                "completed_at": "2026-03-05T10:45:00",
                "targets": "192.168.1.0/24",
                "port_range": "1-1024",
                "scan_type": "syn",
                "hosts_scanned": 10,
                "ports_found": 42,
                "services_detected": 15
            }
        }


class Port(BaseModel):
    """Port information."""

    number: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="tcp")
    state: str = Field(description="open, closed, filtered")
    service: Optional[str] = None
    banner: Optional[str] = None


class TLSInfo(BaseModel):
    """TLS certificate information."""

    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    is_expired: bool = False


class Host(BaseModel):
    """Host information."""

    id: str
    ip_address: str
    hostname: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    os: Optional[str] = None
    open_ports: int = 0
    scan_run_id: str
    discovered_at: datetime
    updated_at: datetime

    class Config:
        json_schema_extra = {
            "example": {
                "id": "host-001",
                "ip_address": "192.168.1.10",
                "hostname": "server1.example.com",
                "tags": ["web", "critical"],
                "os": "Linux 5.10",
                "open_ports": 3,
                "scan_run_id": "scan-001",
                "discovered_at": "2026-03-05T10:01:00",
                "updated_at": "2026-03-05T10:45:00"
            }
        }


class HostDetail(Host):
    """Extended host information with ports and services."""

    ports: list[Port] = Field(default_factory=list)
    tls_info: Optional[dict[str, TLSInfo]] = Field(default_factory=dict)
    notes: Optional[str] = None


class Finding(BaseModel):
    """Vulnerability or security finding."""

    id: str
    host_id: str
    port: Optional[int] = None
    severity: str = Field(description="critical, high, medium, low, info")
    type: str = Field(description="Finding type: service_outdated, weak_cipher, etc.")
    title: str
    description: str
    remediation: Optional[str] = None
    discovered_at: datetime
    status: str = Field(default="open", description="open, in_progress, resolved")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "find-001",
                "host_id": "host-001",
                "port": 443,
                "severity": "high",
                "type": "weak_cipher",
                "title": "Weak TLS Cipher Suite Detected",
                "description": "Server supports weak TLS ciphers",
                "remediation": "Disable weak ciphers in server configuration",
                "discovered_at": "2026-03-05T10:45:00",
                "status": "open"
            }
        }


class DashboardStats(BaseModel):
    """Dashboard statistics."""

    total_hosts: int = 0
    total_open_ports: int = 0
    critical_findings: int = 0
    total_scan_runs: int = 0
    recent_scans: list[ScanRun] = Field(default_factory=list)
    hosts_with_critical: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    avg_scan_duration_minutes: float = 0


class PortComparison(BaseModel):
    """Port discovery comparison between scan methods."""

    connect_ports: list[int]
    syn_ports: list[int]
    only_in_connect: list[int]
    only_in_syn: list[int]
    discrepancies: int


class ExposureDiff(BaseModel):
    """Internal vs external exposure difference."""

    internal_only: list[dict[str, Any]]
    external_only: list[dict[str, Any]]
    both: list[dict[str, Any]]
    exposure_level: str


class ImportResult(BaseModel):
    """Result of nmap import operation."""

    hosts_imported: int
    ports_discovered: int
    services_detected: int
    scan_run_id: str


class ReportFormat(BaseModel):
    """Generated report metadata."""

    scan_run_id: str
    generated_at: datetime
    format: str = "html"
    filename: str


# ============================================================================
# Dashboard Routes
# ============================================================================


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> str:
    """
    Serve the main dashboard HTML page.

    Returns:
        HTML content of the dashboard.
    """
    try:
        templates = request.app.state.templates
        return templates.get_template("dashboard.html").render()
    except Exception as e:
        logger.error(f"Error rendering dashboard: {e}")
        raise HTTPException(status_code=500, detail="Failed to render dashboard")


# ============================================================================
# Scan Management Routes
# ============================================================================


@router.get("/api/scan-runs", response_model=list[ScanRun])
async def list_scan_runs(
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    status: Optional[str] = None,
) -> list[ScanRun]:
    """
    List all scan runs with optional filtering.

    Args:
        limit: Maximum number of results (1-100)
        offset: Number of results to skip
        status: Filter by status (pending, running, completed, failed)

    Returns:
        List of scan run objects.
    """
    # Mock data - replace with actual database queries
    mock_scans = [
        ScanRun(
            id="scan-001",
            name="Production Network Scan",
            status="completed",
            created_at=datetime.now() - timedelta(days=1),
            started_at=datetime.now() - timedelta(days=1, hours=1),
            completed_at=datetime.now() - timedelta(days=1, minutes=45),
            targets="192.168.1.0/24",
            port_range="1-1024",
            scan_type="syn",
            hosts_scanned=15,
            ports_found=87,
            services_detected=32,
        ),
        ScanRun(
            id="scan-002",
            name="DMZ Scan",
            status="running",
            created_at=datetime.now() - timedelta(hours=2),
            started_at=datetime.now() - timedelta(minutes=30),
            targets="10.0.0.0/24",
            port_range="1-65535",
            scan_type="syn",
            hosts_scanned=5,
            ports_found=23,
            services_detected=8,
        ),
    ]

    filtered = mock_scans
    if status:
        filtered = [s for s in filtered if s.status == status]

    return filtered[offset : offset + limit]


@router.post("/api/scan", response_model=ScanRun)
async def start_scan(config: ScanConfig, background_tasks: BackgroundTasks) -> ScanRun:
    """
    Start a new network scan.

    Creates a new scan run and queues it for background processing.

    Args:
        config: Scan configuration
        background_tasks: FastAPI background task manager

    Returns:
        Created scan run object.
    """
    scan_id = f"scan-{uuid4().hex[:8]}"
    now = datetime.now()

    scan = ScanRun(
        id=scan_id,
        name=config.name,
        status="pending",
        created_at=now,
        targets=config.targets,
        port_range=config.port_range,
        scan_type=config.scan_type,
    )

    # Queue background scan task
    background_tasks.add_task(_execute_scan, scan_id, config)

    logger.info(f"Scan {scan_id} queued: {config.name}")
    return scan


async def _execute_scan(scan_id: str, config: ScanConfig) -> None:
    """
    Background task to execute a scan.

    Args:
        scan_id: Scan run ID
        config: Scan configuration
    """
    logger.info(f"Starting scan execution: {scan_id}")
    # Actual scan implementation would go here
    await _simulate_scan_execution(scan_id)


async def _simulate_scan_execution(scan_id: str) -> None:
    """
    Simulate scan execution for demo purposes.

    Args:
        scan_id: Scan run ID
    """
    # In production, this would perform actual network scanning
    logger.debug(f"Scan {scan_id} completed (simulated)")


@router.get("/api/scan-runs/{scan_run_id}", response_model=ScanRun)
async def get_scan_run(scan_run_id: str) -> ScanRun:
    """
    Get details of a specific scan run.

    Args:
        scan_run_id: Scan run identifier

    Returns:
        Scan run object.

    Raises:
        HTTPException: If scan run not found.
    """
    # Mock implementation
    if scan_run_id == "scan-001":
        return ScanRun(
            id="scan-001",
            name="Production Network Scan",
            status="completed",
            created_at=datetime.now() - timedelta(days=1),
            started_at=datetime.now() - timedelta(days=1, hours=1),
            completed_at=datetime.now() - timedelta(days=1, minutes=45),
            targets="192.168.1.0/24",
            port_range="1-1024",
            scan_type="syn",
            hosts_scanned=15,
            ports_found=87,
            services_detected=32,
        )

    raise HTTPException(status_code=404, detail="Scan run not found")


# ============================================================================
# Host Inventory Routes
# ============================================================================


@router.get("/api/hosts", response_model=list[Host])
async def list_hosts(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    tag: Optional[str] = None,
    ip_range: Optional[str] = None,
    scan_run_id: Optional[str] = None,
) -> list[Host]:
    """
    List discovered hosts with optional filtering.

    Args:
        limit: Maximum number of results (1-500)
        offset: Number of results to skip
        tag: Filter by host tag
        ip_range: Filter by IP range (CIDR notation)
        scan_run_id: Filter by scan run

    Returns:
        List of host objects.
    """
    # Mock data
    mock_hosts = [
        Host(
            id="host-001",
            ip_address="192.168.1.10",
            hostname="web1.example.com",
            tags=["web", "production"],
            os="Linux 5.10",
            open_ports=3,
            scan_run_id="scan-001",
            discovered_at=datetime.now() - timedelta(days=1),
            updated_at=datetime.now() - timedelta(hours=1),
        ),
        Host(
            id="host-002",
            ip_address="192.168.1.20",
            hostname="db1.example.com",
            tags=["database", "critical"],
            os="Linux 5.15",
            open_ports=2,
            scan_run_id="scan-001",
            discovered_at=datetime.now() - timedelta(days=1),
            updated_at=datetime.now() - timedelta(hours=1),
        ),
    ]

    filtered = mock_hosts
    if tag:
        filtered = [h for h in filtered if tag in h.tags]
    if scan_run_id:
        filtered = [h for h in filtered if h.scan_run_id == scan_run_id]

    return filtered[offset : offset + limit]


@router.get("/api/hosts/{host_id}", response_model=HostDetail)
async def get_host_detail(host_id: str) -> HostDetail:
    """
    Get detailed information about a specific host.

    Includes ports, services, TLS certificates, and security findings.

    Args:
        host_id: Host identifier

    Returns:
        Detailed host object with ports and services.

    Raises:
        HTTPException: If host not found.
    """
    if host_id == "host-001":
        return HostDetail(
            id="host-001",
            ip_address="192.168.1.10",
            hostname="web1.example.com",
            tags=["web", "production"],
            os="Linux 5.10",
            open_ports=3,
            scan_run_id="scan-001",
            discovered_at=datetime.now() - timedelta(days=1),
            updated_at=datetime.now() - timedelta(hours=1),
            ports=[
                Port(number=22, protocol="tcp", state="open", service="ssh", banner="OpenSSH 8.2p1"),
                Port(number=80, protocol="tcp", state="open", service="http", banner="nginx/1.18"),
                Port(number=443, protocol="tcp", state="open", service="https", banner="nginx/1.18"),
            ],
            tls_info={
                "443": TLSInfo(
                    issuer="Let's Encrypt",
                    subject="web1.example.com",
                    valid_from=datetime.now() - timedelta(days=90),
                    valid_until=datetime.now() + timedelta(days=90),
                    days_until_expiry=90,
                    is_expired=False,
                )
            },
            notes="Primary web server",
        )

    raise HTTPException(status_code=404, detail="Host not found")


@router.get("/api/hosts/{host_id}/ports", response_model=list[Port])
async def get_host_ports(host_id: str) -> list[Port]:
    """
    Get list of ports for a specific host.

    Args:
        host_id: Host identifier

    Returns:
        List of port objects.

    Raises:
        HTTPException: If host not found.
    """
    if host_id == "host-001":
        return [
            Port(number=22, protocol="tcp", state="open", service="ssh", banner="OpenSSH 8.2p1"),
            Port(number=80, protocol="tcp", state="open", service="http", banner="nginx/1.18"),
            Port(number=443, protocol="tcp", state="open", service="https", banner="nginx/1.18"),
        ]

    raise HTTPException(status_code=404, detail="Host not found")


# ============================================================================
# Findings and Vulnerability Routes
# ============================================================================


@router.get("/api/findings", response_model=list[Finding])
async def list_findings(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: Optional[str] = None,
    host_id: Optional[str] = None,
    status: Optional[str] = None,
) -> list[Finding]:
    """
    List security findings with optional filtering.

    Args:
        limit: Maximum number of results (1-500)
        offset: Number of results to skip
        severity: Filter by severity (critical, high, medium, low, info)
        host_id: Filter by host
        status: Filter by status (open, in_progress, resolved)

    Returns:
        List of finding objects sorted by severity.
    """
    # Mock findings
    mock_findings = [
        Finding(
            id="find-001",
            host_id="host-001",
            port=443,
            severity="high",
            type="weak_cipher",
            title="Weak TLS Cipher Suite Detected",
            description="Server supports weak TLS ciphers (DES, RC4)",
            remediation="Disable weak ciphers in server configuration",
            discovered_at=datetime.now() - timedelta(days=1),
            status="open",
        ),
        Finding(
            id="find-002",
            host_id="host-001",
            port=22,
            severity="medium",
            type="service_outdated",
            title="Outdated SSH Version",
            description="SSH service version is outdated",
            remediation="Update to latest stable SSH version",
            discovered_at=datetime.now() - timedelta(days=1),
            status="open",
        ),
        Finding(
            id="find-003",
            host_id="host-002",
            port=3306,
            severity="critical",
            type="exposed_database",
            title="Database Exposed to Network",
            description="Database port accessible from non-admin networks",
            remediation="Restrict database access with firewall rules",
            discovered_at=datetime.now() - timedelta(days=2),
            status="in_progress",
        ),
    ]

    filtered = mock_findings
    if severity:
        filtered = [f for f in filtered if f.severity == severity]
    if host_id:
        filtered = [f for f in filtered if f.host_id == host_id]
    if status:
        filtered = [f for f in filtered if f.status == status]

    # Sort by severity level
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    filtered.sort(key=lambda f: severity_order.get(f.severity, 5))

    return filtered[offset : offset + limit]


# ============================================================================
# Scan Comparison Routes
# ============================================================================


@router.get("/api/diff/connect-vs-syn/{scan_run_id}", response_model=PortComparison)
async def compare_connect_vs_syn(scan_run_id: str) -> PortComparison:
    """
    Compare port discovery results between TCP connect and SYN scan methods.

    Returns discrepancies that may indicate filtering or firewalls.

    Args:
        scan_run_id: Scan run identifier

    Returns:
        Comparison data with discovered ports and discrepancies.

    Raises:
        HTTPException: If scan run not found.
    """
    if scan_run_id == "scan-001":
        return PortComparison(
            connect_ports=[22, 80, 443, 8080],
            syn_ports=[22, 80, 443],
            only_in_connect=[8080],
            only_in_syn=[],
            discrepancies=1,
        )

    raise HTTPException(status_code=404, detail="Scan run not found")


@router.get("/api/diff/internal-vs-external/{scan_run_id}", response_model=ExposureDiff)
async def compare_internal_vs_external(scan_run_id: str) -> ExposureDiff:
    """
    Compare internal vs external exposure for a scan run.

    Shows services exposed only internally, only externally, or both.

    Args:
        scan_run_id: Scan run identifier

    Returns:
        Exposure difference data.

    Raises:
        HTTPException: If scan run not found.
    """
    if scan_run_id == "scan-001":
        return ExposureDiff(
            internal_only=[
                {"host": "192.168.1.20", "port": 3306, "service": "mysql"},
            ],
            external_only=[
                {"host": "10.0.0.5", "port": 8080, "service": "http-proxy"},
            ],
            both=[
                {"host": "192.168.1.10", "port": 443, "service": "https"},
            ],
            exposure_level="medium",
        )

    raise HTTPException(status_code=404, detail="Scan run not found")


# ============================================================================
# Import Routes
# ============================================================================


@router.post("/api/import/nmap", response_model=ImportResult)
async def import_nmap_xml(file: UploadFile = File(...)) -> ImportResult:
    """
    Import scan results from Nmap XML file.

    Parses nmap XML output and creates hosts, ports, and services.

    Args:
        file: Nmap XML file upload

    Returns:
        Import result with statistics.

    Raises:
        HTTPException: If file parsing fails.
    """
    if not file.filename.endswith(".xml"):
        raise HTTPException(status_code=400, detail="File must be XML format")

    try:
        contents = await file.read()
        # Parse XML and import data
        # This would integrate with actual nmap parsing logic

        return ImportResult(
            hosts_imported=5,
            ports_discovered=32,
            services_detected=12,
            scan_run_id=f"imported-{uuid4().hex[:8]}",
        )
    except Exception as e:
        logger.error(f"Nmap import failed: {e}")
        raise HTTPException(status_code=400, detail="Failed to parse nmap XML file")


# ============================================================================
# Report Generation Routes
# ============================================================================


@router.get("/api/reports/{scan_run_id}/html")
async def generate_html_report(scan_run_id: str) -> FileResponse:
    """
    Generate and return an HTML report for a scan run.

    Creates a comprehensive HTML report with findings, statistics, and recommendations.

    Args:
        scan_run_id: Scan run identifier

    Returns:
        HTML file response.

    Raises:
        HTTPException: If scan run not found.
    """
    try:
        # Generate HTML report
        html_content = _generate_html_report(scan_run_id)

        # Return as file
        report_bytes = html_content.encode("utf-8")
        return FileResponse(
            io.BytesIO(report_bytes),
            media_type="text/html",
            filename=f"aegisscan-report-{scan_run_id}.html",
        )
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")


def _generate_html_report(scan_run_id: str) -> str:
    """
    Generate HTML report content.

    Args:
        scan_run_id: Scan run identifier

    Returns:
        HTML content string.
    """
    now = datetime.now().isoformat()

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>AegisScan Report - {scan_run_id}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .header {{ background: #1a1a2e; color: white; padding: 20px; margin-bottom: 30px; }}
            .section {{ background: white; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .severity-critical {{ color: #dc3545; font-weight: bold; }}
            .severity-high {{ color: #fd7e14; font-weight: bold; }}
            .severity-medium {{ color: #ffc107; font-weight: bold; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }}
            th {{ background: #f8f9fa; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>AegisScan Security Report</h1>
            <p>Scan Run: {scan_run_id}</p>
            <p>Generated: {now}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>This report documents the findings from the network security scan.</p>
            <ul>
                <li>Total Hosts: 15</li>
                <li>Open Ports: 87</li>
                <li>Services Detected: 32</li>
                <li>Critical Findings: 2</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>Findings by Severity</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                <tr>
                    <td><span class="severity-critical">Critical</span></td>
                    <td>2</td>
                </tr>
                <tr>
                    <td><span class="severity-high">High</span></td>
                    <td>5</td>
                </tr>
                <tr>
                    <td><span class="severity-medium">Medium</span></td>
                    <td>12</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ol>
                <li>Address critical findings immediately</li>
                <li>Schedule remediation for high-severity items</li>
                <li>Implement network access controls</li>
            </ol>
        </div>
    </body>
    </html>
    """


# ============================================================================
# Dashboard Statistics Routes
# ============================================================================


@router.get("/api/stats", response_model=DashboardStats)
async def get_dashboard_stats() -> DashboardStats:
    """
    Get dashboard statistics and metrics.

    Returns aggregated data for the dashboard overview.

    Returns:
        Dashboard statistics object.
    """
    return DashboardStats(
        total_hosts=47,
        total_open_ports=234,
        critical_findings=3,
        total_scan_runs=12,
        hosts_with_critical=2,
        findings_by_severity={
            "critical": 3,
            "high": 8,
            "medium": 15,
            "low": 23,
            "info": 5,
        },
        avg_scan_duration_minutes=34.5,
        recent_scans=[
            ScanRun(
                id="scan-001",
                name="Production Network Scan",
                status="completed",
                created_at=datetime.now() - timedelta(days=1),
                started_at=datetime.now() - timedelta(days=1, hours=1),
                completed_at=datetime.now() - timedelta(days=1, minutes=45),
                targets="192.168.1.0/24",
                port_range="1-1024",
                scan_type="syn",
                hosts_scanned=15,
                ports_found=87,
                services_detected=32,
            ),
        ],
    )
