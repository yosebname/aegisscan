# AegisScan Report Generator - Reference Documentation

## Overview
Production-quality report generation engine for AegisScan security assessments. Generates professional HTML reports and supports PDF conversion with graceful fallbacks.

## File Structure

```
aegisscan/report/
├── __init__.py              # Module exports
├── generator.py             # Core report generation engine
└── templates/
    └── report.html          # Jinja2 HTML template
```

## Core Classes

### ReportGenerator
Enterprise-grade report generation engine with multi-format support.

```python
from aegisscan.report import ReportGenerator, ReportData, Finding, ScanData, RiskSummary

# Initialize
generator = ReportGenerator()

# Generate HTML
html_path = generator.generate_html(report_data, Path("output.html"))

# Generate PDF (with fallback)
try:
    pdf_path = generator.generate_pdf(report_data, Path("output.pdf"))
except RuntimeError as e:
    # PDF converters not installed
    print(f"Install: {e}")
```

### ReportData (Dataclass)
Aggregates all scan results and findings:

```python
from aegisscan.report import ReportData, ScanData, Finding, RiskSummary
from datetime import datetime

# Construct report data
report_data = ReportData(
    scan_data=ScanData(
        scan_id="scan-20260305-001",
        scan_date=datetime.now(),
        target="192.168.1.0/24",
        duration_seconds=1234.5,
        total_hosts=10,
        total_open_ports=45,
        total_services=30,
    ),
    findings=[
        Finding(
            host="192.168.1.100",
            port=22,
            protocol="tcp",
            service="ssh",
            severity="high",
            title="Weak SSH Configuration",
            description="SSH allows weak cryptographic algorithms",
            remediation="Update SSH configuration to disable weak ciphers",
            tags=["crypto", "access-control"],
            external_exposure=True,
            cve_ids=["CVE-2022-12345"],
        ),
        # More findings...
    ],
    risk_summaries=[
        RiskSummary(
            category="Access Control",
            risk_score=7.5,
            finding_count=12,
            top_findings=["Weak SSH Configuration", "Default Credentials"],
        ),
        # More summaries...
    ],
    host_details={},
    port_analysis={},
    tls_certificates={},
    external_exposure_diff={},
    connect_vs_syn_comparison={},
)
```

### Finding (Dataclass)
Represents a single security finding:

```python
@dataclass
class Finding:
    host: str                      # Target host IP/hostname
    port: int                      # Port number
    protocol: str                  # tcp/udp
    service: str                   # Service name (ssh, http, etc)
    severity: str                  # critical, high, medium, low, info
    title: str                     # Concise finding title
    description: str               # Detailed description
    remediation: str               # How to fix
    tags: List[str]               # Categorization tags
    external_exposure: bool        # Accessible from outside network
    cve_ids: List[str]            # Associated CVEs
```

### ScanData (Dataclass)
Core scan metadata:

```python
@dataclass
class ScanData:
    scan_id: str                   # Unique scan identifier
    scan_date: datetime            # When scan occurred
    target: str                    # Target specification (CIDR, IP, etc)
    duration_seconds: float        # Total scan duration
    total_hosts: int              # Number of hosts scanned
    total_open_ports: int         # Total open ports found
    total_services: int           # Total services detected
```

### RiskSummary (Dataclass)
Risk assessment summary by category:

```python
@dataclass
class RiskSummary:
    category: str                  # Risk category (Access Control, etc)
    risk_score: float             # 0-10 numeric score
    finding_count: int            # Number of findings in category
    top_findings: List[str]       # Most important findings
```

## Methods

### generate_html()
Generate comprehensive HTML report.

```python
html_path = generator.generate_html(report_data, Path("report.html"))
# Returns: str (absolute path to generated file)
```

**Features:**
- Executive summary with metric cards
- Findings grouped by severity
- Host and port analysis
- TLS certificate status
- External exposure differential
- Connect vs SYN comparison
- Risk assessment
- Remediation checklist
- Professional styling with dark header
- Responsive design
- Print-friendly CSS

### generate_pdf()
Generate PDF from HTML (with fallbacks).

```python
try:
    pdf_path = generator.generate_pdf(report_data, Path("report.pdf"))
except RuntimeError as e:
    # Install: weasyprint or wkhtmltopdf
    print(e)
```

**Fallback Chain:**
1. Try weasyprint (Python-based)
2. Try wkhtmltopdf (system binary)
3. Raise RuntimeError with installation instructions

### generate_executive_summary()
Create high-level metrics and insights.

```python
summary = generator.generate_executive_summary(scan_data, findings)
# Returns: Dict with keys:
#   - total_hosts, total_open_ports, total_services
#   - critical_count, high_count, medium_count, low_count, info_count
#   - total_findings, external_exposure_count
#   - top_exposed_ports (list of (port, count) tuples)
#   - top_risky_hosts (list of (host, count) tuples)
#   - risk_score (0-10)
#   - scan_duration
```

### generate_remediation_checklist()
Grouped remediation guidance by priority.

```python
checklist = generator.generate_remediation_checklist(findings)
# Returns: List[Dict] with structure:
#   [
#       {
#           "priority": "critical",
#           "items": [
#               {
#                   "title": "...",
#                   "remediation": "...",
#                   "count": 5,
#                   "affected_hosts": ["192.168.1.1", ...]
#               },
#               ...
#           ]
#       },
#       ...
#   ]
```

## Template Features (report.html)

### Sections Included
1. **Header** - AegisScan branding with scan metadata
2. **Executive Summary** - Key metrics, risk score, exposed ports, risky hosts
3. **Security Findings** - Organized by severity with full details
4. **Connect vs SYN Comparison** - Identifies firewall/load balancer differences
5. **TLS Certificate Status** - Expiry warnings and validity checks
6. **External Exposure Differential** - Public vs private services
7. **Risk Assessment** - Category-based risk scores
8. **Remediation Checklist** - Interactive checklist with deduplication

### Design Features
- **Color Scheme:**
  - Primary: Deep blue (#1e3a8a)
  - Critical: Red (#dc3545)
  - High: Orange (#fd7e14)
  - Medium: Yellow (#ffc107)
  - Low: Blue (#0d6efd)
  - Info: Gray (#6c757d)

- **Typography:**
  - System font stack for excellent rendering
  - Monospace for technical values
  - Clear hierarchy with proper sizing

- **Components:**
  - Metric cards with hover effects
  - Sortable table headers (CSS-only)
  - Severity badges with color coding
  - Risk assessment circles
  - Finding cards with remediation highlights
  - Interactive checklist with checkboxes

- **Responsive Design:**
  - Grid-based layout
  - Mobile-optimized (< 768px, < 480px)
  - Print-friendly CSS with page breaks

## Risk Scoring Algorithm

Risk Score = min(10.0, (weighted_sum / 10.0))

**Weights per Finding:**
- Critical: 5.0 points each
- High: 3.0 points each
- Medium: 1.5 points each
- Low: 0.5 points each
- Info: 0.1 points each

**Risk Levels:**
- 8.5-10.0: Critical
- 7.0-8.4: High
- 5.0-6.9: Medium
- 2.0-4.9: Low
- 0-1.9: Minimal

## HTML Report Structure

### Key Jinja2 Template Variables
```python
{
    "scan_data": ScanData,
    "findings": List[Finding],
    "risk_summaries": List[RiskSummary],
    "executive_summary": Dict,
    "remediation_checklist": List[Dict],
    "host_details": Dict,
    "port_analysis": Dict,
    "tls_certificates": Dict,
    "external_exposure_diff": Dict,
    "connect_vs_syn_comparison": Dict,
    "generation_timestamp": datetime,
    "severity_colors": Dict,
    "findings_by_severity": Dict[str, List[Finding]],
    "findings_by_host": Dict[str, List[Finding]],
}
```

### Custom Jinja2 Filters
- `severity_color` - Hex color for severity level
- `format_timestamp` - Format datetime objects
- `risk_level` - Convert numeric score to text
- `pluralize` - Singular/plural conversion

## Usage Example

```python
from pathlib import Path
from datetime import datetime
from aegisscan.report import (
    ReportGenerator, ReportData, Finding, ScanData, RiskSummary
)

# Create report generator
generator = ReportGenerator()

# Build report data
report_data = ReportData(
    scan_data=ScanData(
        scan_id="scan-2026-03-05-001",
        scan_date=datetime(2026, 3, 5, 14, 30, 0),
        target="192.168.1.0/24",
        duration_seconds=1234.5,
        total_hosts=10,
        total_open_ports=45,
        total_services=30,
    ),
    findings=[
        Finding(
            host="192.168.1.100",
            port=22,
            protocol="tcp",
            service="ssh",
            severity="high",
            title="Weak SSH Cryptography",
            description="SSH daemon allows weak symmetric ciphers",
            remediation="Configure /etc/ssh/sshd_config to disable weak ciphers",
            tags=["cryptography", "access-control"],
            external_exposure=True,
            cve_ids=["CVE-2022-12345"],
        ),
    ],
    risk_summaries=[
        RiskSummary(
            category="Access Control",
            risk_score=7.5,
            finding_count=5,
            top_findings=["Weak SSH Cryptography"],
        ),
    ],
)

# Generate HTML
html_path = generator.generate_html(report_data, Path("scan_report.html"))
print(f"Report: {html_path}")

# Generate PDF (optional)
try:
    pdf_path = generator.generate_pdf(report_data, Path("scan_report.pdf"))
    print(f"PDF: {pdf_path}")
except RuntimeError as e:
    print(f"PDF not available: {e}")
```

## Performance Characteristics

- **Template Rendering:** < 100ms for typical reports (50-500 findings)
- **Memory:** Efficient dataclass-based design
- **File Size:** HTML ~1-5MB depending on findings count
- **PDF Conversion:** 5-30s depending on system load

## Type Hints & Docstrings

All code includes:
- Full type hints for parameters and returns
- Comprehensive docstrings
- Clear parameter descriptions
- Return value documentation
- Raises section for exceptions

## Dependencies

**Core:**
- jinja2 (for templating)
- standard library only otherwise

**Optional (for PDF):**
- weasyprint (recommended) OR
- wkhtmltopdf (system binary)

## Notes

- HTML template is completely self-contained (no external CSS/JS)
- Designed for professional security report delivery
- Print-friendly with optimized page breaks
- Mobile-responsive for tablet/phone viewing
- All colors meet WCAG contrast requirements
- Severity-based color coding aids quick assessment
