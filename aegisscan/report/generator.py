"""
Report Generation Engine for AegisScan

Provides comprehensive report generation capabilities including HTML and PDF outputs,
executive summaries, risk assessments, and remediation guidance.
"""

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

from jinja2 import Environment, PackageLoader, select_autoescape

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a single security finding."""
    host: str
    port: int
    protocol: str
    service: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    remediation: str
    tags: List[str] = field(default_factory=list)
    external_exposure: bool = False
    cve_ids: List[str] = field(default_factory=list)


@dataclass
class RiskSummary:
    """Represents a risk assessment summary."""
    category: str
    risk_score: float  # 0-10
    finding_count: int
    top_findings: List[str] = field(default_factory=list)


@dataclass
class ScanData:
    """Represents core scan metadata."""
    scan_id: str
    scan_date: datetime
    target: str
    duration_seconds: float
    total_hosts: int
    total_open_ports: int
    total_services: int


@dataclass
class ReportData:
    """
    Aggregates all scan results, findings, and risk scores.
    
    This dataclass serves as the primary data container for report generation,
    combining scan metadata, individual findings, and risk assessments.
    """
    scan_data: ScanData
    findings: List[Finding]
    risk_summaries: List[RiskSummary]
    host_details: Dict[str, Any] = field(default_factory=dict)
    port_analysis: Dict[int, Any] = field(default_factory=dict)
    tls_certificates: Dict[str, Any] = field(default_factory=dict)
    external_exposure_diff: Dict[str, Any] = field(default_factory=dict)
    connect_vs_syn_comparison: Dict[str, Any] = field(default_factory=dict)


class ReportGenerator:
    """
    Enterprise-grade report generation engine for security scan results.
    
    Supports multiple output formats (HTML, PDF) with professional styling,
    comprehensive data analysis, and actionable remediation guidance.
    """

    # Severity color mapping for styling
    SEVERITY_COLORS = {
        "critical": "#dc3545",  # Red
        "high": "#fd7e14",      # Orange
        "medium": "#ffc107",    # Yellow
        "low": "#0d6efd",       # Blue
        "info": "#6c757d",      # Gray
    }

    # Severity numeric weights for sorting
    SEVERITY_WEIGHTS = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }

    def __init__(self, template_dir: Optional[Path] = None) -> None:
        """
        Initialize the report generator.
        
        Args:
            template_dir: Optional path to custom templates directory.
                         Defaults to built-in templates.
        
        Raises:
            FileNotFoundError: If template directory does not exist.
        """
        if template_dir is None:
            # Use built-in templates from package
            template_dir = Path(__file__).parent / "templates"
        
        if not template_dir.exists():
            raise FileNotFoundError(f"Template directory not found: {template_dir}")
        
        self.template_dir = template_dir
        self._setup_jinja_environment()

    def _setup_jinja_environment(self) -> None:
        """Configure Jinja2 environment for template rendering."""
        # Use package loader for built-in templates
        try:
            self.env = Environment(
                loader=PackageLoader("aegisscan.report", "templates"),
                autoescape=select_autoescape(["html", "xml"]),
                trim_blocks=True,
                lstrip_blocks=True,
            )
        except Exception:
            # Fallback to filesystem loader
            from jinja2 import FileSystemLoader
            self.env = Environment(
                loader=FileSystemLoader(str(self.template_dir)),
                autoescape=select_autoescape(["html", "xml"]),
                trim_blocks=True,
                lstrip_blocks=True,
            )
        
        # Register custom filters
        self.env.filters["severity_color"] = self._severity_color
        self.env.filters["format_timestamp"] = self._format_timestamp
        self.env.filters["risk_level"] = self._risk_level
        self.env.filters["pluralize"] = self._pluralize

    def generate_html(
        self,
        report_data: ReportData,
        output_path: Path,
    ) -> str:
        """
        Generate a comprehensive HTML report.
        
        Args:
            report_data: Aggregated scan results and findings.
            output_path: Path where HTML file will be written.
        
        Returns:
            Path to generated HTML file.
        
        Raises:
            IOError: If file write fails.
            ValueError: If report_data is invalid.
        """
        if not report_data.findings:
            logger.warning("Report generated with no findings")
        
        # Generate report sections
        executive_summary = self.generate_executive_summary(report_data.scan_data, report_data.findings)
        remediation_checklist = self.generate_remediation_checklist(report_data.findings)
        
        # Prepare template context
        context = {
            "scan_data": report_data.scan_data,
            "findings": report_data.findings,
            "risk_summaries": report_data.risk_summaries,
            "executive_summary": executive_summary,
            "remediation_checklist": remediation_checklist,
            "host_details": report_data.host_details,
            "port_analysis": report_data.port_analysis,
            "tls_certificates": report_data.tls_certificates,
            "external_exposure_diff": report_data.external_exposure_diff,
            "connect_vs_syn_comparison": report_data.connect_vs_syn_comparison,
            "generation_timestamp": datetime.now(),
            "severity_colors": self.SEVERITY_COLORS,
            "findings_by_severity": self._group_findings_by_severity(report_data.findings),
            "findings_by_host": self._group_findings_by_host(report_data.findings),
        }
        
        # Render template
        try:
            template = self.env.get_template("report.html")
            html_content = template.render(**context)
        except Exception as e:
            logger.error(f"Failed to render HTML template: {e}")
            raise ValueError(f"Template rendering failed: {e}")
        
        # Write to file
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(html_content, encoding="utf-8")
            logger.info(f"HTML report generated: {output_path}")
            return str(output_path.absolute())
        except IOError as e:
            logger.error(f"Failed to write HTML report: {e}")
            raise

    def generate_pdf(
        self,
        report_data: ReportData,
        output_path: Path,
    ) -> str:
        """
        Generate a PDF report from HTML using available converters.
        
        Attempts to use weasyprint or wkhtmltopdf if available.
        Falls back to graceful error message if no converter is present.
        
        Args:
            report_data: Aggregated scan results and findings.
            output_path: Path where PDF file will be written.
        
        Returns:
            Path to generated PDF file.
        
        Raises:
            RuntimeError: If no PDF converter is available.
        """
        output_path = Path(output_path)
        
        # Generate HTML first
        html_path = output_path.with_suffix(".html")
        self.generate_html(report_data, html_path)
        
        # Try weasyprint first
        if self._try_weasyprint(str(html_path), str(output_path)):
            return str(output_path.absolute())
        
        # Try wkhtmltopdf second
        if self._try_wkhtmltopdf(str(html_path), str(output_path)):
            return str(output_path.absolute())
        
        # Fallback: inform user to install converter
        error_msg = (
            "PDF generation unavailable. Install one of:\n"
            "  - weasyprint: pip install weasyprint\n"
            "  - wkhtmltopdf: apt install wkhtmltopdf\n"
            f"HTML report saved to: {html_path}"
        )
        logger.warning(error_msg)
        raise RuntimeError(error_msg)

    def _try_weasyprint(self, html_path: str, pdf_path: str) -> bool:
        """
        Attempt to convert HTML to PDF using weasyprint.
        
        Args:
            html_path: Path to HTML file.
            pdf_path: Path where PDF should be written.
        
        Returns:
            True if conversion succeeded, False otherwise.
        """
        try:
            from weasyprint import HTML
            HTML(html_path).write_pdf(pdf_path)
            logger.info(f"PDF generated with weasyprint: {pdf_path}")
            return True
        except ImportError:
            logger.debug("weasyprint not installed")
            return False
        except Exception as e:
            logger.warning(f"weasyprint conversion failed: {e}")
            return False

    def _try_wkhtmltopdf(self, html_path: str, pdf_path: str) -> bool:
        """
        Attempt to convert HTML to PDF using wkhtmltopdf.
        
        Args:
            html_path: Path to HTML file.
            pdf_path: Path where PDF should be written.
        
        Returns:
            True if conversion succeeded, False otherwise.
        """
        try:
            result = subprocess.run(
                ["wkhtmltopdf", html_path, pdf_path],
                capture_output=True,
                timeout=60,
            )
            if result.returncode == 0:
                logger.info(f"PDF generated with wkhtmltopdf: {pdf_path}")
                return True
            else:
                logger.warning(f"wkhtmltopdf failed: {result.stderr.decode()}")
                return False
        except FileNotFoundError:
            logger.debug("wkhtmltopdf not installed")
            return False
        except subprocess.TimeoutExpired:
            logger.warning("wkhtmltopdf conversion timeout")
            return False
        except Exception as e:
            logger.warning(f"wkhtmltopdf conversion error: {e}")
            return False

    def generate_executive_summary(
        self,
        scan_data: ScanData,
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """
        Generate executive summary with high-level metrics and insights.
        
        Args:
            scan_data: Scan metadata.
            findings: List of all security findings.
        
        Returns:
            Dictionary with summary metrics including:
            - total_hosts, total_open_ports, total_services
            - critical/high/medium/low finding counts
            - top_exposed_ports
            - top_risky_hosts
            - external_exposure_count
            - risk_score (0-10)
        """
        # Count findings by severity
        severity_counts = defaultdict(int)
        external_exposure_count = 0
        ports_by_frequency = defaultdict(int)
        hosts_by_risk = defaultdict(int)

        for finding in findings:
            severity_counts[finding.severity] += 1
            if finding.external_exposure:
                external_exposure_count += 1
            ports_by_frequency[finding.port] += 1
            hosts_by_risk[finding.host] += 1

        # Calculate overall risk score (0-10 scale)
        risk_score = self._calculate_risk_score(severity_counts, len(findings))

        # Get top exposed ports
        top_exposed_ports = sorted(
            ports_by_frequency.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        # Get top risky hosts
        top_risky_hosts = sorted(
            hosts_by_risk.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        return {
            "total_hosts": scan_data.total_hosts,
            "total_open_ports": scan_data.total_open_ports,
            "total_services": scan_data.total_services,
            "total_findings": len(findings),
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
            "medium_count": severity_counts.get("medium", 0),
            "low_count": severity_counts.get("low", 0),
            "info_count": severity_counts.get("info", 0),
            "external_exposure_count": external_exposure_count,
            "top_exposed_ports": top_exposed_ports,
            "top_risky_hosts": top_risky_hosts,
            "risk_score": risk_score,
            "scan_duration": scan_data.duration_seconds,
        }

    def generate_remediation_checklist(
        self,
        findings: List[Finding],
    ) -> List[Dict[str, Any]]:
        """
        Generate prioritized remediation guidance grouped by severity.
        
        Args:
            findings: List of security findings.
        
        Returns:
            List of remediation items grouped by priority, with deduplication:
            [
                {
                    "priority": "critical",
                    "items": [
                        {"title": "...", "remediation": "...", "count": 5},
                        ...
                    ]
                },
                ...
            ]
        """
        # Group findings by severity and remediation to avoid duplicates
        remediation_map: Dict[str, Dict[str, Any]] = {}

        for finding in findings:
            key = f"{finding.severity}:{finding.title}"
            if key not in remediation_map:
                remediation_map[key] = {
                    "severity": finding.severity,
                    "title": finding.title,
                    "remediation": finding.remediation,
                    "count": 0,
                    "affected_hosts": set(),
                }
            remediation_map[key]["count"] += 1
            remediation_map[key]["affected_hosts"].add(finding.host)

        # Sort by severity and organize
        result = []
        severity_order = ["critical", "high", "medium", "low", "info"]

        for severity in severity_order:
            items = [
                {
                    "title": item["title"],
                    "remediation": item["remediation"],
                    "count": item["count"],
                    "affected_hosts": sorted(list(item["affected_hosts"])),
                }
                for item in remediation_map.values()
                if item["severity"] == severity
            ]

            if items:
                result.append({
                    "priority": severity,
                    "items": sorted(items, key=lambda x: x["count"], reverse=True),
                })

        return result

    def _calculate_risk_score(
        self,
        severity_counts: Dict[str, int],
        total_findings: int,
    ) -> float:
        """
        Calculate overall risk score (0-10).
        
        Args:
            severity_counts: Dictionary of findings per severity level.
            total_findings: Total number of findings.
        
        Returns:
            Risk score between 0 and 10.
        """
        if total_findings == 0:
            return 0.0

        # Weighted scoring system
        weights = {
            "critical": 5,
            "high": 3,
            "medium": 1.5,
            "low": 0.5,
            "info": 0.1,
        }

        weighted_sum = sum(
            severity_counts.get(severity, 0) * weight
            for severity, weight in weights.items()
        )

        # Normalize to 0-10 scale
        # Assume 10 critical findings = score of 10
        risk_score = min(10.0, (weighted_sum / 10.0))
        return round(risk_score, 2)

    def _group_findings_by_severity(
        self,
        findings: List[Finding],
    ) -> Dict[str, List[Finding]]:
        """
        Group findings by severity level.
        
        Args:
            findings: List of security findings.
        
        Returns:
            Dictionary mapping severity to list of findings.
        """
        result: Dict[str, List[Finding]] = defaultdict(list)
        for finding in findings:
            result[finding.severity].append(finding)
        
        # Sort each group by port/host for consistency
        for severity in result:
            result[severity].sort(
                key=lambda f: (f.host, f.port)
            )
        
        return dict(result)

    def _group_findings_by_host(
        self,
        findings: List[Finding],
    ) -> Dict[str, List[Finding]]:
        """
        Group findings by host.
        
        Args:
            findings: List of security findings.
        
        Returns:
            Dictionary mapping host to list of findings.
        """
        result: Dict[str, List[Finding]] = defaultdict(list)
        for finding in findings:
            result[finding.host].append(finding)
        
        # Sort each group by port for consistency
        for host in result:
            result[host].sort(key=lambda f: f.port)
        
        return dict(result)

    @staticmethod
    def _severity_color(severity: str) -> str:
        """
        Get hex color code for severity level.
        
        Args:
            severity: Severity level (critical, high, medium, low, info).
        
        Returns:
            Hex color code.
        """
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#0d6efd",
            "info": "#6c757d",
        }
        return colors.get(severity, "#6c757d")

    @staticmethod
    def _risk_level(score: float) -> str:
        """
        Convert numeric risk score to text level.
        
        Args:
            score: Risk score (0-10).
        
        Returns:
            Risk level description.
        """
        if score >= 8.5:
            return "Critical"
        elif score >= 7:
            return "High"
        elif score >= 5:
            return "Medium"
        elif score >= 2:
            return "Low"
        else:
            return "Minimal"

    @staticmethod
    def _format_timestamp(dt: datetime, fmt: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
        """
        Format datetime object as human-readable string.
        
        Args:
            dt: Datetime object.
            fmt: Format string.
        
        Returns:
            Formatted timestamp string.
        """
        if isinstance(dt, str):
            return dt
        return dt.strftime(fmt)

    @staticmethod
    def _pluralize(count: int, singular: str, plural: Optional[str] = None) -> str:
        """
        Convert word to plural form based on count.
        
        Args:
            count: Item count.
            singular: Singular form.
            plural: Plural form (defaults to singular + 's').
        
        Returns:
            Appropriately pluralized word.
        """
        if plural is None:
            plural = f"{singular}s"
        return singular if count == 1 else plural
