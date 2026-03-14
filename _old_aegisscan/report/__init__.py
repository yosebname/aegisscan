"""
AegisScan Report Generation Module

This module provides comprehensive report generation capabilities for security scan results,
including HTML reports with professional styling, PDF generation with fallback support,
and detailed remediation guidance.
"""

from aegisscan.report.generator import (
    ReportGenerator,
    ReportData,
)

__all__ = [
    "ReportGenerator",
    "ReportData",
]

__version__ = "1.0.0"
