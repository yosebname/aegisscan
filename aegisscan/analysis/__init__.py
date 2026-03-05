"""Analysis and diff engine for AegisScan.

This module provides comprehensive analysis capabilities for network scan results,
including diff analysis for comparing scan methods and runs, and risk scoring for
identifying security concerns.
"""

from aegisscan.analysis.diff_analyzer import (
    DiffAnalyzer,
    DiffFinding,
    FindingType,
    Severity,
)
from aegisscan.analysis.risk_scorer import (
    RiskScorer,
    RiskAssessment,
    HostRiskSummary,
)

__all__ = [
    "DiffAnalyzer",
    "DiffFinding",
    "FindingType",
    "Severity",
    "RiskScorer",
    "RiskAssessment",
    "HostRiskSummary",
]
