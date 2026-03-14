"""Diff analysis engine for comparing network scan results.

This module provides comprehensive comparison capabilities for network scan results,
including detection of discrepancies between scan methods, identification of shadow
exposure, and tracking of changes across scan runs.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingType(str, Enum):
    """Types of findings discovered during analysis."""

    SCAN_DISCREPANCY = "SCAN_DISCREPANCY"
    SHADOW_EXPOSURE = "SHADOW_EXPOSURE"
    BLOCKED_PORT = "BLOCKED_PORT"
    BANNER_MISMATCH = "BANNER_MISMATCH"
    TLS_MISMATCH = "TLS_MISMATCH"
    NEW_PORT = "NEW_PORT"
    CLOSED_PORT = "CLOSED_PORT"
    SERVICE_CHANGE = "SERVICE_CHANGE"


@dataclass
class DiffFinding:
    """Represents a single finding from diff analysis.

    Attributes:
        finding_type: Classification of the finding.
        severity: Severity level of the finding.
        host: Target host IP address or hostname.
        port: Target port number.
        summary: Human-readable summary of the finding.
        evidence: Dictionary containing detailed evidence data.
        recommendations: List of actionable remediation steps.
        timestamp: When the finding was generated.
    """

    finding_type: FindingType
    severity: Severity
    host: str
    port: int
    summary: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "finding_type": self.finding_type.value,
            "severity": self.severity.value,
            "host": self.host,
            "port": self.port,
            "summary": self.summary,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
            "timestamp": self.timestamp.isoformat(),
        }


class DiffAnalyzer:
    """Analyzes differences between network scan results.

    This class provides methods to compare scan results from different
    techniques, locations, and time periods to identify discrepancies,
    security concerns, and configuration changes.
    """

    # Severity mappings for different finding types
    FINDING_TYPE_SEVERITY_MAP = {
        FindingType.SHADOW_EXPOSURE: Severity.CRITICAL,
        FindingType.SCAN_DISCREPANCY: Severity.HIGH,
        FindingType.BLOCKED_PORT: Severity.MEDIUM,
        FindingType.TLS_MISMATCH: Severity.HIGH,
        FindingType.BANNER_MISMATCH: Severity.MEDIUM,
        FindingType.NEW_PORT: Severity.HIGH,
        FindingType.CLOSED_PORT: Severity.LOW,
        FindingType.SERVICE_CHANGE: Severity.MEDIUM,
    }

    def __init__(self) -> None:
        """Initialize the DiffAnalyzer."""
        self._findings: List[DiffFinding] = []

    def compare_connect_vs_syn(
        self, connect_results: Dict[str, Any], syn_results: Dict[str, Any]
    ) -> List[DiffFinding]:
        """Compare TCP connect scan vs SYN scan results.

        Identifies ports that are detected by one method but not the other,
        which can indicate filtering, firewalls, or IDS evasion signatures.

        Args:
            connect_results: Dictionary with keys: {host: {port: port_info}}.
            syn_results: Dictionary with same structure as connect_results.

        Returns:
            List of DiffFinding objects identifying discrepancies.
        """
        findings: List[DiffFinding] = []

        # Normalize input to ensure consistent structure
        connect_hosts = self._normalize_scan_results(connect_results)
        syn_hosts = self._normalize_scan_results(syn_results)

        # Get all unique hosts
        all_hosts = set(connect_hosts.keys()) | set(syn_hosts.keys())

        for host in all_hosts:
            connect_ports = connect_hosts.get(host, {})
            syn_ports = syn_hosts.get(host, {})

            connect_open = self._extract_open_ports(connect_ports)
            syn_open = self._extract_open_ports(syn_ports)

            # Find ports open in connect but not in SYN
            ports_connect_only = connect_open - syn_open
            for port in ports_connect_only:
                port_info = connect_ports.get(port, {})
                findings.append(
                    DiffFinding(
                        finding_type=FindingType.SCAN_DISCREPANCY,
                        severity=Severity.HIGH,
                        host=host,
                        port=port,
                        summary=f"Port {port} open in TCP connect scan but not detected in SYN scan",
                        evidence={
                            "scan_method_found": "CONNECT",
                            "scan_method_not_found": "SYN",
                            "port_info_connect": port_info,
                            "possible_causes": [
                                "Firewall or IDS evasion filtering SYN probes",
                                "Rate limiting on SYN packets",
                                "Stateful inspection differences",
                            ],
                        },
                        recommendations=[
                            "Verify firewall rules for SYN packet handling",
                            "Check IDS/IPS for SYN-specific filtering",
                            "Investigate potential evasion techniques in use",
                            "Correlate with firewall logs for blocked SYN packets",
                        ],
                    )
                )

            # Find ports open in SYN but not in connect
            ports_syn_only = syn_open - connect_open
            for port in ports_syn_only:
                port_info = syn_ports.get(port, {})
                findings.append(
                    DiffFinding(
                        finding_type=FindingType.SCAN_DISCREPANCY,
                        severity=Severity.HIGH,
                        host=host,
                        port=port,
                        summary=f"Port {port} open in SYN scan but connection could not be established",
                        evidence={
                            "scan_method_found": "SYN",
                            "scan_method_not_found": "CONNECT",
                            "port_info_syn": port_info,
                            "possible_causes": [
                                "Service crashes or resets on full TCP connection",
                                "Connection-level firewall rules dropping full connections",
                                "RST packets generated during TCP handshake",
                            ],
                        },
                        recommendations=[
                            "Attempt manual TCP connection to verify service behavior",
                            "Check service logs for connection-related errors",
                            "Investigate firewall rules for connection-stage filtering",
                            "Test with different TCP flags or timing",
                        ],
                    )
                )

        self._findings.extend(findings)
        return findings

    def compare_internal_vs_external(
        self, internal_data: Dict[str, Any], external_data: Dict[str, Any]
    ) -> List[DiffFinding]:
        """Compare internal vs external scan results.

        Identifies shadow exposure (ports visible externally but not internally),
        blocked ports (internal but not external), and discrepancies in service
        banners or TLS configurations.

        Args:
            internal_data: Dictionary with keys: {host: {port: port_info}}.
            external_data: Dictionary with same structure as internal_data.

        Returns:
            List of DiffFinding objects identifying exposure and blocking issues.
        """
        findings: List[DiffFinding] = []

        internal_hosts = self._normalize_scan_results(internal_data)
        external_hosts = self._normalize_scan_results(external_data)

        # Process each host
        all_hosts = set(internal_hosts.keys()) | set(external_hosts.keys())

        for host in all_hosts:
            internal_ports = internal_hosts.get(host, {})
            external_ports = external_hosts.get(host, {})

            internal_open = self._extract_open_ports(internal_ports)
            external_open = self._extract_open_ports(external_ports)

            # Shadow exposure: visible externally but not internally
            shadow_ports = external_open - internal_open
            for port in shadow_ports:
                port_info = external_ports.get(port, {})
                findings.append(
                    DiffFinding(
                        finding_type=FindingType.SHADOW_EXPOSURE,
                        severity=Severity.CRITICAL,
                        host=host,
                        port=port,
                        summary=f"SHADOW EXPOSURE: Port {port} visible externally but not detected in internal scan",
                        evidence={
                            "visible_in": "EXTERNAL",
                            "not_visible_in": "INTERNAL",
                            "external_service": port_info.get("service", "unknown"),
                            "external_banner": port_info.get("banner", ""),
                            "exposure_risk": "Service accessible from untrusted networks",
                        },
                        recommendations=[
                            "Immediately investigate why service is exposed externally",
                            "Verify firewall rules between internal and external networks",
                            "Check if internal scan properly reached the service",
                            "Review network topology and routing configurations",
                            "Consider blocking external access if not required",
                        ],
                    )
                )

            # Blocked ports: open internally but not externally
            blocked_ports = internal_open - external_open
            for port in blocked_ports:
                port_info = internal_ports.get(port, {})
                findings.append(
                    DiffFinding(
                        finding_type=FindingType.BLOCKED_PORT,
                        severity=Severity.MEDIUM,
                        host=host,
                        port=port,
                        summary=f"Port {port} open internally but blocked from external access",
                        evidence={
                            "visible_in": "INTERNAL",
                            "blocked_from": "EXTERNAL",
                            "internal_service": port_info.get("service", "unknown"),
                            "internal_banner": port_info.get("banner", ""),
                            "blocking_mechanism": "Firewall or network segmentation",
                        },
                        recommendations=[
                            "Verify firewall rules are functioning correctly",
                            "Confirm network segmentation is as intended",
                            "Document intentional blocking in security policy",
                            "Monitor for changes in blocking behavior",
                        ],
                    )
                )

            # Banner mismatches
            for port in internal_open & external_open:
                internal_port_info = internal_ports.get(port, {})
                external_port_info = external_ports.get(port, {})

                internal_banner = internal_port_info.get("banner", "").strip()
                external_banner = external_port_info.get("banner", "").strip()

                if internal_banner and external_banner and internal_banner != external_banner:
                    findings.append(
                        DiffFinding(
                            finding_type=FindingType.BANNER_MISMATCH,
                            severity=Severity.MEDIUM,
                            host=host,
                            port=port,
                            summary=f"Service banner differs between internal and external scans on port {port}",
                            evidence={
                                "internal_banner": internal_banner,
                                "external_banner": external_banner,
                                "service": internal_port_info.get("service", "unknown"),
                                "possible_causes": [
                                    "Load balancing with different backend versions",
                                    "Banner modification/obfuscation for external",
                                    "Different service instances",
                                ],
                            },
                            recommendations=[
                                "Verify service versions on internal and external endpoints",
                                "Confirm load balancer or reverse proxy configuration",
                                "Check for intentional banner obfuscation",
                                "Investigate version misalignment if not expected",
                            ],
                        )
                    )

            # TLS mismatches
            for port in internal_open & external_open:
                internal_port_info = internal_ports.get(port, {})
                external_port_info = external_ports.get(port, {})

                internal_tls = internal_port_info.get("tls_info", {})
                external_tls = external_port_info.get("tls_info", {})

                if internal_tls and external_tls:
                    if internal_tls.get("certificate") != external_tls.get("certificate"):
                        findings.append(
                            DiffFinding(
                                finding_type=FindingType.TLS_MISMATCH,
                                severity=Severity.HIGH,
                                host=host,
                                port=port,
                                summary=f"TLS certificate differs between internal and external scans on port {port}",
                                evidence={
                                    "internal_cert_subject": internal_tls.get("subject", ""),
                                    "external_cert_subject": external_tls.get("subject", ""),
                                    "internal_cert_issuer": internal_tls.get("issuer", ""),
                                    "external_cert_issuer": external_tls.get("issuer", ""),
                                    "possible_causes": [
                                        "Man-in-the-middle proxy on internal network",
                                        "Different server instances",
                                        "Certificate replacement/reissue",
                                    ],
                                },
                                recommendations=[
                                    "Verify certificate chain is legitimate",
                                    "Check for corporate SSL inspection proxies",
                                    "Confirm both endpoints are serving same certificate",
                                    "Investigate any unauthorized certificate modification",
                                ],
                            )
                        )

        self._findings.extend(findings)
        return findings

    def compare_scan_runs(
        self, run1_data: Dict[str, Any], run2_data: Dict[str, Any]
    ) -> List[DiffFinding]:
        """Compare results from two separate scan runs.

        Identifies new ports opened, closed ports, and service version changes
        between scan runs to detect changes in the network state.

        Args:
            run1_data: Dictionary with keys: {host: {port: port_info}} from first run.
            run2_data: Dictionary with same structure from second run.

        Returns:
            List of DiffFinding objects identifying changes between runs.
        """
        findings: List[DiffFinding] = []

        run1_hosts = self._normalize_scan_results(run1_data)
        run2_hosts = self._normalize_scan_results(run2_data)

        all_hosts = set(run1_hosts.keys()) | set(run2_hosts.keys())

        for host in all_hosts:
            run1_ports = run1_hosts.get(host, {})
            run2_ports = run2_hosts.get(host, {})

            run1_open = self._extract_open_ports(run1_ports)
            run2_open = self._extract_open_ports(run2_ports)

            # New ports opened
            new_ports = run2_open - run1_open
            for port in new_ports:
                port_info = run2_ports.get(port, {})
                findings.append(
                    DiffFinding(
                        finding_type=FindingType.NEW_PORT,
                        severity=Severity.HIGH,
                        host=host,
                        port=port,
                        summary=f"New port {port} detected on host {host}",
                        evidence={
                            "service": port_info.get("service", "unknown"),
                            "banner": port_info.get("banner", ""),
                            "detection_run": "run2",
                            "previous_state": "closed",
                        },
                        recommendations=[
                            "Verify this is an authorized service",
                            "Determine why this service was exposed",
                            "Review recent configuration changes",
                            "Check change management logs for this service",
                            "Verify service is properly secured and hardened",
                        ],
                    )
                )

            # Ports closed
            closed_ports = run1_open - run2_open
            for port in closed_ports:
                port_info = run1_ports.get(port, {})
                findings.append(
                    DiffFinding(
                        finding_type=FindingType.CLOSED_PORT,
                        severity=Severity.LOW,
                        host=host,
                        port=port,
                        summary=f"Port {port} closed on host {host}",
                        evidence={
                            "service": port_info.get("service", "unknown"),
                            "banner": port_info.get("banner", ""),
                            "previous_state": "open",
                        },
                        recommendations=[
                            "Verify service was intentionally closed",
                            "Confirm no service outage or misconfiguration",
                            "Update asset inventory and documentation",
                        ],
                    )
                )

            # Service version changes
            for port in run1_open & run2_open:
                run1_port_info = run1_ports.get(port, {})
                run2_port_info = run2_ports.get(port, {})

                run1_service = run1_port_info.get("service", "")
                run2_service = run2_port_info.get("service", "")

                if run1_service and run2_service and run1_service != run2_service:
                    findings.append(
                        DiffFinding(
                            finding_type=FindingType.SERVICE_CHANGE,
                            severity=Severity.MEDIUM,
                            host=host,
                            port=port,
                            summary=f"Service version changed on port {port}",
                            evidence={
                                "previous_service": run1_service,
                                "current_service": run2_service,
                                "previous_banner": run1_port_info.get("banner", ""),
                                "current_banner": run2_port_info.get("banner", ""),
                            },
                            recommendations=[
                                "Verify service upgrade was authorized",
                                "Review service release notes for security fixes",
                                "Check for known vulnerabilities in new version",
                                "Update documentation and asset inventory",
                                "Test service compatibility with dependent systems",
                            ],
                        )
                    )

        self._findings.extend(findings)
        return findings

    def get_all_findings(self) -> List[DiffFinding]:
        """Get all findings from all analyses performed.

        Returns:
            List of all DiffFinding objects discovered.
        """
        return self._findings.copy()

    def get_findings_by_severity(self, severity: Severity) -> List[DiffFinding]:
        """Filter findings by severity level.

        Args:
            severity: Severity level to filter by.

        Returns:
            List of findings with specified severity.
        """
        return [f for f in self._findings if f.severity == severity]

    def get_findings_by_type(self, finding_type: FindingType) -> List[DiffFinding]:
        """Filter findings by type.

        Args:
            finding_type: FindingType to filter by.

        Returns:
            List of findings of specified type.
        """
        return [f for f in self._findings if f.finding_type == finding_type]

    def get_findings_by_host(self, host: str) -> List[DiffFinding]:
        """Filter findings by host.

        Args:
            host: Host IP or hostname to filter by.

        Returns:
            List of findings for specified host.
        """
        return [f for f in self._findings if f.host == host]

    def clear_findings(self) -> None:
        """Clear all stored findings."""
        self._findings.clear()

    # Private helper methods

    def _normalize_scan_results(self, scan_data: Dict[str, Any]) -> Dict[str, Dict[int, Dict[str, Any]]]:
        """Normalize scan results to consistent structure.

        Args:
            scan_data: Raw scan data in various possible formats.

        Returns:
            Normalized dictionary with structure {host: {port: port_info}}.
        """
        normalized: Dict[str, Dict[int, Dict[str, Any]]] = {}

        if not scan_data:
            return normalized

        for host, host_data in scan_data.items():
            if isinstance(host_data, dict):
                normalized[host] = {}
                for port_key, port_info in host_data.items():
                    try:
                        port_num = int(port_key)
                        if isinstance(port_info, dict):
                            normalized[host][port_num] = port_info
                        else:
                            # Handle case where port_info is simple string
                            normalized[host][port_num] = {"state": str(port_info)}
                    except (ValueError, TypeError):
                        continue

        return normalized

    def _extract_open_ports(self, port_dict: Dict[int, Dict[str, Any]]) -> Set[int]:
        """Extract set of open ports from port dictionary.

        Args:
            port_dict: Dictionary mapping port numbers to port information.

        Returns:
            Set of port numbers that are open.
        """
        open_ports: Set[int] = set()

        for port_num, port_info in port_dict.items():
            if isinstance(port_info, dict):
                state = port_info.get("state", "").lower()
                if state in ("open", "opened"):
                    open_ports.add(port_num)
            elif isinstance(port_info, str):
                if port_info.lower() in ("open", "opened"):
                    open_ports.add(port_num)

        return open_ports
