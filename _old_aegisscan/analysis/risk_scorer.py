"""Risk scoring engine for network scan results.

This module provides comprehensive risk assessment capabilities for network services,
identifying security concerns based on known vulnerabilities, configurations,
and service characteristics.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict


class RiskLevel(str, Enum):
    """Risk levels for services and hosts."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


@dataclass
class RiskFactor:
    """Represents a single risk factor contributing to risk score.

    Attributes:
        factor_name: Name of the risk factor.
        severity_multiplier: How much this factor multiplies base score (0.0-2.0).
        description: Detailed description of the risk.
        remediation: How to remediate this specific factor.
    """

    factor_name: str
    severity_multiplier: float
    description: str
    remediation: str


@dataclass
class RiskAssessment:
    """Risk assessment for a single port/service.

    Attributes:
        port: Port number being assessed.
        service: Service name/type.
        score: Risk score from 0-100.
        risk_level: Categorical risk level.
        factors: List of risk factors contributing to score.
        recommendations: Actionable remediation recommendations.
        timestamp: When assessment was generated.
    """

    port: int
    service: str
    score: float
    risk_level: RiskLevel
    factors: List[RiskFactor] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert assessment to dictionary representation."""
        return {
            "port": self.port,
            "service": self.service,
            "score": self.score,
            "risk_level": self.risk_level.value,
            "factors": [
                {
                    "factor_name": f.factor_name,
                    "severity_multiplier": f.severity_multiplier,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in self.factors
            ],
            "recommendations": self.recommendations,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class HostRiskSummary:
    """Risk summary for a single host.

    Attributes:
        host: Host IP address or hostname.
        total_score: Aggregate risk score for host.
        risk_level: Overall risk level for host.
        port_count: Total number of open ports.
        critical_ports: Ports with critical risk level.
        high_risk_ports: Ports with high risk level.
        findings_summary: Summary of risk findings.
        port_assessments: List of individual port risk assessments.
        timestamp: When summary was generated.
    """

    host: str
    total_score: float
    risk_level: RiskLevel
    port_count: int
    critical_ports: List[int] = field(default_factory=list)
    high_risk_ports: List[int] = field(default_factory=list)
    findings_summary: Dict[str, int] = field(default_factory=dict)
    port_assessments: List[RiskAssessment] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary representation."""
        return {
            "host": self.host,
            "total_score": self.total_score,
            "risk_level": self.risk_level.value,
            "port_count": self.port_count,
            "critical_ports": self.critical_ports,
            "high_risk_ports": self.high_risk_ports,
            "findings_summary": self.findings_summary,
            "port_assessments": [pa.to_dict() for pa in self.port_assessments],
            "timestamp": self.timestamp.isoformat(),
        }


class RiskScorer:
    """Scores risk for network services and hosts.

    This class evaluates security risk based on port usage, service type,
    TLS configuration, banner information, and known vulnerabilities.
    """

    # Known risky ports with base scores and descriptions
    KNOWN_RISKY_PORTS: Dict[int, Tuple[float, str]] = {
        # Database ports
        3306: (85.0, "MySQL database exposed"),
        5432: (85.0, "PostgreSQL database exposed"),
        27017: (90.0, "MongoDB database exposed"),
        6379: (80.0, "Redis cache exposed"),
        5984: (80.0, "CouchDB database exposed"),
        # Windows/RDP
        3389: (75.0, "RDP management protocol exposed"),
        1433: (85.0, "MSSQL database exposed"),
        # SSH/Telnet
        22: (30.0, "SSH service exposed"),
        23: (90.0, "Telnet unencrypted management exposed"),
        # FTP
        21: (75.0, "FTP unencrypted file transfer exposed"),
        # HTTP/HTTPS on non-standard ports
        8080: (40.0, "HTTP on non-standard port"),
        8443: (30.0, "HTTPS on non-standard port"),
        # Directory services
        389: (60.0, "LDAP directory service exposed"),
        636: (40.0, "LDAPS directory service exposed"),
        # Mail protocols
        25: (50.0, "SMTP service exposed"),
        110: (60.0, "POP3 unencrypted mail exposed"),
        143: (60.0, "IMAP unencrypted mail exposed"),
        # DNS
        53: (40.0, "DNS service exposed"),
        # SMB/Windows shares
        139: (70.0, "NetBIOS/SMB service exposed"),
        445: (70.0, "SMB service exposed"),
        # VNC/Remote access
        5900: (70.0, "VNC remote access exposed"),
        # Oracle
        1521: (85.0, "Oracle database exposed"),
        # NFS
        2049: (75.0, "NFS service exposed"),
        # Elasticsearch
        9200: (85.0, "Elasticsearch service exposed"),
        9300: (80.0, "Elasticsearch cluster service exposed"),
        # Jenkins
        8081: (70.0, "Jenkins CI/CD exposed"),
        # Docker
        2375: (95.0, "Docker daemon unencrypted exposed"),
        2376: (70.0, "Docker daemon exposed"),
        # Kubernetes
        10250: (90.0, "Kubernetes kubelet exposed"),
        # Various admin interfaces
        8000: (50.0, "Common admin interface port"),
        8888: (50.0, "Common admin interface port"),
        9000: (50.0, "Common admin interface port"),
    }

    # Known weak TLS versions
    WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

    # Common default service versions with known vulnerabilities
    VULNERABLE_SERVICE_PATTERNS = {
        "Apache/2.4.1": {"severity": 0.6, "issue": "Apache vulnerability"},
        "nginx/1.0": {"severity": 0.5, "issue": "Nginx vulnerability"},
        "OpenSSH_5": {"severity": 0.7, "issue": "OpenSSH security issues"},
        "OpenSSH_6.0": {"severity": 0.5, "issue": "OpenSSH older version"},
        "Tomcat/5": {"severity": 0.8, "issue": "Tomcat critical vulnerability"},
        "Tomcat/6": {"severity": 0.6, "issue": "Tomcat security issues"},
        "IIS/6": {"severity": 0.8, "issue": "IIS outdated version"},
        "IIS/7": {"severity": 0.6, "issue": "IIS older version"},
    }

    # Management ports that should be restricted
    MANAGEMENT_PORTS = {22, 23, 3389, 8000, 8001, 8080, 8081, 8888, 9000}

    # Standard unencrypted protocol ports
    UNENCRYPTED_PORTS = {
        21: "FTP",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        389: "LDAP",
        445: "SMB",
    }

    def __init__(self) -> None:
        """Initialize the RiskScorer."""
        pass

    def score_port(
        self,
        port: int,
        service: str = "",
        banner_info: Optional[Dict[str, Any]] = None,
        tls_info: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessment:
        """Score risk for a single port and service.

        Args:
            port: Port number being scored.
            service: Service name/version string.
            banner_info: Dictionary with banner and version information.
            tls_info: Dictionary with TLS certificate and configuration.

        Returns:
            RiskAssessment with score and contributing factors.
        """
        if banner_info is None:
            banner_info = {}
        if tls_info is None:
            tls_info = {}

        factors: List[RiskFactor] = []
        base_score = 20.0  # Base score for any open port

        # Check for known risky ports
        if port in self.KNOWN_RISKY_PORTS:
            port_score, port_description = self.KNOWN_RISKY_PORTS[port]
            factors.append(
                RiskFactor(
                    factor_name="Known Risky Port",
                    severity_multiplier=port_score / 50.0,
                    description=port_description,
                    remediation=f"Restrict access to port {port} or disable service",
                )
            )
            base_score = port_score

        # Check for vulnerable service versions
        vuln_factors = self._check_vulnerable_services(service)
        factors.extend(vuln_factors)

        # Check TLS configuration
        tls_factors = self._assess_tls_security(tls_info)
        factors.extend(tls_factors)

        # Check for unencrypted protocols
        if port in self.UNENCRYPTED_PORTS:
            protocol = self.UNENCRYPTED_PORTS[port]
            factors.append(
                RiskFactor(
                    factor_name="Unencrypted Protocol",
                    severity_multiplier=0.3,
                    description=f"Unencrypted {protocol} protocol allows traffic interception",
                    remediation=f"Migrate to encrypted variant (e.g., FTPS for FTP, encrypted protocols for SMTP)",
                )
            )

        # Check for management port exposure
        if port in self.MANAGEMENT_PORTS and port not in (80, 443):
            factors.append(
                RiskFactor(
                    factor_name="Management Port Exposure",
                    severity_multiplier=0.5,
                    description="Management/administration port exposed",
                    remediation="Restrict access to management ports from trusted IPs only",
                )
            )

        # Check for default credentials indicators
        default_cred_factors = self._check_default_credentials(service, banner_info)
        factors.extend(default_cred_factors)

        # Calculate final score with multiplicative factors
        score = base_score
        for factor in factors:
            score = min(100.0, score + (factor.severity_multiplier * 20.0))

        # Determine risk level
        risk_level = self._score_to_risk_level(score)

        # Generate recommendations
        recommendations = self._generate_port_recommendations(port, service, factors)

        return RiskAssessment(
            port=port,
            service=service or "Unknown",
            score=round(score, 1),
            risk_level=risk_level,
            factors=factors,
            recommendations=recommendations,
        )

    def score_host(self, host_data: Dict[str, Any]) -> HostRiskSummary:
        """Score risk for entire host based on all open ports.

        Args:
            host_data: Dictionary with structure:
                {
                    "host": "192.168.1.1",
                    "ports": {
                        port_num: {
                            "service": "service_name",
                            "banner": "banner_info",
                            "tls_info": {...}
                        }
                    }
                }

        Returns:
            HostRiskSummary with aggregate and per-port assessments.
        """
        host = host_data.get("host", "unknown")
        ports_data = host_data.get("ports", {})

        if not isinstance(ports_data, dict):
            ports_data = {}

        port_assessments: List[RiskAssessment] = []
        critical_ports: List[int] = []
        high_risk_ports: List[int] = []
        risk_level_counts: Dict[RiskLevel, int] = defaultdict(int)

        # Score each port
        for port_key, port_info in ports_data.items():
            try:
                port_num = int(port_key)
            except (ValueError, TypeError):
                continue

            if isinstance(port_info, dict):
                service = port_info.get("service", "")
                banner_info = port_info.get("banner_info", {})
                tls_info = port_info.get("tls_info", {})
            else:
                service = str(port_info)
                banner_info = {}
                tls_info = {}

            assessment = self.score_port(port_num, service, banner_info, tls_info)
            port_assessments.append(assessment)

            # Track critical and high risk ports
            if assessment.risk_level == RiskLevel.CRITICAL:
                critical_ports.append(port_num)
            elif assessment.risk_level == RiskLevel.HIGH:
                high_risk_ports.append(port_num)

            risk_level_counts[assessment.risk_level] += 1

        # Calculate aggregate score
        if port_assessments:
            total_score = sum(pa.score for pa in port_assessments) / len(port_assessments)
        else:
            total_score = 0.0

        # Determine host risk level
        if critical_ports:
            host_risk_level = RiskLevel.CRITICAL
        elif high_risk_ports:
            host_risk_level = RiskLevel.HIGH
        else:
            host_risk_level = self._score_to_risk_level(total_score)

        # Build findings summary
        findings_summary = {
            "total_ports": len(port_assessments),
            "critical_ports": len(critical_ports),
            "high_risk_ports": len(high_risk_ports),
            "medium_risk_ports": risk_level_counts.get(RiskLevel.MEDIUM, 0),
            "low_risk_ports": risk_level_counts.get(RiskLevel.LOW, 0),
            "minimal_risk_ports": risk_level_counts.get(RiskLevel.MINIMAL, 0),
        }

        return HostRiskSummary(
            host=host,
            total_score=round(total_score, 1),
            risk_level=host_risk_level,
            port_count=len(port_assessments),
            critical_ports=sorted(critical_ports),
            high_risk_ports=sorted(high_risk_ports),
            findings_summary=findings_summary,
            port_assessments=port_assessments,
        )

    def generate_remediation(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable remediation recommendations from findings.

        Args:
            findings: List of finding dictionaries from diff analyzer.

        Returns:
            List of prioritized remediation recommendations.
        """
        recommendations: Dict[str, int] = {}  # recommendation -> priority
        seen_recommendations: set = set()

        # Aggregate recommendations from findings
        for finding in findings:
            if not isinstance(finding, dict):
                continue

            finding_type = finding.get("finding_type", "")
            host = finding.get("host", "")
            port = finding.get("port", 0)

            # Generate specific remediation based on finding type
            if finding_type == "SHADOW_EXPOSURE":
                rec = f"Investigate and potentially block external access to {host}:{port}"
                if rec not in seen_recommendations:
                    recommendations[rec] = 10
                    seen_recommendations.add(rec)

            elif finding_type == "SCAN_DISCREPANCY":
                rec = f"Review firewall rules for {host}:{port} - potential filtering detected"
                if rec not in seen_recommendations:
                    recommendations[rec] = 7
                    seen_recommendations.add(rec)

            elif finding_type == "BLOCKED_PORT":
                rec = f"Verify intentional blocking of {host}:{port}"
                if rec not in seen_recommendations:
                    recommendations[rec] = 3
                    seen_recommendations.add(rec)

            elif finding_type == "TLS_MISMATCH":
                rec = f"Investigate TLS certificate mismatch on {host}:{port}"
                if rec not in seen_recommendations:
                    recommendations[rec] = 8
                    seen_recommendations.add(rec)

            elif finding_type == "NEW_PORT":
                rec = f"Verify authorization for newly opened port {host}:{port}"
                if rec not in seen_recommendations:
                    recommendations[rec] = 9
                    seen_recommendations.add(rec)

        # Add general remediation
        general_remediations = [
            ("Implement network segmentation to restrict access to sensitive ports", 6),
            ("Deploy IDS/IPS to monitor and block suspicious port scanning", 5),
            ("Establish baseline scan schedule for continuous monitoring", 4),
            ("Review and update firewall rules based on findings", 7),
            ("Implement principle of least privilege for service access", 6),
            ("Document authorized services and ports", 3),
            ("Schedule regular security assessments and vulnerability scanning", 4),
        ]

        for rec, priority in general_remediations:
            if rec not in seen_recommendations:
                recommendations[rec] = priority
                seen_recommendations.add(rec)

        # Sort by priority (descending) and return
        sorted_recommendations = sorted(
            recommendations.items(), key=lambda x: x[1], reverse=True
        )
        return [rec for rec, _ in sorted_recommendations]

    # Private helper methods

    def _check_vulnerable_services(self, service: str) -> List[RiskFactor]:
        """Check service string against known vulnerable versions.

        Args:
            service: Service name and version string.

        Returns:
            List of risk factors for vulnerable services.
        """
        factors: List[RiskFactor] = []

        if not service:
            return factors

        for pattern, vuln_info in self.VULNERABLE_SERVICE_PATTERNS.items():
            if pattern.lower() in service.lower():
                factors.append(
                    RiskFactor(
                        factor_name="Known Vulnerable Service Version",
                        severity_multiplier=vuln_info["severity"],
                        description=f"{service} - {vuln_info['issue']}",
                        remediation=f"Update {service} to latest patched version",
                    )
                )

        return factors

    def _assess_tls_security(self, tls_info: Dict[str, Any]) -> List[RiskFactor]:
        """Assess TLS/SSL configuration security.

        Args:
            tls_info: Dictionary with TLS certificate and configuration details.

        Returns:
            List of risk factors for TLS configuration.
        """
        factors: List[RiskFactor] = []

        if not tls_info:
            return factors

        # Check for weak TLS versions
        tls_version = tls_info.get("version", "").upper()
        if tls_version in self.WEAK_TLS_VERSIONS:
            factors.append(
                RiskFactor(
                    factor_name="Weak TLS Version",
                    severity_multiplier=0.8,
                    description=f"Service uses weak TLS version {tls_version}",
                    remediation="Update to TLS 1.2 or later (recommend TLS 1.3)",
                )
            )

        # Check for self-signed certificates
        if tls_info.get("is_self_signed", False):
            factors.append(
                RiskFactor(
                    factor_name="Self-Signed Certificate",
                    severity_multiplier=0.4,
                    description="TLS certificate is self-signed",
                    remediation="Install certificate signed by trusted certificate authority",
                )
            )

        # Check for expired certificates
        expiration = tls_info.get("expiration_date")
        if expiration:
            try:
                from datetime import datetime

                exp_date = (
                    datetime.fromisoformat(expiration)
                    if isinstance(expiration, str)
                    else expiration
                )
                if exp_date < datetime.utcnow():
                    factors.append(
                        RiskFactor(
                            factor_name="Expired Certificate",
                            severity_multiplier=0.9,
                            description="TLS certificate has expired",
                            remediation="Immediately renew certificate to prevent service disruption",
                        )
                    )
            except (ValueError, TypeError):
                pass

        # Check for expiring certificates (within 30 days)
        if expiration:
            try:
                from datetime import datetime, timedelta

                exp_date = (
                    datetime.fromisoformat(expiration)
                    if isinstance(expiration, str)
                    else expiration
                )
                days_until_expiry = (exp_date - datetime.utcnow()).days
                if 0 < days_until_expiry <= 30:
                    factors.append(
                        RiskFactor(
                            factor_name="Expiring Certificate",
                            severity_multiplier=0.3,
                            description=f"TLS certificate expires in {days_until_expiry} days",
                            remediation="Schedule certificate renewal immediately",
                        )
                    )
            except (ValueError, TypeError):
                pass

        return factors

    def _check_default_credentials(
        self, service: str, banner_info: Dict[str, Any]
    ) -> List[RiskFactor]:
        """Check for indicators of default credentials.

        Args:
            service: Service name/version.
            banner_info: Banner information from service.

        Returns:
            List of risk factors for default credential risks.
        """
        factors: List[RiskFactor] = []

        # Common default credential indicators
        default_indicators = {
            "tomcat": "Tomcat default credentials may be in use",
            "jenkins": "Jenkins default credentials may be in use",
            "elasticsearch": "Elasticsearch may have default access",
            "mongodb": "MongoDB may have default access",
            "mysql": "MySQL default credentials may be in use",
            "postgres": "PostgreSQL default credentials may be in use",
            "admin": "Admin interface may have default credentials",
        }

        service_lower = service.lower()
        for indicator, risk_desc in default_indicators.items():
            if indicator in service_lower:
                factors.append(
                    RiskFactor(
                        factor_name="Potential Default Credentials",
                        severity_multiplier=0.7,
                        description=risk_desc,
                        remediation="Change default credentials immediately and enforce strong passwords",
                    )
                )
                break

        return factors

    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level.

        Args:
            score: Risk score from 0-100.

        Returns:
            RiskLevel enum value.
        """
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def _generate_port_recommendations(
        self, port: int, service: str, factors: List[RiskFactor]
    ) -> List[str]:
        """Generate specific recommendations for a port.

        Args:
            port: Port number.
            service: Service name.
            factors: Risk factors for this port.

        Returns:
            List of actionable recommendations.
        """
        recommendations: List[str] = []

        # Base recommendation
        if port in self.KNOWN_RISKY_PORTS:
            recommendations.append(
                f"Restrict access to port {port} or disable the service if not needed"
            )
        else:
            recommendations.append(
                f"Review necessity of service on port {port} and restrict access appropriately"
            )

        # Factor-specific recommendations
        for factor in factors:
            recommendations.append(factor.remediation)

        # Service-specific recommendations
        if "mysql" in service.lower():
            recommendations.append("Move MySQL to non-standard port and use firewall rules")
            recommendations.append("Enable MySQL user authentication and disable root remote access")
        elif "postgres" in service.lower():
            recommendations.append("Configure PostgreSQL to listen only on necessary interfaces")
            recommendations.append("Implement network-level access controls")
        elif "ssh" in service.lower():
            recommendations.append("Disable SSH root login and use key-based authentication")
            recommendations.append("Change SSH to non-standard port if possible")
            recommendations.append("Implement fail2ban or similar rate limiting")
        elif "rdp" in service.lower() or port == 3389:
            recommendations.append("Restrict RDP to VPN or bastion host access")
            recommendations.append("Implement network level authentication (NLA)")
            recommendations.append("Consider using a jump host/bastion server")
        elif "smb" in service.lower() or port in (139, 445):
            recommendations.append("Restrict SMB access to trusted internal networks")
            recommendations.append("Disable SMB on systems that don't need file sharing")
            recommendations.append("Implement SMB encryption (SMB 3.0+)")

        return recommendations
