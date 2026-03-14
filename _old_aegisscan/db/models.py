"""SQLAlchemy ORM models for AegisScan database schema.

Defines all data models for scan results, hosts, services, certificates,
and observations with proper relationships and indexes.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    JSON,
    String,
    Integer,
    Float,
    DateTime,
    ForeignKey,
    Index,
    Boolean,
    Text,
    LargeBinary,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Mapped, mapped_column, relationship

Base = declarative_base()


class ScanRun(Base):
    """Represents a single scan execution.
    
    Tracks scan metadata including targets, configuration, engine version,
    and completion status.
    """

    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    start_time: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, index=True)
    targets: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    engine_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
        index=True,
    )

    # Relationships
    nmap_observations: Mapped[List["NmapObservation"]] = relationship(
        "NmapObservation",
        back_populates="scan_run",
        cascade="all, delete-orphan",
        foreign_keys="NmapObservation.scan_run_id",
    )
    diff_findings: Mapped[List["DiffFinding"]] = relationship(
        "DiffFinding",
        back_populates="scan_run",
        cascade="all, delete-orphan",
        foreign_keys="DiffFinding.scan_run_id",
    )

    __table_args__ = (
        Index("idx_scan_runs_status_start_time", "status", "start_time"),
        Index("idx_scan_runs_config_hash", "config_hash"),
    )

    def __repr__(self) -> str:
        return f"<ScanRun(id={self.id}, status={self.status}, start_time={self.start_time})>"


class Host(Base):
    """Represents a discovered host on the network.
    
    Stores host metadata including IP address, hostname, and custom tags
    with first and last seen timestamps for temporal tracking.
    """

    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, unique=True, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    tags: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relationships
    ports: Mapped[List["Port"]] = relationship(
        "Port",
        back_populates="host",
        cascade="all, delete-orphan",
        foreign_keys="Port.host_id",
    )
    services: Mapped[List["Service"]] = relationship(
        "Service",
        back_populates="host",
        cascade="all, delete-orphan",
        foreign_keys="Service.host_id",
    )
    banners: Mapped[List["Banner"]] = relationship(
        "Banner",
        back_populates="host",
        cascade="all, delete-orphan",
        foreign_keys="Banner.host_id",
    )
    tls_certs: Mapped[List["TLSCert"]] = relationship(
        "TLSCert",
        back_populates="host",
        cascade="all, delete-orphan",
        foreign_keys="TLSCert.host_id",
    )
    nmap_observations: Mapped[List["NmapObservation"]] = relationship(
        "NmapObservation",
        back_populates="host",
        cascade="all, delete-orphan",
        foreign_keys="NmapObservation.host_id",
    )
    external_observations: Mapped[List["ExternalObservation"]] = relationship(
        "ExternalObservation",
        back_populates="host",
        cascade="all, delete-orphan",
        foreign_keys="ExternalObservation.host_id",
    )

    __table_args__ = (
        Index("idx_hosts_ip_last_seen", "ip", "last_seen"),
        Index("idx_hosts_hostname", "hostname"),
    )

    def __repr__(self) -> str:
        return f"<Host(id={self.id}, ip={self.ip}, hostname={self.hostname})>"


class Port(Base):
    """Represents an open or filtered port on a host.
    
    Stores port state information, protocol details, and round-trip time
    measurements with temporal tracking.
    """

    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    port_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp", index=True)
    state_connect: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    state_syn: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    rtt_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relationships
    host: Mapped["Host"] = relationship("Host", back_populates="ports", foreign_keys=[host_id])

    __table_args__ = (
        Index("idx_ports_host_port_protocol", "host_id", "port_number", "protocol"),
        Index("idx_ports_last_seen", "last_seen"),
        Index("uq_ports_host_port_protocol", "host_id", "port_number", "protocol", unique=True),
    )

    def __repr__(self) -> str:
        return f"<Port(id={self.id}, host_id={self.host_id}, port={self.port_number}/{self.protocol})>"


class Service(Base):
    """Represents a detected service running on a host:port.
    
    Stores service identification data including product, version,
    and confidence metrics from various detection methods.
    """

    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    port_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    detected_service: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown", index=True)

    # Relationships
    host: Mapped["Host"] = relationship("Host", back_populates="services", foreign_keys=[host_id])

    __table_args__ = (
        Index("idx_services_host_port", "host_id", "port_number"),
        Index("idx_services_product_version", "product", "version"),
    )

    def __repr__(self) -> str:
        return f"<Service(id={self.id}, host_id={self.host_id}, port={self.port_number}, service={self.detected_service})>"


class Banner(Base):
    """Represents a raw banner or service greeting from a port.
    
    Stores complete banner data with parsed field extraction for
    structured analysis.
    """

    __tablename__ = "banners"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    port_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    raw_banner: Mapped[str] = mapped_column(Text, nullable=False)
    parsed_fields: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relationships
    host: Mapped["Host"] = relationship("Host", back_populates="banners", foreign_keys=[host_id])

    __table_args__ = (
        Index("idx_banners_host_port", "host_id", "port_number"),
        Index("idx_banners_collected_at", "collected_at"),
    )

    def __repr__(self) -> str:
        return f"<Banner(id={self.id}, host_id={self.host_id}, port={self.port_number})>"


class TLSCert(Base):
    """Represents a TLS certificate extracted from a service.
    
    Stores comprehensive certificate metadata including subject, issuer,
    validity dates, SANs, and cryptographic signatures for security analysis.
    """

    __tablename__ = "tls_certs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    port_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    sni: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    issuer: Mapped[str] = mapped_column(Text, nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    not_after: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    san_list: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    serial_number: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    sig_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)

    # Relationships
    host: Mapped["Host"] = relationship("Host", back_populates="tls_certs", foreign_keys=[host_id])

    __table_args__ = (
        Index("idx_tls_certs_host_port", "host_id", "port_number"),
        Index("idx_tls_certs_not_after", "not_after"),
        Index("idx_tls_certs_subject", "subject"),
    )

    def __repr__(self) -> str:
        return f"<TLSCert(id={self.id}, host_id={self.host_id}, port={self.port_number}, fingerprint={self.fingerprint_sha256[:16]})>"


class NmapObservation(Base):
    """Represents nmap-specific service and script observations.
    
    Stores nmap service detection results and NSE script output summaries
    linked to specific scan runs for reproducibility.
    """

    __tablename__ = "nmap_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    port_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    nmap_service: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    nmap_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    scripts_summary: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    scan_run_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("scan_runs.id"), nullable=True, index=True)

    # Relationships
    host: Mapped["Host"] = relationship("Host", back_populates="nmap_observations", foreign_keys=[host_id])
    scan_run: Mapped[Optional["ScanRun"]] = relationship("ScanRun", back_populates="nmap_observations", foreign_keys=[scan_run_id])

    __table_args__ = (
        Index("idx_nmap_obs_host_port", "host_id", "port_number"),
        Index("idx_nmap_obs_scan_run", "scan_run_id"),
    )

    def __repr__(self) -> str:
        return f"<NmapObservation(id={self.id}, host_id={self.host_id}, port={self.port_number})>"


class ExternalObservation(Base):
    """Represents observations from external data sources (shodan, certs.io, etc.).
    
    Aggregates multi-source vulnerability and service intelligence for
    comprehensive threat assessment.
    """

    __tablename__ = "external_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    port_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    service: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    raw_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Relationships
    host: Mapped["Host"] = relationship("Host", back_populates="external_observations", foreign_keys=[host_id])

    __table_args__ = (
        Index("idx_ext_obs_source_host_port", "source", "host_id", "port_number"),
        Index("idx_ext_obs_last_seen", "last_seen"),
    )

    def __repr__(self) -> str:
        return f"<ExternalObservation(id={self.id}, source={self.source}, host_id={self.host_id}, port={self.port_number})>"


class DiffFinding(Base):
    """Represents a difference or change detected between scan runs.
    
    Tracks new services, closed ports, certificate changes, and other
    security-relevant differences with severity assessment.
    """

    __tablename__ = "diff_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_run_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_runs.id"), nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relationships
    scan_run: Mapped["ScanRun"] = relationship("ScanRun", back_populates="diff_findings", foreign_keys=[scan_run_id])

    __table_args__ = (
        Index("idx_diff_findings_scan_run", "scan_run_id"),
        Index("idx_diff_findings_severity", "severity"),
        Index("idx_diff_findings_finding_type", "finding_type"),
    )

    def __repr__(self) -> str:
        return f"<DiffFinding(id={self.id}, scan_run_id={self.scan_run_id}, severity={self.severity})>"
